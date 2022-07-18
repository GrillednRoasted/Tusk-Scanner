#!/bin/env python3
import time
import subprocess as sp
import os
import requests as req
import json
import argparse
import textwrap
import email
import sys
import smtplib
import ssl
import socket
import re
import getpass
from pyshark import LiveCapture
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from interface import Interface
import ipaddress

separator = '-'*72+'\n'
global malicious_ip
malicious_ip = []
pcap_file = "/tmp/tusk.pcap"
unique_file = "/tmp/tusk_unique"

def topath(path):
    return f"{os.path.dirname(__file__)}/{path}"

def cmd(command):
    """ runs a given command and return its output """
    return sp.run(command.split(" "), capture_output = True, text=True).stdout

def check_ip(src,dst,auto_block):
    """ runs an IP confidence test on www.abuseipdb.com """

    with open("api-key.txt") as key:
        key = key.read().strip()

    data = {"maxAgeInDays":90}
    headers = {"Key":key,"Accept":"application/json"}
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={dst}"
    r = req.get(url, data=data, headers=headers)

    dic = json.loads(r.content.decode())
    
    if not "data" in dic:
        return None

    msg = f"IP: {dst} malicious factor: {dic['data']['abuseConfidenceScore']}"
    if dic['data']['abuseConfidenceScore'] == 100:
        malicious_ip.append(msg)
        if auto_block:
            block_ip(src,dst,True)
                
    return dic['data']['abuseConfidenceScore']

def reverse_dns(ip):
    """ tries to get a domain name associated with the ip """
    return cmd(f"dig -x {ip} +short").strip()

def get_processes():
    """ returns dictionary with ip data and it's process """
    proc = cmd("ss -nap").split("\n")

    name_reg = re.compile(r'\"(?P<name>.*)\"\,')
    ipv6_reg = re.compile(r'\[(?P<ip>.*)\]\:')
    ipv4_reg = re.compile(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\:')

    dic = {}
    # searches for ip and process, continues if not found
    for line in proc:
        line = [a for a in line.split(" ") if a != ""]

        if len(line) > 0:
            ip,name = line[-2:]

            ipv6 = ipv6_reg.search(ip)
            ipv4 = ipv4_reg.search(ip)

            if ipv6:
                ip = ipv6.group("ip")
            elif ipv4:
                ip = ipv4.group("ip")
            else:
                continue
            
            name = name_reg.search(name)
            if name:
                name = name.group("name")
            else:
                continue
            dic[ip] = name

    return dic

def get_local_ip():
    """  connect to google's DNS server in order to get local ip and return it  """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.connect(("8.8.8.8", 80))
        return connection.getsockname()[0]

def load_unique_ips():
    if not os.path.exists(unique_file):
        open(unique_file,"w").close()
        return []

    with open(unique_file) as file:
        return file.read().split("\n")

def save_to_uniques(uniques):
    with open(unique_file,"w") as file:
        file.write("\n".join(uniques))

def clear_pcap():
    if os.path.exists(pcap_file):
        cmd(f"rm {pcap_file}")

def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def sniffer(pcount,psize,use_ipdb,use_dns,auto_block):
    """  captures live packets on the network """
    clear_pcap()
    capture = LiveCapture(interface='wlo1', output_file=pcap_file)
    process_dic = get_processes()
    #capture.set_debug()
    hostname = get_local_ip()
    count = 1
    scores = {}
    uniques = load_unique_ips()
    # capture a specified number of packets and iterate through them
    for packet in capture.sniff_continuously(packet_count=pcount):
        if int(packet.length) < psize:
            continue

        protocol = packet.transport_layer

        if "arp" in packet:
            src_addr = packet.arp.src_proto_ipv4
            dst_addr = packet.arp.src_proto_ipv4
            ptype = "arp"
        elif "ip" in packet:
            src_addr = packet.ip.src
            dst_addr = packet.ip.dst
            ptype = "ipv4"
        elif "ipv6" in packet:
            src_addr = packet.ipv6.src
            dst_addr = packet.ipv6.dst
            ptype = "ipv6"

        if protocol:
            src_port = packet[protocol].srcport
            dst_port = packet[protocol].dstport
        else:
            src_port = ""
            dst_port = ""

        if dst_addr in process_dic:
            process = process_dic[dst_addr]
        else:
            process = "?"

        #checks if packet is unique
        packet_str = ",".join([dst_addr,process,ptype])

        skip = False
        for unique in uniques:
            if unique.startswith(packet_str):
                score = unique.split(",")[-1]
                if score == 100:
                    block_ip(src_addr,dst_addr,True)
                skip = True
                break

        if skip:
            continue 

        localtime = time.asctime(time.localtime(time.time()))
        print(f"Packet Number {count}:")
        print ("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol),"\n")
        print(f"Packet Length: {packet.length}")

        print(f"IP: {dst_addr} is coming from '{process}'")

        if use_dns:
            domain = reverse_dns(dst_addr)
            if domain != "":
                print(f"IP: {dst_addr} domain is: {domain}")
            else:
                print(f"IP: {dst_addr} has no domain name associated with it.")
            
        score = 0
        if use_ipdb:        
            if dst_addr not in scores:
                scores[dst_addr] = check_ip(src_addr,dst_addr,auto_block)
            score = scores[dst_addr]
            if score != None:
                print(f"Confidence score: {score}")
            else:
                print("Failed to get IP confidence score!")
                score = 0

        uniques.append(f"{packet_str},{score}")

        if scores[dst_addr] == 100:
            print(f"Blocking IP {dst_addr}")

        print(separator)   
        count += 1

    save_to_uniques(uniques)
    
    blocked = [a for a in scores if scores[a] == 100]
    if len(blocked) > 0:
        print("List of blocked IPs:")
        for ip in blocked:
            print(f"    {ip}")

def snort(file):
    """ runs snort command to detect malicious activity """
    snort_results = cmd("snort -N -A console -q -u snort -g snort -c /etc/snort/snort.conf --daq-dir /usr/lib/daq/ --pcap-list " + file)
    print(snort_results)
    if len(snort_results) > 0:
        malicious_ip.append(snort_results)

def block_ip(src,ip,block):
    """ blocks traffic from ip """
    local = get_local_ip()
    if block and src != local:
        return
    cmd(f"iptables -{'A' if block else 'D'} INPUT -s {ip} -j DROP")
    #print(f"{'Blocking' if block else 'Unblocking'} traffic from {ip}!")

def email_notif(uemail, pword):
    """ sets up email notification using gmail """ 
    subject = "Malicious Packets Detected!"
    body = "Malicious activity detected:\n{}".format("\n".join(malicious_ip))
    sender_email = uemail
    receiver_email = uemail
    password = pword

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))
    # uses email address and google app password to login and send an email
    text = message.as_string()
    context = ssl.create_default_context()    
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, text)

def check_email(email):
    """ regex for validating email format """
    return True if re.match(r".+@.+\.com",str(email)) else False

def notif(send_email):
    msg = "Malicious IP Detected!"
    if send_email:
        msg += " Check email!"
    """ runs notification bash script """
    sp.run(["sh","notify.sh","-u","critical","Alert!",msg])
    
def toint(value):
    """ converts str to int """
    value = str(value)
    if value.isdigit():
        return int(value)
    return 0

def get_args():
    """ sets arguments and argument descriptions """
    parser = argparse.ArgumentParser(description='Custom IDS Tool',
    formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent(
        '''Example: sudo pyshart-test.py -e user@email.com -p [email password] -c [packet count] -s [packet size] -i'''))
    parser.add_argument('-e', '--email', help='adds user email')
    parser.add_argument('-c', '--count', type=int, default=200, help='specifies ammount of packets to count')
    parser.add_argument('-s', '--size', type=int, default=10, help='specifies minimum packet size')
    parser.add_argument('-i', '--interface', help='opens the user interface', action="store_true")
    parser.add_argument('-d', '--daemon', help='runs as a daemon', action="store_true")

    return parser.parse_args()

def run_interface(args):
    """ launches user interface """
    ui = Interface(args.email, args.count, args.size)

    while ui.open:
        event, values = ui.update()
        
        block = event == "block"
        if block or event == "unblock":            
            local = get_local_ip()
            if valid_ip(values['blockip']):
                block_ip(local,values['blockip'],block)
                print(f"{'Blocked' if block else 'Unblocked'} IP {values['blockip']}")
            else:
                print("Invalid IP!")

        # if scan button clicked, run sniffer with specified parameters
        elif event == "scan":
            values['count'] = toint(values['count'])
            values['size'] = toint(values['size'])
               
            print("Scanning...")
            ui.progress(25)

            sniffer(values['count'],values['size'],values['ipdb'],values['dns'],values['autoblock'])
            ui.progress(50)
            # runs snort if selected
            if values['snort']:
                snort(pcap_file)

            ui.progress(75)
            # sends email for malicious ips if email credentials are valid
            if len(malicious_ip) > 0:
                if args.valid_email:
                    email_notif(values['email'],values['passw'])                    
                notif(args.valid_email)
            ui.progress(100) 

def run(args):        
    """ run the application without a user interface """
        
    sniffer(args.count,args.size,True,True,True)
    snort(pcap_file)
    # send email alerting of malicious ips if email credentials valid
    if len(malicious_ip) > 0:
        if args.valid_email: 
            email_notif(args.email, args.password)
        notif(args.valid_email)

def run_daemon(args):
    global malicious_ip
    stdout = sys.stdout

    cmd("rm /tmp/tusk.log")

    while True:
        malicious_ip = []
        with open("/tmp/tusk.log","a") as log:
            sys.stdout = log
            run(args)
        sys.stdout = stdout
        time.sleep(5)

    sys.stdout = stdout


def email_login(email,password):
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(email, password)
        return True
    except smtplib.SMTPAuthenticationError as e:
        return False 

def main():
    args = get_args()

    valid_email = check_email(args.email)

    # ask for a password if email valid
    if valid_email:
        args.password = getpass.getpass("E-mail password: ")
        valid_email = email_login(args.email,args.password)
        if not valid_email:
            print("Wrong email or password!")
    else:
        print("Invalid email!")
        args.password = ""

    args.valid_email = valid_email

    if args.interface:
        run_interface(args)
    elif args.daemon:
        run_daemon(args)
    else:
        run(args)

if __name__ == '__main__':
    main()
