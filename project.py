#!/bin/env python3
from pyshark import LiveCapture
import time
import subprocess as sp
import os
import requests as req
import json
import argparse
import textwrap
import email
import smtplib
import ssl
import socket
import re
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import notify2
from interface import Interface
import getpass

pcap_file = "test.pcap"
separator = '-'*72+'\n'
malicious_ip = []
INVALID_EMAIL = "Invalid e-mail!"

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
            local = get_local_ip()
            if src == local:
                block_ip(dst,True)
    return msg

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

def sniffer(pcount,psize,use_ipdb,use_dns,auto_block):
    """  captures live packets on the network """
    capture = LiveCapture(interface='wlo1', output_file=pcap_file)
    process_dic = get_processes()
    hostname = get_local_ip()
    count = 1
    unique = []
    # capture a specified number of packets and iterate through them
    for packet in capture.sniff_continuously(packet_count=pcount):
        if int(packet.length) < psize:
            continue

        localtime = time.asctime(time.localtime(time.time()))

        if not "ip" in packet:
            return

        protocol = packet.transport_layer
        src_addr = packet.ip.src
        src_port = packet[protocol].srcport
        dst_addr = packet.ip.dst
        dst_port = packet[protocol].dstport
        # makes sure ips reported are unique and aren't the host's ip
        if dst_addr in unique or dst_addr == hostname:
            continue
                    
        unique.append(dst_addr)
                
        print(f"Packet Number {count}:")
        print ("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol),"\n")
        print(f"Packet Length: {packet.length}")

        if dst_addr in process_dic:
            print(f"IP: {dst_addr} is coming from '{process_dic[dst_addr]}'")

        if use_dns:
            domain = reverse_dns(dst_addr)
            if domain != "":
                print(f"IP: {dst_addr} domain is: {domain}")
            else:
                print(f"IP: {dst_addr} has no domain name associated with it.")
            
        if use_ipdb:
            score = check_ip(src_addr,dst_addr,auto_block)
            if score:
                print( score)
            else:
                print( "Failed to get IP confidence score!")

        print(separator)   
        count += 1

    print()

def snort(file):
    """ runs snort command to detect malicious activity """
    snort_results = cmd("snort -N -A console -q -u snort -g snort -c /etc/snort/snort.conf --daq-dir /usr/lib/daq/ --pcap-list " + file)
    print(snort_results)
    if len(snort_results) > 0:
        malicious_ip.append(snort_results)

def block_ip(ip,block):
    """ blocks traffic from ip """
    cmd(f"iptables -{'A' if block else 'D'} INPUT -s {ip} -j DROP")
    print(f"{'Blocking' if block else 'Unblocking'} traffic from {ip}!")

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

def notif():
    """ runs notification bash script """
    sp.run(["sh","notify.sh","-u","critical","Alert!","Malicious IP Detected! Check Email!"])
    
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
    parser.add_argument('-c', '--count', type=int, default=500, help='specifies ammount of packets to count')
    parser.add_argument('-s', '--size', type=int, default=200, help='specifies minimum packet size')
    parser.add_argument('-i', '--interface', help='opens the user interface', action="store_true")

    return parser.parse_args()


def run_interface(args):
    """ launches user interface """
    ui = Interface(args.email, args.count, args.size)

    while ui.open:
        event, values = ui.update()
        # if scan button clicked, run sniffer with specified parameters
        if event == "block":
            block_ip(values['blockip'],True)
        elif event == "unblock":
            block_ip(values['blockip'],False)
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

            valid_email = check_email(values['email']) 
            ui.progress(75)
            # sends email for malicious ips if email credentials are valid
            if len(malicious_ip) > 0:
                if valid_email:
                    email_notif(values['email'],values['passw'])
                else:
                    print(INVALID_EMAIL)
                    
                notif()
            ui.progress(100) 

def run(args):        
    """ run the application without a user interface """
    valid_email = check_email(args.email)

    # ask for a password if email valid
    if valid_email:
        password = getpass.getpass("E-mail password: ")
    else:
        password = ""
        
    sniffer(args.count,args.size,True,True,False)
    snort(pcap_file)
    # send email alerting of malicious ips if email credentials valid
    if len(malicious_ip) > 0:
        if valid_email: 
            mail_notif(args.email, args.password)
        else:
            print(INVALID_EMAIL)
        notif()
    

def main():
    args = get_args()

    if args.interface:
        run_interface(args)
    else:
        run(args)

if __name__ == '__main__':
    main()
