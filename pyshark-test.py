#!/bin/env python3

import pyshark
import time 
import subprocess as sp
import os
import request as req
import re
import argparse
import json
import socket
import json
import email
import ssl
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

capture = pyshark.LiveCapture(interface='wlo1',output_file="test.pcap")
separator = '-'*72
pcap_file = "test.pcap"
malicious_ip = []

def check_ip( ip):

    with open("key") as key:
        key = key.read().strip()

    data = {"maxAgeInDays":90}
    headers = {"Key":key,"Accept":"application/json"}

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    r = req.get( url, data=data, headers=headers)

    dic = json.loads(r.content.decode())
    return f"IP: {ip} malicious factor: {dic['data']['abuseConfidenceScore']}"


def cmd(command):
    return sp.run(command.split(" "), capture_output = True, text=True).stdout

    
def sniffer():
    count = 1
    print(cmd("ss -tp"))
    unique = []
    s = socke.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    for packet in capture.sniff_continuously(packet_count=500):
        try:
            if int(packet.length) > 200:
                localtime = time.asctime(time.localtime(time.time()))

                protocol = packet.transport_layer   
                src_addr = packet.ip.src            
                src_port = packet[protocol].srcport   
                dst_addr = packet.ip.dst           
                dst_port = packet[protocol].dstport   

                if dst_addr in unique:
                    continue

                unique.append(dst_addr)
                print(f"Packet Number {count}:")
                print ("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol),"\n")
                print(f"Packet Length: {packet.length}")
                if dst_addr != s.getsockname()[0]:
                    lines = cmd("netstat -na | grep -i established").split("\n")

                    ip_list = []
                    for line in lines[:-1]:
                        ip_list.append(line.split(" ")[-2].split(":")[0])

                    if dst_addr in ip_list:
                        print("ip is legit")
                    else:
                        print(f"IP: {dst_addr} looking a little sus ngl")
                        print(check_ip(dest_addr))
                print(separator)   
                count += 1
            else:
                continue
        except AttributeError as e:
            pass
    print()


   
def snort(file):
    print(cmd("snort -A console -q -u snort -g snort -c /etc/snort/snort.conf --daq-dir /usr/lib/daq/ --pcap-list " + file))


def email_notif(uemail, pword):
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

    text = message.as_string()
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, text)

def check_email(email):
    return True if re.match(r".+@.+\.com",str(email)) else False


def get_args():
    parser = argparse.ArgumentParser(description='Custom IDS Tool',
    formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent(
        '''Example: sudo pyshart-test.py -e user@email.com -p [email password] -c [packet count] -s [packet size]'''))
    parser.add_argument('-e', '--email', help='adds user email')
    parser.add_argument('-c', '--count', type=int, default=500, help='specifies ammount of packets to count')
    parser.add_argument('-s', '--size', type=int, default=200, help='specifies minimum packet size')

    return parser.parse_args()


def run( args):        
    valid_email=check_email(args.email)

    if valid_email:
        password = getpass.getpass("E-mail password: ")
    else:
        password = ""
        
    sniffer(args.count,args.size,True,True)
    snort(pcap_file)

    if len(malicious_ip) > 0:
        if valid_email: 
            mail_notif(args.email, args.password)
        else:
            print(INVALID_EMAIL)
        

if __name__ == '__main__':
    args = get_args()
    
    if args.interface:
        run_interface(args)
    else:
        run(args)
