#!/bin/env python3
import pyshark
import time
import subprocess as sp
import os
import requests as req
import json
import random
import argparse
import textwrap
import smtplib
import email
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
import sys
sys.stderr = None
from scapy.all import *
sys.stderr = sys.__stderr__

pcap_file = "test.pcap"
capture = pyshark.LiveCapture(interface='wlo1', output_file=pcap_file)
separator = '-'*72+'\n'
malicious_ip = []
INVALID_EMAIL = "Invalid e-mail!"

def cmd(command):
    return sp.run(command.split(" "), capture_output = True, text=True).stdout

def check_ip( ip):

    with open("key") as key:
        key = key.read().strip()

    data = {"maxAgeInDays":90}
    headers = {"Key":key,"Accept":"application/json"}

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    r = req.get( url, data=data, headers=headers)

    dic = json.loads(r.content.decode())

    if dic['data']['abuseConfidenceScore'] == 100:
        malicious_ip.append(f"IP: {ip} malicious factor: {dic['data']['abuseConfidenceScore']}")

    return f"IP: {ip} malicious factor: {dic['data']['abuseConfidenceScore']}"

def reverse_dns(ip):
    return cmd(f"dig -x {ip} +short").strip()

def get_processes():
    proc = cmd("ss -nap").split("\n")

    name_reg = re.compile(r'\"(?P<name>.*)\"\,')
    ipv6_reg = re.compile(r'\[(?P<ip>.*)\]\:')
    ipv4_reg = re.compile(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\:')

    dic = {}

    for line in proc:
        line = [a for a in line.split(" ") if a != ""]

        if len( line) > 0:
            ip,name = line[-2:]

            ipv6 = ipv6_reg.search( ip)
            ipv4 = ipv4_reg.search( ip)

            if ipv6:
                ip = ipv6.group("ip")
            elif ipv4:
                ip = ipv4.group("ip")
            else:
                continue
            
            name = name_reg.search( name)
            if name:
                name = name.group("name")
            else:
                continue

            dic[ip] = name

    return dic

def sniffer(pcount,psize,ipdb,dns):
    process_dic = get_processes()

    count = 1
    unique = []

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))

    hostname = s.getsockname()[0]
    
    s.close()

    for packet in capture.sniff_continuously(packet_count=pcount):
        try:
            if int(packet.length) > psize:
                localtime = time.asctime(time.localtime(time.time()))

                protocol = packet.transport_layer
                src_addr = packet.ip.src
                src_port = packet[protocol].srcport
                dst_addr = packet.ip.dst
                dst_port = packet[protocol].dstport

                if dst_addr in unique or dst_addr == hostname:
                    continue
                    
                unique.append(dst_addr)
                
                print(f"Packet Number {count}:")
                print ("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol),"\n")
                print(f"Packet Length: {packet.length}")

                if dst_addr in process_dic:
                    print(f"IP: {dst_addr} is coming from '{process_dic[dst_addr]}'")

                if dns:
                    domain = reverse_dns(dst_addr)
                    if domain != "":
                        print(f"IP: {dst_addr} domain is: {domain}")
                    else:
                        print(f"IP: {dst_addr} has no domain name associated with it.")

                if ipdb:
                    print(check_ip(dst_addr))

                print(separator)   
                count += 1
            else:
                continue
        except AttributeError as e:
            pass
    print()

def snort(file):
    snort_results = cmd("snort -N -A console -q -u snort -g snort -c /etc/snort/snort.conf --daq-dir /usr/lib/daq/ --pcap-list " + file)
    print(snort_results)
    if len(snort_results) > 0:
        malicious_ip.append(snort_results)

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

def notif():
    sp.run(["sh","notify.sh","-u","critical","Alert!","Malicious IP Detected! Check Email!"])
    
def toint( value):
    value = str(value)
    if value.isdigit():
        return int(value)
    return 0
    
def get_args():
    parser = argparse.ArgumentParser(description='Custom IDS Tool',
    formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent(
        '''Example: sudo pyshart-test.py -e user@email.com -p [email password] -c [packet count] -s [packet size] -i'''))
    parser.add_argument('-e', '--email', help='adds user email')
    parser.add_argument('-c', '--count', type=int, default=500, help='specifies ammount of packets to count')
    parser.add_argument('-s', '--size', type=int, default=200, help='specifies minimum packet size')
    parser.add_argument('-i', '--interface', help='opens the user interface', action="store_true")

    return parser.parse_args()

def run_interface( args):
    ui = Interface(args.email, args.count, args.size)

    while ui.open:
        event, values = ui.update()

        if event == "scan":
            values['count'] = toint( values['count'])
            values['size'] = toint( values['size'])
               
            print("Scanning...")
            ui.progress(25)

            sniffer(values['count'],values['size'],values['ipdb'],values['dns'])
            ui.progress(50)

            if values['snort']:
                snort(pcap_file)

            valid_email = check_email(values['email']) 
            ui.progress(75)

            if len(malicious_ip) > 0:
                if valid_email:
                    email_notif(values['email'],values['passw'])
                else:
                    print(INVALID_EMAIL)
                    
                notif()
            ui.progress(100) 
 
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
        notif()
    
if __name__ == '__main__':
    args = get_args()

    if args.interface:
        run_interface( args)
    else:
        run( args)

