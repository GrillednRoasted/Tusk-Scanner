#!/bin/env python3

import pyshark
import time 
import subprocess as sp
import os
import request as req
import json
import socket
capture = pyshark.LiveCapture(interface='wlo1',output_file="test.pcap")
separator = '------------------------------------------------------------------------'
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
def main():
    sniffer()
    snort(pcap_file)

if __name__ == '__main__':
    main()
