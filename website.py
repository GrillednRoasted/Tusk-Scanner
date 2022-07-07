#!/bin/env python3

import requests as req
import json

def check_ip( ip):

    with open("key") as key:
        key = key.read().strip()

    data = {"maxAgeInDays":90}
    headers = {"Key":key,"Accept":"application/json"}

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    r = req.get( url, data=data, headers=headers)

    dic = json.loads(r.content.decode())

    return f"IP: {ip} malicious factor: {dic['data']['abuseConfidenceScore']}"

