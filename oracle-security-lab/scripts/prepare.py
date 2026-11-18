#!/usr/bin/env python3
"""Prepare a fresh pilot without printing passwords or importing old peers."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess

parser=argparse.ArgumentParser()
parser.add_argument('--endpoint-ip',required=True)
args=parser.parse_args()
address=ipaddress.ip_address(args.endpoint_ip)
if address.version!=4 or not address.is_global:
    parser.error('Use the confirmed public IPv4 of the laboratory VM.')
root=Path(__file__).resolve().parent.parent
state=root/'state';state.mkdir(mode=0o700,exist_ok=True);state.chmod(0o700)
(root/'evidence').mkdir(exist_ok=True)
lock=json.loads((root/'config/image-lock.json').read_text())
for name in ['.env','state/bootstrap.env']:
    if (root/name).exists():raise SystemExit('Existing preparation detected; no files overwritten.')
public='VPN_IMAGE='+lock['image']+'\nVPN_ENDPOINT_IPV4='+str(address)+'\n'
with os.fdopen(os.open(root/'.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:stream.write(public)
values={
 'INIT_ENABLED':'true','INIT_USERNAME':'vpnadmin','INIT_PASSWORD':'L4b!'+secrets.token_urlsafe(28),
 'INIT_HOST':str(address),'INIT_PORT':'51820','INIT_DNS':'1.1.1.1,1.0.0.1',
 'INIT_IPV4_CIDR':'10.66.77.0/24','INIT_IPV6_CIDR':'fd4a:66:77::/64',
 'INIT_ALLOWED_IPS':'0.0.0.0/0,::/0'}
with os.fdopen(os.open(state/'bootstrap.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:
    stream.write(''.join(k+'='+v+'\n' for k,v in values.items()))
print('Fresh preparation saved. Bootstrap secret is protected and was not displayed. No container started.')
