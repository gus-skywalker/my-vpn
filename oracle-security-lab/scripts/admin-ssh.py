#!/usr/bin/env python3
"""SSH administration via the Mac physical interface, without changing VPN routes.

Usage: admin-ssh.py [--batch] [--dashboard | --password] [-- command]
The native macOS nc -b binds only this SSH TCP connection to the selected NIC.
No global route, WireGuard profile or server firewall exception is introduced.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import socket
import sys

root = Path(__file__).resolve().parent.parent
config = json.loads((root/'config/admin-mac.json').read_text())
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--batch', action='store_true')
p.add_argument('--interface', default=config['physical_interface'])
p.add_argument('--local-port', type=int, default=51821)
group = p.add_mutually_exclusive_group()
group.add_argument('--dashboard', action='store_true')
group.add_argument('--password', action='store_true')
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
command = a.command[1:] if a.command[:1] == ['--'] else a.command
ssh = ['/usr/bin/ssh', '-o', 'StrictHostKeyChecking=yes', '-o', 'ForwardAgent=no',
       '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2']
if platform.system() == 'Darwin':
    if not re.fullmatch(r'en[0-9]+', a.interface):
        p.error('Select a physical Ethernet/Wi-Fi interface such as en0; utun is not allowed.')
    socket.if_nametoindex(a.interface)
    ssh += ['-o', f'ProxyCommand=/usr/bin/nc -4 -n -G 8 -b {a.interface} %h %p']
if a.dashboard:
    if command or a.password:
        p.error('Dashboard mode does not accept remote commands.')
    if not 1024 <= a.local_port <= 65535:
        p.error('Use an unprivileged local port from 1024 to 65535.')
    ssh += ['-N', '-o', 'ExitOnForwardFailure=yes', '-L', f'127.0.0.1:{a.local_port}:127.0.0.1:51821']
else:
    ssh += ['-o', 'ClearAllForwardings=yes']
    if a.password:
        if not sys.stdout.isatty():
            p.error('Password mode is only for the operator interactive terminal.')
        ssh += ['-tt']
        command = ['python3 /opt/hermes-security-vpn/scripts/show-admin-password.py']
    elif a.batch:
        ssh += ['-T', '-o', 'BatchMode=yes']
    elif not command:
        ssh += ['-t']
ssh += [config['user']+'@'+config['host'], *command]
os.execv(ssh[0], ssh)
