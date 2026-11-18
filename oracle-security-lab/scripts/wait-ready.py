#!/usr/bin/env python3
"""Wait for WireGuard and the loopback UI; never inspect configuration secrets."""
import subprocess
import time
import urllib.request

for attempt in range(60):
    result = subprocess.run(['docker', 'exec', 'hermes-security-vpn', 'wg', 'show', 'wg0', 'listen-port'], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip() == '51820':
        try:
            with urllib.request.urlopen('http://127.0.0.1:51821/', timeout=2) as response:
                if response.status == 200:
                    print('WireGuard and private UI ready.')
                    break
        except Exception:
            pass
    time.sleep(1)
else:
    raise SystemExit('VPN readiness timed out; inspect container locally without sharing secrets.')
