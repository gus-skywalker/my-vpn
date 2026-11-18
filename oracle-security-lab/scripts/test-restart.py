#!/usr/bin/env python3
"""Controlled VPN process failure; verify Docker recovery without restarting Hermes.

Run on Oracle with sudo, after an encrypted backup has passed restoration.
This briefly interrupts VPN traffic. It never reboots the VM or Docker daemon.
"""
import json
import os
from pathlib import Path
import platform
import pwd
import sqlite3
import subprocess
import time
import urllib.request

if platform.node() != 'security-lab-vnic' or os.geteuid() != 0:
    raise SystemExit('Run with sudo on the confirmed laboratory VM.')
root = Path(__file__).resolve().parent.parent

def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError('Restart validation command failed; raw state output suppressed.')
    return result.stdout.strip()

def inspect():
    return json.loads(run('docker','inspect','hermes-security-vpn'))[0]

def wg(field):
    return run('docker','exec','hermes-security-vpn','wg','show','wg0',field)

def hermes():
    names=run('docker','ps','--filter','name=hermes-security-lab','--filter','name=hermes-lab-pilot','--format','{{.Names}}').splitlines()
    result={}
    for name in names:
        c=json.loads(run('docker','inspect',name))[0]
        result[name]={'id':c['Id'],'started_at':c['State']['StartedAt']}
    return result

before=inspect()
if before['HostConfig']['RestartPolicy']['Name'] != 'unless-stopped':
    raise SystemExit('Automatic restart policy is not configured.')
identity=wg('public-key')
peers=sorted(wg('peers').splitlines())
hermes_before=hermes()
input_before=run('iptables','-S','INPUT')
report={'status':'failed','hermes_unchanged':False,'manual_recovery_used':False}
started=time.monotonic()
try:
    run('docker','exec','hermes-security-vpn','sh','-c','kill -KILL "$(pidof node)"',check=False)
    for attempt in range(90):
        current=inspect()
        if current['RestartCount']>before['RestartCount'] and current['State']['Running']:
            try:
                if wg('public-key')==identity and sorted(wg('peers').splitlines())==peers:
                    with urllib.request.urlopen('http://127.0.0.1:51821/',timeout=2) as r:
                        if r.status==200:break
            except Exception:
                pass
        time.sleep(1)
    else:
        raise RuntimeError('Automatic recovery did not become functional within 90 seconds.')
    after=inspect()
    volume=Path(next(m['Source'] for m in after['Mounts'] if m['Destination']=='/etc/wireguard'))
    with sqlite3.connect(volume.joinpath('wg-easy.db').as_uri()+'?mode=ro',uri=True) as database:
        if database.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
            raise RuntimeError('Database integrity check failed after restart.')
    report.update(status='passed',restart_count_before=before['RestartCount'],restart_count_after=after['RestartCount'],
                  recovery_seconds=round(time.monotonic()-started,2),wireguard_identity_preserved=True,
                  peer_count=len(peers),peers_preserved=True,sqlite_integrity='ok',
                  hermes_unchanged=hermes()==hermes_before,host_input_unchanged=run('iptables','-S','INPUT')==input_before,
                  restart_policy=after['HostConfig']['RestartPolicy']['Name'],vm_reboot_tested=False)
    if not report['hermes_unchanged'] or not report['host_input_unchanged']:
        report['status']='failed'
finally:
    if not inspect()['State']['Running']:
        run('docker','start','hermes-security-vpn')
        report['manual_recovery_used']=True
        report['status']='failed'
    destination=root/'evidence'/('restart-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.json')
    destination.write_text(json.dumps(report,indent=2)+'\n')
    owner=pwd.getpwnam('ubuntu')
    os.chown(destination,owner.pw_uid,owner.pw_gid)
    print(json.dumps(report))
if report['status']!='passed':raise SystemExit(1)
