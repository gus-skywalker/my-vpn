#!/usr/bin/env python3
"""Mac operator: create/copy an encrypted backup and verify it in an offline clone.

Private identity remains in state/recovery on this Mac. No plaintext archive is
written to disk. The restore stream uses the authenticated SSH connection.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import time

root=Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--restore-only',type=Path,help='Verify an existing encrypted backup instead of creating another.')
a=p.parse_args()
if platform.system()!='Darwin':raise SystemExit('Run this orchestrator on the operator Mac.')
identity=root/'state/recovery/backup-identity.txt'
if not identity.is_file() or identity.stat().st_mode & 0o077:
    raise SystemExit('A private recovery identity with mode 0600 is required on this Mac.')
ssh=['python3',str(root/'scripts/admin-ssh.py'),'--batch','--']
report={}
if a.restore_only:
    backup=a.restore_only.resolve()
    report['file']=backup.name
    report['ciphertext_sha256']=hashlib.sha256(backup.read_bytes()).hexdigest()
else:
    result=subprocess.run(ssh+['cd /opt/hermes-security-vpn && sudo -n python3 scripts/create-backup.py'],
                          capture_output=True,text=True,timeout=40,check=True)
    report=json.loads(result.stdout)
    name=report['file']
    if Path(name).name!=name or not name.endswith('.tar.gz.age'):
        raise SystemExit('Unexpected backup filename from server.')
    folder=root/'backups';folder.mkdir(mode=0o700,exist_ok=True)
    backup=folder/name
    data=subprocess.check_output(ssh+[shlex.join(['cat','/opt/hermes-security-vpn/backups/'+name])],timeout=30)
    if hashlib.sha256(data).hexdigest()!=report['ciphertext_sha256']:
        raise SystemExit('Encrypted transfer digest mismatch.')
    with os.fdopen(os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as stream:
        stream.write(data)
    (folder/(name+'.json')).write_text(json.dumps(report,indent=2)+'\n')
age=root/'state/tools/darwin-arm64/age'
decrypt=subprocess.Popen([str(age),'-d','-i',str(identity),str(backup)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
    restored=subprocess.run(ssh+['sudo -n python3 /opt/hermes-security-vpn/scripts/check-restore.py'],
                            stdin=decrypt.stdout,capture_output=True,text=True,timeout=110)
    decrypt.stdout.close()
    decrypt.communicate(timeout=10)
    if decrypt.returncode or restored.returncode:
        raise SystemExit('Encrypted backup or offline restoration failed; no plaintext output displayed.')
    verification=json.loads(restored.stdout)
    if verification.get('status')!='passed' or not verification.get('temporary_resources_removed'):
        raise SystemExit('Offline restore did not pass or its temporary resources remain.')
finally:
    if decrypt.poll() is None:decrypt.kill();decrypt.wait()
destination=root/'evidence'/('backup-restore-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.json')
destination.write_text(json.dumps({'backup':report,'restore':verification},indent=2)+'\n')
print('PASS: backup cifrado, cópia no Mac e restauração isolada verificados.')
print('Backup:',backup)
print('Evidence:',destination)
