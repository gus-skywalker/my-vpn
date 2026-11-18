#!/usr/bin/env python3
"""Read decrypted backup from stdin; restore only into an offline disposable clone.

No ports, no network, no production volume mounts. Plaintext is never printed.
The disposable container and volume are removed even when validation fails.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pwd
import sqlite3
import subprocess
import sys
import tarfile
import time
import uuid

if platform.node() != 'security-lab-vnic' or os.geteuid() != 0:
    raise SystemExit('Run with sudo on the confirmed laboratory VM.')
os.umask(0o077)
root = Path(__file__).resolve().parent.parent
archive = sys.stdin.buffer.read(64*1024*1024+1)
if len(archive)>64*1024*1024:
    raise SystemExit('Encrypted restore input exceeds pilot budget.')
files = {}
with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
    total = 0
    for member in tar.getmembers():
        name = member.name
        if not member.isfile() or name.startswith('/') or '..' in Path(name).parts or member.size>32*1024*1024:
            raise SystemExit('Unexpected restore member.')
        total += member.size
        if total>32*1024*1024 or len(files)>64:
            raise SystemExit('Expanded restore exceeds pilot budget.')
        files[name] = tar.extractfile(member).read()
meta = json.loads(files['manifest.json'])
lock = json.loads((root/'config/image-lock.json').read_text())
if meta['image'] != lock['image']:
    raise SystemExit('Backup image differs from current image lock; inspect before restoring.')
for name in meta['files']:
    if hashlib.sha256(files[name]).hexdigest() != meta['files'][name]:
        raise SystemExit('Restored file digest mismatch.')

def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=40)
    if check and result.returncode:
        raise RuntimeError('Offline restore command failed; no output containing state was printed.')
    return result.stdout.strip()

name = 'hermes-security-vpn-restore-'+uuid.uuid4().hex[:12]
volume_created = False
container_attempted = False
report = {'status': 'failed', 'network': 'none', 'published_ports': False}
try:
    run('docker','volume','create',name)
    volume_created = True
    path = Path(json.loads(run('docker','volume','inspect',name))[0]['Mountpoint'])
    path.chmod(0o700)
    for filename in ['wg-easy.db','wg0.conf']:
        target = path/filename
        target.write_bytes(files['wireguard/'+filename]); target.chmod(0o600)
    with sqlite3.connect(path.joinpath('wg-easy.db').as_uri()+'?mode=ro', uri=True) as database:
        if database.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise RuntimeError('Restored database integrity failed.')
    report['sqlite_integrity'] = 'ok'
    if 'traffic/traffic.db' in files:
        target=path/'traffic-check.db'
        target.write_bytes(files['traffic/traffic.db']);target.chmod(0o600)
        with sqlite3.connect(target.as_uri()+'?mode=ro',uri=True) as database:
            if database.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
                raise RuntimeError('Restored traffic ledger integrity failed.')
            for month,charged,measured,lost in database.execute('SELECT period,charged,measured,lost_reserved FROM periods'):
                reserved=database.execute("SELECT coalesce(sum(amount),0) FROM leases WHERE period=? AND state='active'",(month,)).fetchone()[0]
                if min(charged,measured,lost)<0 or charged!=measured+lost+reserved:
                    raise RuntimeError('Traffic accounting invariant failed in restored copy.')
        target.unlink()
        report.update(traffic_ledger_restored_and_checked=True,traffic_controller_started=False,live_traffic_ledger_overwritten=False)
    report['file_hashes_verified']=len(meta['files'])
    container_attempted = True
    run('docker','run','-d','--name',name,'--network','none',
        '--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges:true',
        '--read-only','--cpus','.25','--memory','512m','--pids-limit','128',
        '--sysctl','net.ipv4.ip_forward=1','--sysctl','net.ipv6.conf.all.disable_ipv6=1',
        '--tmpfs','/tmp:rw,nosuid,nodev,size=67108864,mode=1777',
        '--tmpfs','/run:rw,nosuid,nodev,size=8388608,mode=0755',
        '-v',name+':/etc/wireguard','-v',str(root/'scripts/vpn-entry.sh')+':/opt/vpn/vpn-entry.sh:ro',
        '-e','VPN_ENDPOINT_IPV4=132.145.178.32','-e','VPN_COBUDGET_IPV4=150.136.11.57',
        '-e','DISABLE_IPV6=true','-e','INSECURE=true','-e','DISABLE_VERSION_CHECK=true',
        '--entrypoint','/bin/sh',lock['image'],'/opt/vpn/vpn-entry.sh',
        '/usr/bin/dumb-init','node','server/index.mjs')
    for _ in range(60):
        result = subprocess.run(['docker','exec',name,'wg','show','wg0','public-key'], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip() == meta['server_public_key']:
            break
        time.sleep(1)
    else:
        raise RuntimeError('Offline clone did not restore the expected WireGuard identity.')
    ui = run('docker','exec',name,'node','-e',"require('http').get('http://127.0.0.1:51821/',r=>{console.log(r.statusCode);process.exit()}).on('error',()=>process.exit(1))")
    if ui not in ['200','302']:
        raise RuntimeError('Restored UI did not respond.')
    report.update(status='passed', wireguard_identity_restored=True, ui_http=int(ui))
finally:
    if container_attempted:
        run('docker','rm','-f',name, check=False)
    if volume_created:
        run('docker','volume','rm',name)
    report['temporary_resources_removed'] = True
    destination = root/'evidence'/('restore-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.json')
    destination.write_text(json.dumps(report, indent=2)+'\n')
    owner = pwd.getpwnam('ubuntu')
    os.chown(destination, owner.pw_uid, owner.pw_gid)
    print(json.dumps(report))
