#!/usr/bin/env python3
"""Oracle-only: consistent SQLite snapshot, RAM-only plaintext, age encryption.

Run with sudo. Only the public age recipient is present on the Oracle host.
The decryption identity belongs on the operator's Mac/offline storage.
"""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pwd
import sqlite3
import subprocess
import tarfile
import tempfile
import uuid

root = Path(__file__).resolve().parent.parent
if platform.node() != 'security-lab-vnic' or os.geteuid() != 0:
    raise SystemExit('Run with sudo on the confirmed laboratory VM.')
os.umask(0o077)
image = json.loads((root/'config/image-lock.json').read_text())['image']
container = json.loads(subprocess.check_output(['docker', 'inspect', 'hermes-security-vpn']))[0]
source = Path(next(m['Source'] for m in container['Mounts'] if m['Destination'] == '/etc/wireguard'))
public_key = subprocess.check_output(['docker','exec','hermes-security-vpn','wg','show','wg0','public-key'], text=True).strip()
recipient = (root/'state/backup-recipient.txt').read_text().strip()
if not recipient.startswith('age1') or '\n' in recipient:
    raise SystemExit('Expected one public age recipient.')
directory = root/'backups'
directory.mkdir(mode=0o700, exist_ok=True)
stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
destination = directory/(stamp+'.tar.gz.age')
with tempfile.TemporaryDirectory(prefix='hermes-vpn-backup-', dir='/dev/shm') as temporary:
    work = Path(temporary)
    snapshot = work/'wg-easy.db'
    with sqlite3.connect(source.joinpath('wg-easy.db').as_uri()+'?mode=ro', uri=True) as src:
        with sqlite3.connect(snapshot) as dst:
            src.backup(dst)
            if dst.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise SystemExit('SQLite snapshot integrity failed.')
    snapshot.chmod(0o600)
    files = {'wireguard/wg-easy.db': snapshot, 'wireguard/wg0.conf': source/'wg0.conf',
             'operator/bootstrap.env': root/'state/bootstrap.env',
             'source/compose.yaml': root/'compose.yaml',
             'source/vpn-entry.sh': root/'scripts/vpn-entry.sh',
             'source/image-lock.json': root/'config/image-lock.json'}
    traffic = root/'state/traffic/traffic.db'
    if traffic.is_file():
        traffic_snapshot = work/'traffic.db'
        with sqlite3.connect(traffic.as_uri()+'?mode=ro',uri=True) as src:
            with sqlite3.connect(traffic_snapshot) as dst:
                src.backup(dst)
                if dst.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
                    raise SystemExit('Traffic snapshot integrity failed.')
        traffic_snapshot.chmod(0o600)
        files['traffic/traffic.db']=traffic_snapshot
        notifications=root/'state/traffic/notifications.db'
        if notifications.is_file():
            notification_snapshot=work/'notifications.db'
            with sqlite3.connect(notifications.as_uri()+'?mode=ro',uri=True) as src:
                with sqlite3.connect(notification_snapshot) as dst:
                    src.backup(dst)
                    if dst.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
                        raise SystemExit('Notification snapshot integrity failed.')
            notification_snapshot.chmod(0o600)
            files['traffic/notifications.db']=notification_snapshot
        for name,path in {
            'source/traffic-policy.json':root/'config/traffic-policy.json',
            'source/compose.traffic.yaml':root/'compose.traffic.yaml',
            'source/traffic-meter.py':root/'scripts/traffic-meter.py',
            'source/traffic_store.py':root/'scripts/traffic_store.py',
            'source/traffic_nft.py':root/'scripts/traffic_nft.py',
            'source/hermes-vpn-traffic.service':root/'systemd/hermes-vpn-traffic.service',
        }.items():files[name]=path
        for name,path in {'source/traffic-status.py':root/'scripts/traffic-status.py',
                          'source/traffic-notify.py':root/'scripts/traffic-notify.py',
                          'source/hermes-vpn-notify.service':root/'systemd/hermes-vpn-notify.service',
                          'source/TRAFEGO.md':root/'TRAFEGO.md'}.items():
            if path.is_file():files[name]=path
    if sum(path.stat().st_size for path in files.values())>32*1024*1024:
        raise SystemExit('Backup input exceeds pilot budget; review retention/growth first.')
    meta = {'format': 1, 'image': image, 'server_public_key': public_key,
            'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'files': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name,path in files.items()}}
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        for name,path in files.items():
            info = tar.gettarinfo(str(path), arcname=name)
            info.mode = 0o600
            with path.open('rb') as stream:
                tar.addfile(info, stream)
        data = json.dumps(meta).encode()
        info = tarfile.TarInfo('manifest.json'); info.size = len(data); info.mode = 0o600
        tar.addfile(info, io.BytesIO(data))
    partial = destination.with_suffix(destination.suffix+'.partial')
    try:
        with partial.open('xb') as encrypted:
            result = subprocess.run([str(root/'state/tools/linux-arm64/age'), '-r', recipient],
                                    input=archive.getvalue(), stdout=encrypted, stderr=subprocess.PIPE)
        if result.returncode:
            raise RuntimeError('age encryption failed; no backup accepted.')
        partial.rename(destination)
    finally:
        partial.unlink(missing_ok=True)
owner = pwd.getpwnam('ubuntu')
os.chown(directory, owner.pw_uid, owner.pw_gid)
os.chown(destination, owner.pw_uid, owner.pw_gid)
report = {'file': destination.name, 'ciphertext_sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
          'encrypted_bytes': destination.stat().st_size, 'sqlite_integrity': 'ok',
          'plaintext_archive_persisted': False, 'identity_on_oracle': False}
report['traffic_ledger_included'] = traffic.is_file()
manifest = directory/(stamp+'.json')
manifest.write_text(json.dumps(report, indent=2)+'\n')
os.chown(manifest, owner.pw_uid, owner.pw_gid)
print(json.dumps(report))
