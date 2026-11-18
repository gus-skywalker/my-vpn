#!/usr/bin/env python3
"""Install pinned age binaries in project state, after checking the release digest."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

root = Path(__file__).resolve().parent.parent
lock = json.loads((root/'config/age-lock.json').read_text())
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('platform', choices=lock['assets'])
a = p.parse_args()
asset = f"age-{lock['version']}-{a.platform}.tar.gz"
url = f"https://github.com/FiloSottile/age/releases/download/{lock['version']}/{asset}"
data = urllib.request.urlopen(url, timeout=45).read(80*1024*1024)
if hashlib.sha256(data).hexdigest() != lock['assets'][a.platform]['sha256']:
    raise SystemExit('Release digest mismatch; nothing installed.')
destination = root/'state/tools'/a.platform
destination.mkdir(parents=True, exist_ok=True, mode=0o700)
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
    for name in ['age', 'age-keygen']:
        member = tar.getmember('age/'+name)
        if not member.isfile():
            raise SystemExit('Unexpected archive member.')
        path = destination/name
        with path.open('wb') as stream:
            stream.write(tar.extractfile(member).read())
        path.chmod(0o755)
print(f"Verified and installed {lock['version']} {a.platform} in project state.")
