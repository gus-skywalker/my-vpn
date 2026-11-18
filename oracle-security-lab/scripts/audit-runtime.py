#!/usr/bin/env python3
"""Sanitized Oracle runtime evidence; never print inspect environment values."""
import datetime
import json
import platform
import subprocess
import time
from pathlib import Path

if platform.node() != 'security-lab-vnic':
    raise SystemExit('This audit is restricted to the confirmed laboratory host.')

def out(*args):
    return subprocess.check_output(args, text=True).strip()

def inside(*args):
    return out('docker', 'exec', 'hermes-security-vpn', *args)

def cpu():
    return dict(line.split() for line in inside('cat', '/sys/fs/cgroup/cpu.stat').splitlines())

container = json.loads(out('docker', 'inspect', 'hermes-security-vpn'))[0]
start = cpu()
stamp = time.monotonic()
time.sleep(10)
finish = cpu()
elapsed = time.monotonic()-stamp
root = Path(__file__).resolve().parent.parent
volume = next(m['Source'] for m in container['Mounts'] if m['Destination'] == '/etc/wireguard')
rules = out('sudo', '-n', 'iptables-save')
report = {
    'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'hostname': platform.node(), 'architecture': platform.machine(),
    'image_id': container['Image'],
    'status': container['State']['Status'],
    'ports': container['NetworkSettings']['Ports'],
    'bootstrap_password_present': any(v.startswith('INIT_PASSWORD=') and v.split('=',1)[1] for v in container['Config']['Env']),
    'cap_add': container['HostConfig']['CapAdd'], 'cap_drop': container['HostConfig']['CapDrop'],
    'readonly_root': container['HostConfig']['ReadonlyRootfs'],
    'memory_limit_bytes': container['HostConfig']['Memory'],
    'nano_cpus': container['HostConfig']['NanoCpus'],
    'pids_limit': container['HostConfig']['PidsLimit'],
    'restart_policy': container['HostConfig']['RestartPolicy'],
    'memory_current_bytes': int(inside('cat', '/sys/fs/cgroup/memory.current')),
    'memory_peak_bytes': int(inside('cat', '/sys/fs/cgroup/memory.peak')),
    'idle_sample_seconds': elapsed,
    'idle_cpu_percent_of_one_core': (int(finish['usage_usec'])-int(start['usage_usec']))/elapsed/10000,
    'peer_count': len(inside('wg', 'show', 'wg0', 'peers').splitlines()),
    'persistent_state_bytes': int(out('sudo', '-n', 'du', '-sb', volume).split()[0]),
    'host_input_rules': [line for line in rules.splitlines() if line.startswith('-A INPUT ')],
    'udp_dnat_rule': [line for line in out('sudo', '-n', 'iptables', '-t', 'nat', '-nvxL', 'DOCKER').splitlines() if 'dpt:51820 ' in line],
    'running_containers': out('docker', 'ps', '--format', '{{.Names}} {{.Status}}').splitlines(),
}
destination = root/'evidence'/('runtime-'+time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())+'.json')
destination.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
print('Evidence:', destination)
