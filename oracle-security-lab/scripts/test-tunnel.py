#!/usr/bin/env python3
"""Disposable peer: prove encrypted egress and namespace filtering, no secret output.

Run with compose.yaml + compose.private.yaml + compose.test.yaml already up.
The client has only a Docker-internal transit network. Keys exist only in tmpfs.
Evidence contains outcomes/counters, never client profiles or private keys.
"""
import datetime
import argparse
import fcntl
import json
import ipaddress
import os
import platform
from pathlib import Path
import subprocess
import shlex
import time

ROOT = Path(__file__).resolve().parent.parent
SERVER = 'hermes-security-vpn'
CLIENT = 'hermes-security-vpn-test'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--server-ssh', choices=['ubuntu@132.145.178.32'], help='Test the published Oracle endpoint from this Mac instead of the internal fixture.')
args = parser.parse_args()
if args.server_ssh and platform.system() == 'Darwin':
    route = subprocess.run(['/sbin/route', '-n', 'get', '1.1.1.1'], capture_output=True, text=True)
    if 'utun' in route.stdout:
        print('Há uma VPN ativa no Mac. Este teste Docker exige saída direta, sem outro túnel. '
              'Desative a VPN para executá-lo; para testar o aplicativo nativo ativo, confira seu IP de saída.', flush=True)
        raise SystemExit(2)
# This harness deliberately reserves one client name and one peer address.
# Serialize executions from this checkout before touching Docker or the server.
lock_dir = ROOT/'state'
lock_dir.mkdir(mode=0o700, exist_ok=True)
lock_fd = os.open(lock_dir/'test-tunnel.lock', os.O_RDWR | os.O_CREAT, 0o600)
try:
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print('Outro teste VPN já está em andamento neste diretório. Aguarde ele terminar; esta execução não alterou a VPN.', flush=True)
    os.close(lock_fd)
    raise SystemExit(75)
os.ftruncate(lock_fd, 0)
os.write(lock_fd, ('pid=%d\n' % os.getpid()).encode())
report = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': []}
report['mode'] = 'public-endpoint-from-Mac' if args.server_ssh else 'internal-transit'

def run(*args, input=None, check=True):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=35)
    if check and result.returncode:
        # Do not emit command arguments, stdout or stderr: some contain public
        # peer configuration, and future revisions might include secrets.
        raise RuntimeError('Test command failed (exit %d)' % result.returncode)
    return result.stdout.strip()

def dex(container, *command):
    if container == SERVER and args.server_ssh:
        return run('ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'ConnectTimeout=8', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
                   args.server_ssh, shlex.join(['docker', 'exec', container, *command]))
    return run('docker', 'exec', container, *command)

def record(name, passed, detail=None):
    report['checks'].append({'name': name, 'passed': bool(passed), 'detail': detail})
    print(('%s: ' % ('PASS' if passed else 'FAIL')) + name, flush=True)
    if not passed:
        raise RuntimeError(name)

def counters():
    lines = dex(SERVER, 'iptables-nft', '-t', 'raw', '-L', 'HERMES_VPN_PEERS', '-n', '-v', '-x').splitlines()
    return {str(ipaddress.ip_network(p[8], strict=False)): int(p[0]) for line in lines if len(p := line.split()) >= 9 and p[2] == 'DROP'}

public = None
created = False
try:
    image = json.loads((ROOT/'config/image-lock.json').read_text())['image']
    report['stage'] = 'wait for server startup'
    for attempt in range(30):
        try:
            ready = dex(SERVER, 'wg', 'show', 'wg0', 'listen-port')
        except RuntimeError:
            ready = ''
        if ready == '51820':
            break
        time.sleep(1)
    else:
        raise RuntimeError('WireGuard server did not become ready')
    # Refuse a collision instead of removing an unrelated existing container.
    existing = run('docker', 'ps', '-a', '--filter', 'name=^/'+CLIENT+'$', '--format', '{{.Names}}')
    if existing:
        raise RuntimeError('O container de teste já existe. Pode haver outro teste em andamento ou uma execução interrompida; nenhum container existente foi removido.')
    report['cpu_before'] = dex(SERVER, 'cat', '/sys/fs/cgroup/cpu.stat')
    client_network = ['--network', 'bridge'] if args.server_ssh else ['--network', 'hermes-security-vpn_test-transit', '--ip', '172.30.88.3']
    run('docker', 'run', '-d', '--name', CLIENT, *client_network, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
        '--security-opt', 'no-new-privileges:true', '--read-only', '--memory', '128m', '--pids-limit', '32',
        '--tmpfs', '/run:rw,nosuid,nodev,size=8388608', '--entrypoint', '/bin/sh', image,
        '-c', 'umask 077; wg genkey > /run/test.key; sleep 1800')
    created = True
    report['stage'] = 'read disposable client public key'
    time.sleep(1)
    public = dex(CLIENT, 'sh', '-c', 'wg pubkey < /run/test.key')
    report['stage'] = 'configure temporary peer'
    server_public = dex(SERVER, 'wg', 'show', 'wg0', 'public-key')
    endpoint = dex(SERVER, 'printenv', 'VPN_ENDPOINT_IPV4')
    assert ipaddress.ip_address(endpoint).is_global
    dex(SERVER, 'wg', 'set', 'wg0', 'peer', public, 'allowed-ips', '10.66.77.254/32')
    dex(CLIENT, 'sh', '-c', 'ip link add wg-test type wireguard; ip addr add 10.66.77.254/32 dev wg-test; ip link set wg-test mtu 1380 up')
    dex(CLIENT, 'wg', 'set', 'wg-test', 'private-key', '/run/test.key', 'peer', server_public,
        'endpoint', (endpoint if args.server_ssh else '172.30.88.2')+':51820', 'allowed-ips', '0.0.0.0/0', 'persistent-keepalive', '5')
    if args.server_ssh:
        gateway = dex(CLIENT, 'sh', '-c', "ip route show default | awk '{print $3}'")
        dex(CLIENT, 'ip', 'route', 'add', endpoint+'/32', 'via', gateway)
    dex(CLIENT, 'sh', '-c', 'ip route del default 2>/dev/null || true; ip route add default dev wg-test; iptables-nft -I OUTPUT -d 127.0.0.11 -j DROP')
    # Resolve explicitly inside the tunnel; never use Docker's resolver for this test.
    report['stage'] = 'tunneled DNS'
    dns = dex(CLIENT, 'nslookup', 'api.ipify.org', '1.1.1.1')
    record('approved DNS through WireGuard', 'Name:' in dns)
    code = "const https=require('https'),dns=require('dns'); dns.setServers(['1.1.1.1']); https.get('https://api.ipify.org',{lookup:(h,o,cb)=>dns.resolve4(h,(e,a)=>o.all?cb(e,a&&a.map(address=>({address,family:4}))):cb(e,a&&a[0],4)),timeout:12000},r=>{let d='';r.on('data',b=>d+=b);r.on('end',()=>{if(r.statusCode!==200)process.exit(2);console.log(d)})}).on('error',()=>process.exit(3)).on('timeout',()=>process.exit(4));"
    report['stage'] = 'tunneled HTTPS'
    exit_ip = dex(CLIENT, 'node', '-e', code)
    record('HTTPS egress through encrypted tunnel', bool(exit_ip), {'exit_ipv4': exit_ip})
    if args.server_ssh:
        record('public exit matches Oracle VM', exit_ip == endpoint)
    handshakes = dex(SERVER, 'wg', 'show', 'wg0', 'latest-handshakes').splitlines()
    record('authenticated WireGuard handshake', any(line.startswith(public+'\t') and int(line.split()[1]) > 0 for line in handshakes))
    before = counters()
    # All destinations are covered by explicit DROP rules. Ping cannot reach
    # the protected hosts; counter increments establish the actual drop point.
    destinations = {'10.0.0.197': '10.0.0.0/8', '169.254.169.254': '169.254.0.0/16',
                    '172.30.86.2': '172.16.0.0/12', '172.30.87.1': '172.16.0.0/12',
                    '10.66.77.1': '10.0.0.0/8', '10.66.77.253': '10.0.0.0/8'}
    protected = dex(SERVER, 'printenv', 'VPN_COBUDGET_IPV4')
    if not args.server_ssh:
        destinations[endpoint] = endpoint+'/32'
    destinations[protected] = protected+'/32'
    # NET_RAW is intentionally absent: use UDP datagrams rather than ping.
    for dest, prefix in destinations.items():
        old = counters().get(prefix, 0)
        dex(CLIENT, 'node', '-e', "const s=require('dgram').createSocket('udp4');s.send(Buffer.from('vpn-isolation-test'),9,process.argv[1],()=>s.close());", dest)
        time.sleep(.15)
        record('blocked '+dest, counters().get(prefix, 0) > old)
    old_dns = dex(SERVER, 'iptables-nft', '-t', 'raw', '-L', 'HERMES_VPN_DNS', '-n', '-v', '-x')
    dex(CLIENT, 'node', '-e', "const s=require('dgram').createSocket('udp4');s.send(Buffer.from('dns-policy-test'),53,'8.8.8.8',()=>s.close());")
    time.sleep(.15)
    new_dns = dex(SERVER, 'iptables-nft', '-t', 'raw', '-L', 'HERMES_VPN_DNS', '-n', '-v', '-x')
    record('unapproved UDP DNS dropped', old_dns != new_dns)
    old_dns = new_dns
    dex(CLIENT, 'node', '-e', "const s=require('net').connect({host:'8.8.8.8',port:53});s.setTimeout(1000);s.on('timeout',()=>s.destroy());s.on('error',()=>{});")
    new_dns = dex(SERVER, 'iptables-nft', '-t', 'raw', '-L', 'HERMES_VPN_DNS', '-n', '-v', '-x')
    record('unapproved TCP DNS dropped', old_dns != new_dns)
    record('server IPv6 disabled', dex(SERVER, 'cat', '/proc/sys/net/ipv6/conf/all/disable_ipv6') == '1')
    report['rules_after'] = dex(SERVER, 'iptables-nft', '-t', 'raw', '-L', 'HERMES_VPN_PEERS', '-n', '-v', '-x')
    report['memory_current_bytes'] = int(dex(SERVER, 'cat', '/sys/fs/cgroup/memory.current'))
    report['memory_peak_bytes'] = int(dex(SERVER, 'cat', '/sys/fs/cgroup/memory.peak'))
    report['cpu_after'] = dex(SERVER, 'cat', '/sys/fs/cgroup/cpu.stat')
    report['transport'] = dex(SERVER, 'wg', 'show', 'wg0', 'transfer').splitlines()[0].split()[1:]
    dex(SERVER, 'wg', 'set', 'wg0', 'peer', public, 'remove')
    revoked = dex(CLIENT, 'node', '-e', "const r=new(require('dns').Resolver)({timeout:1000,tries:1});r.setServers(['1.1.1.1']);r.resolve4('example.com',e=>{console.log(e?'blocked':'unexpected-success')});")
    record('revoked peer loses DNS connectivity', revoked == 'blocked')
    report['status'] = 'passed'
except Exception as error:
    report['status'] = 'failed'
    report['error'] = str(error)
    if public:
        try:
            report['handshake_seen_before_failure'] = any(
                line.startswith(public+'\t') and int(line.split()[1]) > 0
                for line in dex(SERVER, 'wg', 'show', 'wg0', 'latest-handshakes').splitlines())
        except Exception:
            pass
    print('Teste não concluído. Etapa: '+report.get('stage', 'unknown'), flush=True)
    if isinstance(error, RuntimeError):
        print('Motivo: '+str(error), flush=True)
    else:
        print('Motivo técnico registrado no relatório de evidências.', flush=True)
finally:
    if public:
        try:
            dex(SERVER, 'wg', 'set', 'wg0', 'peer', public, 'remove')
            report['temporary_peer_removed'] = public not in dex(SERVER, 'wg', 'show', 'wg0', 'peers').splitlines()
            if not report['temporary_peer_removed']:
                report['status'] = 'failed'
        except Exception:
            report['temporary_peer_removed'] = False
            report['status'] = 'failed'
    if created:
        run('docker', 'rm', '-f', CLIENT, check=False)
    report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    destination = ROOT/'evidence'/('tunnel-'+time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())+'.json')
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(report, indent=2)+'\n')
    print('Evidence: '+str(destination), flush=True)
    fcntl.flock(lock_fd, fcntl.LOCK_UN)
    os.close(lock_fd)
if report.get('status') != 'passed':
    raise SystemExit(1)
print('PASS: teste completo; peer temporário removido.', flush=True)
