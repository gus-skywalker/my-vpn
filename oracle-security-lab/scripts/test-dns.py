#!/usr/bin/env python3
"""Mac native-resolver DNS test, observing only synthetic queries on Oracle.

Requires the existing Mac WireGuard profile active. Does not toggle it, change
DNS settings/firewalls, or capture ordinary browsing. Oracle capture is scoped
to a fresh DNS-label prefix; host root enters only the VPN network namespace.
Local BPF capture is not required and its absence remains an explicit limit.
"""
import fcntl
import ipaddress
import json
from pathlib import Path
import platform
import re
import secrets
import select
import shlex
import subprocess
import sys
import time

if platform.system() != 'Darwin':
    raise SystemExit('Run on the operator Mac with the VPN active.')
root=Path(__file__).resolve().parent.parent
(root/'state').mkdir(mode=0o700,exist_ok=True)
lock=(root/'state/test-dns.lock').open('a')
try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:raise SystemExit('Another DNS test is already running.')
report={'status':'failed','checks':[],'synthetic_prefix':'hermesdns-'+secrets.token_hex(4)+'-',
        'local_physical_packet_capture':False,'all_apps_and_networks_tested':False}

def command(*args,timeout=20,check=True):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('DNS test command failed; raw command output suppressed.')
    return result

def remote(*args):
    return command('python3',str(root/'scripts/admin-ssh.py'),'--batch','--',shlex.join(args),timeout=20).stdout.strip()

def dex(*args):
    return remote('docker','exec','hermes-security-vpn',*args)

def record(name,passed):
    report['checks'].append({'name':name,'passed':bool(passed)})
    print(('PASS: ' if passed else 'FAIL: ')+name,flush=True)
    if not passed:raise RuntimeError(name)

def policy_counters():
    text=dex('iptables-nft','-t','raw','-nvxL','HERMES_VPN_DNS')
    return {parts[2]+' '+parts[8]:int(parts[0]) for line in text.splitlines()
            if len(parts:=line.split())>=9 and parts[0].isdigit() and parts[2] in ['RETURN','DROP']}

def drop_count():
    return sum(count for key,count in policy_counters().items() if key.startswith('DROP '))

def bpf_prefix(prefix,transport):
    # UDP header (8) + DNS header (12) + first label length (1).
    # Match every byte of this run's unique label prefix, never other traffic.
    data=prefix.encode();offset=21 if transport=='udp' else 15;terms=[]
    while data:
        size=4 if len(data)>=4 else 2 if len(data)>=2 else 1
        location=str(offset) if transport=='udp' else f'(((tcp[12] & 0xf0) >> 2) + {offset})'
        part=data[:size]
        # DNS name casing is not significant. Native resolvers may change
        # query casing; constrain every byte while accepting A/a equivalence.
        mask=bytes(0xdf if 65<=b<=90 or 97<=b<=122 else 0xff for b in part)
        expected=bytes(b&m for b,m in zip(part,mask))
        terms.append(f'({transport}[{location}:{size}] & 0x{mask.hex()}) = 0x{expected.hex()}')
        data=data[size:];offset+=size
    return ' and '.join(terms)

class Capture:
    def __init__(self,pid,interface,client):
        self.interface=interface;self.prefix_log=b'';self.collected=False
        filter_='ip and ((udp dst port 53 and '+bpf_prefix(report['synthetic_prefix'],'udp')+') or (tcp dst port 53 and '+bpf_prefix(report['synthetic_prefix'],'tcp')+'))'
        if interface=='wg0':filter_+=' and src host '+client
        args=['sudo','-n','nsenter','-t',pid,'-n','timeout','30','/usr/bin/tcpdump',
              '-nn','-i',interface,'-s','256','-l',filter_]
        self.process=subprocess.Popen(['python3',str(root/'scripts/admin-ssh.py'),'--batch','--',shlex.join(args)],
                                      stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        self.lines=[]
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if self.process.poll() is not None:break
            readable,_,_=select.select([self.process.stderr],[],[],.25)
            if readable:
                import os
                chunk=os.read(self.process.stderr.fileno(),4096)
                self.prefix_log+=chunk
                if ('listening on '+interface).encode() in self.prefix_log:return
        self.process.terminate()
        self.process.communicate(timeout=5)
        raise RuntimeError('Scoped packet capture did not become ready on '+interface)

    def collect(self):
        if self.collected:return self.lines
        try:stdout,stderr=self.process.communicate(timeout=35)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            stdout,stderr=self.process.communicate(timeout=5)
            raise RuntimeError('Scoped capture failed to stop on '+self.interface)
        self.lines=[line for line in stdout.decode(errors='replace').splitlines()
                    if report['synthetic_prefix'] in line.lower()]
        self.collected=True
        if self.process.returncode not in [0,124]:
            raise RuntimeError('Scoped capture failed on '+self.interface)
        return self.lines

captures=[]
started=time.monotonic()
try:
    route=command('/sbin/route','-n','get','1.1.1.1').stdout
    match=re.search(r'interface:\s+(utun\d+)',route)
    if not match:raise RuntimeError('The VPN must be active; DNS settings were not changed.')
    interface=match.group(1)
    addresses=command('/sbin/ifconfig',interface).stdout
    client=re.search(r'^\s+inet\s+(\d+\.\d+\.\d+\.\d+)',addresses,re.M)
    if not client or ipaddress.ip_address(client.group(1)) not in ipaddress.ip_network('10.66.77.0/24'):
        raise RuntimeError('Active tunnel is not the expected laboratory peer network.')
    report.update(vpn_interface=interface,peer_ipv4=client.group(1))
    dns=command('/usr/sbin/scutil','--dns').stdout
    first=dns.split('resolver #1',1)[1].split('resolver #2',1)[0]
    primary=re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)',first)
    report['primary_dns_servers']=primary
    record('Mac primary DNS servers are the approved Cloudflare pair',set(primary)=={'1.1.1.1','1.0.0.1'})
    exit_ip=command('/usr/bin/curl','-q','--noproxy','*','-4','-sS','--connect-timeout','5','--max-time','10','https://api.ipify.org').stdout.strip()
    report['exit_ipv4']=exit_ip
    record('Mac native IPv4 exits through Oracle',exit_ip=='132.145.178.32')
    pid=remote('docker','inspect','--format','{{.State.Pid}}','hermes-security-vpn')
    if not pid.isdigit() or int(pid)<2:raise RuntimeError('Invalid VPN namespace PID.')
    report['counters_before']=policy_counters()
    captures=[Capture(pid,'wg0',client.group(1))]
    captures.append(Capture(pid,'eth0',client.group(1)))
    print('Scoped Oracle captures ready; generating unique native DNS lookups.',flush=True)
    native=[];native_statuses=[]
    for number in range(3):
        name=report['synthetic_prefix']+str(number)+'.cloudflare.com'
        code="import socket,sys\ntry: socket.getaddrinfo(sys.argv[1],443); print('resolved')\nexcept socket.gaierror as e: print('gaierror '+str(e.errno))"
        result=command(sys.executable,'-c',code,name,timeout=8)
        native.append(name);native_statuses.append(result.stdout.strip())
    report['native_query_names']=native
    report['native_query_statuses']=native_statuses
    positive=command(sys.executable,'-c',"import socket;print(len(socket.getaddrinfo('example.com',443,socket.AF_INET)))").stdout.strip()
    record('Native resolver resolves a public hostname',int(positive)>0)
    query=report['synthetic_prefix']+'secondary.example.com'
    allowed=command('/usr/bin/dig','@1.0.0.1',query,'A','+time=2','+tries=1',check=False)
    record('Approved secondary resolver responds over the active VPN',allowed.returncode==0 and bool(re.search(r'status: (NOERROR|NXDOMAIN),',allowed.stdout)))
    query=report['synthetic_prefix']+'tcp-approved.example.com'
    allowed_tcp=command('/usr/bin/dig','@1.1.1.1',query,'A','+tcp','+time=2','+tries=1',check=False)
    record('Approved resolver responds over TCP DNS',allowed_tcp.returncode==0 and bool(re.search(r'status: (NOERROR|NXDOMAIN),',allowed_tcp.stdout)))
    for transport in ['UDP','TCP']:
        before=drop_count()
        query=report['synthetic_prefix']+transport.lower()+'-denied.example.com'
        args=['/usr/bin/dig','@8.8.8.8',query,'A','+time=2','+tries=1']
        if transport=='TCP':args.append('+tcp')
        denied=command(*args,check=False)
        record('Unapproved '+transport+' DNS times out and increments Oracle DROP',denied.returncode!=0 and drop_count()>before)
    wg_lines=captures[0].collect()
    egress_lines=captures[1].collect()
    report['scoped_wg0_capture']=wg_lines
    report['scoped_egress_capture']=egress_lines
    record('All three unique native DNS names arrived inside WireGuard',all(any(name in line.lower() for line in wg_lines) for name in native))
    record('All three native DNS names left Oracle toward an approved resolver',
           all(any(name in line.lower() and ('1.1.1.1.53:' in line or '1.0.0.1.53:' in line) for line in egress_lines) for name in native))
    record('Denied UDP DNS name arrived inside the tunnel but did not leave Oracle',
           any('udp-denied' in line for line in wg_lines) and not any('udp-denied' in line for line in egress_lines))
    report['counters_after']=policy_counters()
    report['status']='passed'
except Exception as error:
    report['error']=str(error)
    print('DNS validation did not complete: '+str(error),flush=True)
finally:
    for capture in captures:
        if capture.process.poll() is None:
            capture.process.terminate()
        if not capture.collected:
            try:
                stdout,stderr=capture.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                capture.process.kill();stdout,stderr=capture.process.communicate()
            report['partial_capture_'+capture.interface]=[line for line in stdout.decode(errors='replace').splitlines()
                    if report['synthetic_prefix'] in line.lower()]
    report['duration_seconds']=round(time.monotonic()-started,2)
    report['captures_time_bounded_seconds']=30
    destination=root/'evidence'/('dns-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.json')
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(report,indent=2)+'\n')
    print('Evidence: '+str(destination),flush=True)
    fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
if report['status']!='passed':raise SystemExit(1)
print('PASS: DNS test completed; scopes and limitations are recorded.',flush=True)
