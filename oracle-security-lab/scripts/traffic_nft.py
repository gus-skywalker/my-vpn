"""Only the VPN net namespace and our own nft table; never host firewall flushes."""
import json
import datetime as dt
import os
import subprocess

TABLE = 'hermes_vpn_traffic'


class Nft:
    def __init__(self, pid):
        self.fd = os.open('/proc/'+str(int(pid))+'/ns/net', os.O_RDONLY)
        self.identity = os.fstat(self.fd).st_ino

    def command(self, *args, input=None, check=True):
        p = subprocess.run(['nsenter','--net=/proc/self/fd/'+str(self.fd),*args],
                           pass_fds=(self.fd,),input=input,capture_output=True,text=True,timeout=8,
                           env={**os.environ,'TZ':'UTC'})
        if check and p.returncode:
            raise RuntimeError('Namespace operation failed; private output suppressed')
        return p

    def snapshot(self):
        p = self.command('nft','-j','list','table','inet',TABLE,check=False)
        if p.returncode:
            return None
        result = {'accepted':0,'packets':0,'quota_used':0,'cookie':None}
        for obj in json.loads(p.stdout)['nftables']:
            if 'table' in obj:
                result['cookie'] = obj['table'].get('comment')
            if obj.get('counter',{}).get('name') == 'accepted':
                result.update(accepted=obj['counter']['bytes'],packets=obj['counter']['packets'])
            if obj.get('quota',{}).get('name') == 'allowance':
                result['quota_used'] = obj['quota'].get('used',0)
        return result

    def install(self, lease=None, observe=False, test_port=None):
        existing = self.snapshot()
        text = ('delete table inet '+TABLE+'\n') if existing is not None else ''
        cookie = lease['id'] if lease else ('observe' if observe else 'closed')
        text += 'table inet '+TABLE+' {\n comment "'+cookie+'"\n counter accepted {}\n counter rejected {}\n'
        if lease:
            text += ' quota allowance { until '+str(int(lease['amount']))+' bytes; }\n'
        text += ' chain account {\n'
        if lease and lease.get('period'):
            start=dt.date.fromisoformat(lease['period']+'-01')
            end=(start.replace(day=28)+dt.timedelta(days=4)).replace(day=1)
            # A dead collector must not carry an old prepaid grant into a
            # later month. nft parses this absolute deadline with TZ=UTC.
            text += ' meta time >= "'+end.isoformat()+' 00:00:00" drop\n'
        if lease:
            text += ' quota name "allowance" counter name "accepted" accept\n'
        elif observe:
            text += ' counter name "accepted" accept\n'
        text += ' counter name "rejected" drop\n }\n'
        # The test predicate exists only in a disposable network-none namespace.
        if test_port:
            text += ' chain output { type filter hook output priority -10; policy accept; udp dport '+str(int(test_port))+' jump account; }\n'
        else:
            # Charge each OCI-bound packet once: uploaded payload and encrypted
            # downloads/handshakes. Do not also count decapsulated downloads.
            text += ' chain forward { type filter hook forward priority -10; policy accept; iifname "wg0" jump account;\n'
            if not lease and not observe:
                text += ' oifname "wg0" drop;\n'
            text += ' }\n chain output { type filter hook output priority -10; policy accept; oifname "eth0" udp sport 51820 jump account; }\n'
        text += '}\n'
        self.command('nft','-f','-',input=text)

    def freeze(self):
        if self.snapshot() is None:
            self.install()
            return
        self.command('nft','-f','-',input='flush chain inet '+TABLE+' account\nadd rule inet '+TABLE+' account counter name "rejected" drop\n')

    def close(self):
        os.close(self.fd)
