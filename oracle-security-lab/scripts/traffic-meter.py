#!/usr/bin/env python3
"""Trusted host collector and durable quota controller. No LLM, packet capture or URLs."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import sqlite3
import subprocess
import time

from traffic_store import Store, period, utcnow
from traffic_nft import Nft

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT/'state/traffic'
CONTAINER = 'hermes-security-vpn'
stopping = False


def run(*args, **kwargs):
    p = subprocess.run(args, capture_output=True, text=True, timeout=12, **kwargs)
    if p.returncode:
        raise RuntimeError('Operator command failed; private output suppressed')
    return p.stdout.strip()


def config():
    policy = json.loads((ROOT/'config/traffic-policy.json').read_text())
    if policy['mode'] not in ['observe','enforce'] or policy['period_timezone'] != 'UTC':
        raise ValueError('Invalid mode/timezone')
    if not 0 < policy['lease_bytes'] <= policy['monthly_limit_bytes'] <= 10**15:
        raise ValueError('Invalid monthly allowance')
    if not .1 <= policy['refill_at_fraction'] <= .95 or not 1 <= policy['poll_seconds'] <= 10:
        raise ValueError('Invalid polling policy')
    return policy


def inspect():
    obj = json.loads(run('docker','inspect',CONTAINER))[0]
    if obj['Config'].get('Labels',{}).get('com.docker.compose.project') != 'hermes-security-vpn':
        raise RuntimeError('Unexpected container ownership')
    if not obj['State']['Running']:
        raise RuntimeError('VPN container is not running')
    return obj


def peer_id(public):
    return hashlib.sha256(public.encode()).hexdigest()[:24]


def initialize():
    if DATA.exists():
        raise RuntimeError('Traffic state already exists; initialization must not reset counters')
    DATA.mkdir(parents=True,mode=0o700)
    store = Store(DATA/'traffic.db',create=True)
    obj = inspect()
    volume = next(m['Source'] for m in obj['Mounts'] if m['Destination']=='/etc/wireguard')
    # Public identity and display label only; never private keys/endpoints.
    with sqlite3.connect((Path(volume)/'wg-easy.db').as_uri()+'?mode=ro',uri=True) as db:
        rows = db.execute('SELECT name,public_key FROM clients_table WHERE enabled=1').fetchall()
    for label,public in rows:
        store.db.execute('INSERT INTO peers VALUES(?,?)', (peer_id(public),label))
    store.event('initialized',{'mode':config()['mode'],'accounting_starts_utc':utcnow().isoformat()})
    store.observation('accounting_started_utc',utcnow().isoformat())
    print(json.dumps({'initialized':True,'peer_count':len(rows),'historical_usage_reconstructed':False}))


def sample(store, nft, obj):
    volume=next(m['Source'] for m in obj['Mounts'] if m['Destination']=='/etc/wireguard')
    with sqlite3.connect((Path(volume)/'wg-easy.db').as_uri()+'?mode=ro',uri=True) as db:
        registered={peer_id(public):label for label,public in db.execute('SELECT name,public_key FROM clients_table WHERE enabled=1')}
    for peer,label in registered.items():
        store.db.execute('INSERT INTO peers VALUES(?,?) ON CONFLICT(id) DO UPDATE SET label=excluded.label',(peer,label))
    link = json.loads(nft.command('ip','-j','link','show','wg0').stdout)[0]
    epoch = obj['State']['StartedAt']+':'+str(nft.identity)+':'+str(link['ifindex'])
    text = run('docker','exec',CONTAINER,'wg','show','wg0','transfer')
    unregistered=0
    for row in text.splitlines():
        public,rx,tx = row.split()
        peer = peer_id(public)
        # Disposable operator test peers still consume the global byte budget,
        # but do not create permanent device identities in the usage history.
        if peer not in registered:
            unregistered+=1
            continue
        store.sample(peer,int(rx),int(tx),epoch)
    store.observation('unregistered_peer_count',unregistered)
    route = json.loads(run('ip','-j','route','get','1.1.1.1'))[0]
    dev = route['dev']
    if not dev.replace('_','').replace('-','').isalnum():
        raise RuntimeError('Invalid external interface name')
    tx = int((Path('/sys/class/net')/dev/'statistics/tx_bytes').read_text())
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    store.sample('__host_external__',0,tx,boot+':'+dev)
    store.observation('host_external_device',dev)


def publish(store, policy, gate, live=None):
    report = store.status()
    observed=report['finalized_egress_bytes']+(live['accepted'] if live else 0)
    report['measured_egress_including_live_bytes']=observed
    report['conservative_used_percent']=round(100*report['charged_including_reservations_bytes']/policy['monthly_limit_bytes'],5)
    report['unallocated_budget_bytes']=max(0,policy['monthly_limit_bytes']-report['charged_including_reservations_bytes'])
    now=utcnow();month_start=now.replace(day=1,hour=0,minute=0,second=0,microsecond=0)
    started=report['observations'].get('accounting_started_utc')
    if not started:
        row=store.db.execute("SELECT timestamp FROM events WHERE kind='initialized' ORDER BY id LIMIT 1").fetchone()
        started=row[0] if row else None
    start=max(month_start,dt.datetime.fromisoformat(started)) if started else month_start
    next_month=(month_start.replace(day=28)+dt.timedelta(days=4)).replace(day=1)
    elapsed=max(0,(now-start).total_seconds())
    report['forecast_from_tracking_start_bytes']=int(observed+observed/elapsed*(next_month-now).total_seconds()) if elapsed>=3600 else None
    report['forecast_note']='Observed rate extrapolated after one hour; does not reconstruct traffic before accounting began.'
    report.update(mode=policy['mode'],monthly_limit_bytes=policy['monthly_limit_bytes'],
                  budget_metric=policy['budget_metric'],gate=gate,last_update_utc=utcnow().isoformat(),
                  live_authorization=live,notification_channels=policy['notification_channels'])
    DATA.mkdir(mode=0o700,exist_ok=True)
    temporary = DATA/'status.json.partial'
    temporary.write_text(json.dumps(report,indent=2)+'\n')
    temporary.chmod(0o600)
    temporary.replace(DATA/'status.json')
    return report


def serve(policy):
    global stopping
    lock = (DATA/'controller.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    # Own the lock before touching the live gate. Close before loading a ledger
    # so a missing/truncated database cannot reopen or retain uncertain traffic.
    initial = Nft(inspect()['State']['Pid'])
    try:initial.freeze()
    finally:initial.close()
    store = Store(DATA/'traffic.db')
    nft = None; current = None; obj = None; fingerprint = None
    observed = 0; observed_previous = 0; observed_month = period()
    last_sample = 0; last_inspect = 0; last_status = 0; lost = None

    def settle_current(close_remaining=False):
        nonlocal current
        if current:
            nft.freeze()
            snap = nft.snapshot()
            if snap['cookie'] != current['id']:
                raise RuntimeError('Authorization changed outside controller; no uncertain refund')
            store.settle(current['id'],snap['accepted'],close_remaining=close_remaining)
            current = None

    def connect():
        nonlocal nft,current,obj,fingerprint,observed,observed_previous,lost
        obj = inspect()
        current_fingerprint = (obj['Id'],obj['State']['StartedAt'])
        if current_fingerprint == fingerprint:
            return
        if nft:
            nft.freeze()
            # A generation change never refunds uncertain authorization.
            nft.close();current=None
        nft = Nft(obj['State']['Pid']);nft.freeze()
        lost = store.recover()
        if lost:
            import uuid
            store.event('uncertain_reservation_'+uuid.uuid4().hex[:8],{'charged_bytes':lost,'reason':'controller_or_namespace_changed'})
            print(json.dumps({'event':'uncertain_reservation','charged_bytes':lost}),flush=True)
        fingerprint=current_fingerprint
        observed=0;observed_previous=0
        if policy['mode']=='enforce':
            flags = dict(v.split('=',1) for v in obj['Config']['Env'] if '=' in v)
            if flags.get('VPN_TRAFFIC_ENFORCE') != '1':
                raise RuntimeError('Closed bootstrap is required before enforcement')
        else:
            nft.install(observe=True)

    try:
        while not stopping:
            now = time.monotonic()
            if not nft or now-last_inspect>=5:
                connect();last_inspect=now
            month = period()
            snap = nft.snapshot()
            if snap is None:
                raise RuntimeError('Traffic table disappeared')
            if policy['mode']=='enforce':
                if current and snap['cookie']!=current['id']:
                    raise RuntimeError('Traffic authorization identity changed')
                if current and (current['period']!=month or snap['accepted']>=current['amount']*policy['refill_at_fraction'] or snap['quota_used']>=current['amount']):
                    # The final packet may be larger than the last few bytes
                    # of monthly budget. Close that tail conservatively rather
                    # than repeatedly refunding/reissuing an unusable grant.
                    final_tail=(current['period']==month and snap['quota_used']>=current['amount'] and store.status()['charged_including_reservations_bytes']>=policy['monthly_limit_bytes'])
                    settle_current(close_remaining=final_tail)
                if not current:
                    nft.freeze()
                    current=store.reserve(month,policy['monthly_limit_bytes'],policy['lease_bytes'])
                    if current:
                        nft.install(lease=current)
                        snap=nft.snapshot()
                    elif store.event('quota_exhausted',{'limit_bytes':policy['monthly_limit_bytes']}):
                        print(json.dumps({'event':'quota_exhausted','period':month}),flush=True)
                gate='authorized' if current else 'blocked_quota'
            else:
                if snap['cookie']!='observe':
                    raise RuntimeError('Observation table changed')
                observed += max(0,snap['accepted']-observed_previous);observed_previous=snap['accepted']
                if month!=observed_month:
                    store.observe_bytes(observed,observed_month);observed=0;observed_month=month
                gate='observe_only'
            if now-last_sample>=policy['sample_seconds']:
                if policy['mode']=='observe':
                    store.observe_bytes(observed,observed_month);observed=0
                sample(store,nft,obj)
                store.prune(policy['detail_retention_days'],policy['daily_retention_days'])
                last_sample=now
            if now-last_status>=10:
                for threshold in policy['warning_percentages']:
                    charged=store.status()['charged_including_reservations_bytes']
                    if charged>=policy['monthly_limit_bytes']*threshold/100 and store.event('threshold_'+str(threshold),{'percent':threshold,'charged_bytes':charged}):
                        print(json.dumps({'event':'traffic_threshold','percent':threshold,'period':month}),flush=True)
                publish(store,policy,gate,{'bytes':current['amount'],'accepted':snap['accepted']} if current else None)
                last_status=now
            time.sleep(policy['poll_seconds'])
    finally:
        if nft:
            nft.freeze()
            if policy['mode']=='enforce':
                settle_current()
            else:
                snap=nft.snapshot()
                observed+=max(0,snap['accepted']-observed_previous)
                store.observe_bytes(observed,observed_month)
            publish(store,policy,'closed_controller_stopped')
            nft.close()
        store.db.close();lock.close()


def main():
    if platform.node()!='security-lab-vnic' or os.geteuid()!=0:
        raise SystemExit('Run with sudo on the confirmed Oracle laboratory VM')
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['init','run','status'])
    args=p.parse_args()
    policy=config()
    if args.action=='init':initialize()
    elif args.action=='status':
        result=Store(DATA/'traffic.db').status()
        if (DATA/'status.json').exists():result['controller']=json.loads((DATA/'status.json').read_text())
        result['service_state']=subprocess.run(['systemctl','is-active','hermes-vpn-traffic.service'],capture_output=True,text=True).stdout.strip()
        result['policy']=policy
        result['notifications']={'service_state':subprocess.run(['systemctl','is-active','hermes-vpn-notify.service'],capture_output=True,text=True).stdout.strip() or 'not-installed',
                                 'pending':0,'delivered':0}
        notification_db=DATA/'notifications.db'
        if notification_db.is_file():
            with sqlite3.connect(notification_db.as_uri()+'?mode=ro',uri=True) as db:
                pending,delivered=db.execute('SELECT sum(delivered IS NULL),sum(delivered IS NOT NULL) FROM outbox').fetchone()
            result['notifications'].update(pending=pending or 0,delivered=delivered or 0)
        print(json.dumps(result,indent=2))
    else:
        def stop(*_):
            global stopping
            stopping=True
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        serve(policy)


if __name__=='__main__':main()
