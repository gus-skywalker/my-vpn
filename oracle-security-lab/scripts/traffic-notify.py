#!/usr/bin/env python3
"""Deliver durable VPN quota events to the already-bound private Hermes chat.

No bot secret, poller, LLM, packet data or accounting writes. Delivery is at least
once: an ambiguous network failure after Telegram accepted a message can repeat it.
"""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import platform
import signal
import sqlite3
import subprocess
import time

ROOT=Path(__file__).resolve().parent.parent
KINDS={'threshold_50','threshold_75','threshold_90','quota_exhausted'}
STOP=False


def message(period,kind,limit):
    if kind=='quota_exhausted':
        body='Cota esgotada. O tráfego da VPN foi bloqueado até o próximo período UTC; a administração SSH permanece disponível.'
    elif kind in KINDS:
        body='Aviso: '+kind.split('_')[1]+'% do orçamento mensal comprometido, incluindo a reserva conservadora.'
    else:raise ValueError('Not a quota notification')
    return 'VPN Oracle — '+period+' (UTC)\n'+body+'\nLimite compartilhado: '+str(limit/10**12)+' TB decimais.\nID: '+period+'/'+kind


def receipts(path):
    db=sqlite3.connect(path,timeout=5,isolation_level=None)
    path.chmod(0o600)
    db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
    db.execute('''CREATE TABLE IF NOT EXISTS outbox(period TEXT NOT NULL,kind TEXT NOT NULL,
        text TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0,
        delivered INTEGER,PRIMARY KEY(period,kind))''')
    return db


def enqueue(db,events,limit):
    for period,kind in events:
        if kind in KINDS:
            db.execute('INSERT OR IGNORE INTO outbox(period,kind,text) VALUES(?,?,?)',(period,kind,message(period,kind,limit)))


def send(text):
    # Root operator executes a fixed helper in the isolated relay, not the worker.
    # The actual token remains only in that service; the trusted host sees no key.
    code='''import json,urllib.request
from pathlib import Path
c=json.loads(Path('/run/secrets/telegram.json').read_text())
p={'chat_id':c['owner_id'],'text':TEXT,'link_preview_options':{'is_disabled':True}}
r=urllib.request.Request('http://127.0.0.1:8020/bot'+c['relay_token']+'/sendMessage',data=json.dumps(p).encode(),headers={'Content-Type':'application/json'})
assert json.load(urllib.request.urlopen(r,timeout=35))['ok']
'''.replace('TEXT',repr(text))
    p=subprocess.run(['docker','exec','-i','hermes-security-lab-telegram-relay-1','python3','-'],
                     input=code,text=True,capture_output=True,timeout=45)
    if p.returncode:raise RuntimeError('Private relay unavailable; notification retained for retry')


def deliver(db,sender=send,now=None):
    now=int(time.time()) if now is None else now
    for period,kind,text,attempts in db.execute('SELECT period,kind,text,attempts FROM outbox WHERE delivered IS NULL AND next_attempt<=? ORDER BY period,kind LIMIT 8',(now,)).fetchall():
        # Commit attempt before external side effect; success receipt follows acceptance.
        db.execute('UPDATE outbox SET attempts=attempts+1,next_attempt=? WHERE period=? AND kind=?',
                   (now+min(3600,60*2**min(attempts,6)),period,kind))
        try:sender(text)
        except Exception:
            print(json.dumps({'notification':'pending_retry','kind':kind,'period':period}),flush=True)
        else:
            db.execute('UPDATE outbox SET delivered=? WHERE period=? AND kind=?',(now,period,kind))
            print(json.dumps({'notification':'delivered','kind':kind,'period':period}),flush=True)


def main():
    if platform.node()!='security-lab-vnic' or os.geteuid()!=0:raise SystemExit('Run with sudo on the confirmed Oracle VM')
    os.umask(0o077)
    folder=ROOT/'state/traffic'
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--queue-test',action='store_true',help='Queue one clearly labeled delivery test; never changes quota accounting')
    args=parser.parse_args()
    if args.queue_test:
        db=receipts(folder/'notifications.db')
        month=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m')
        kind='delivery_test_'+str(time.time_ns())
        text='TESTE de entrega — avisos da VPN no Telegram. Limite: 8 TB/mês UTC; avisos em 50%, 75% e 90%. Este teste não alterou consumo nem cota.\nID: '+month+'/'+kind
        db.execute('INSERT INTO outbox(period,kind,text) VALUES(?,?,?)',(month,kind,text));db.close()
        print(json.dumps({'queued_test':True,'period':month,'kind':kind,'quota_ledger_changed':False}));return
    lock=(folder/'notifications.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    db=receipts(folder/'notifications.db')
    def stop(*_):
        global STOP
        STOP=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    while not STOP:
        policy=json.loads((ROOT/'config/traffic-policy.json').read_text())
        ledger=folder/'traffic.db'
        with sqlite3.connect(ledger.as_uri()+'?mode=ro',uri=True,timeout=5) as src:
            events=src.execute("SELECT period,kind FROM events WHERE kind IN ('threshold_50','threshold_75','threshold_90','quota_exhausted')").fetchall()
        enqueue(db,events,policy['monthly_limit_bytes']);deliver(db)
        # Keep delivery receipts as long as monthly accounting, avoiding old replays.
        for _ in range(60):
            if STOP:break
            time.sleep(1)
    db.close()


if __name__=='__main__':main()
