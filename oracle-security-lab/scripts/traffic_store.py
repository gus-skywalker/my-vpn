"""Durable accounting. Reserved bytes are committed before kernel authorization.

The ledger is independent of Hermes and wg-easy configuration. A fresh process
burns outstanding reservations conservatively; it never refunds an uncertain
lease or replays a stale kernel authorization from disk.
"""
import datetime as dt
import json
from pathlib import Path
import sqlite3
import uuid


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def period(now=None):
    return (now or utcnow()).strftime('%Y-%m')


class Store:
    def __init__(self, path, create=False):
        self.path = Path(path)
        if not create and not self.path.is_file():
            raise RuntimeError('Missing ledger; initialize explicitly, never silently reset usage')
        if create and self.path.exists():
            raise RuntimeError('Refuse reinitialization of an existing ledger')
        self.db = sqlite3.connect(self.path if create else self.path.resolve().as_uri()+'?mode=rw',
                                  uri=not create,timeout=10,isolation_level=None)
        if not create and self.db.execute('PRAGMA user_version').fetchone()[0] != 1:
            self.db.close()
            raise RuntimeError('Unrecognized or truncated ledger; keep authorization closed')
        self.path.chmod(0o600)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS periods(period TEXT PRIMARY KEY, charged INTEGER NOT NULL DEFAULT 0,
          measured INTEGER NOT NULL DEFAULT 0, lost_reserved INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS leases(id TEXT PRIMARY KEY, period TEXT NOT NULL, amount INTEGER NOT NULL,
          accepted INTEGER, state TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, period TEXT NOT NULL,
          kind TEXT NOT NULL, detail TEXT NOT NULL, UNIQUE(period,kind));
        CREATE TABLE IF NOT EXISTS peers(id TEXT PRIMARY KEY, label TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS checkpoints(id TEXT PRIMARY KEY, epoch TEXT NOT NULL, rx INTEGER NOT NULL,
          tx INTEGER NOT NULL, timestamp TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS samples(timestamp TEXT NOT NULL, peer TEXT NOT NULL, rx INTEGER NOT NULL,
          tx INTEGER NOT NULL, discontinuity INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS daily(day TEXT NOT NULL, peer TEXT NOT NULL, rx INTEGER NOT NULL DEFAULT 0,
          tx INTEGER NOT NULL DEFAULT 0, gaps INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(day,peer));
        CREATE TABLE IF NOT EXISTS observations(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        PRAGMA user_version=1;
        ''')
        if self.db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise RuntimeError('Ledger integrity failed')

    def transaction(self, fn):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            result = fn()
            self.db.execute('COMMIT')
            return result
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def event(self, kind, detail, month=None):
        month = month or period()
        cursor = self.db.execute('INSERT OR IGNORE INTO events(timestamp,period,kind,detail) VALUES(?,?,?,?)',
                                 (utcnow().isoformat(), month, kind, json.dumps(detail)))
        return bool(cursor.rowcount)

    def recover(self):
        def work():
            rows = self.db.execute("SELECT period,sum(amount) FROM leases WHERE state='active' GROUP BY period").fetchall()
            for month, amount in rows:
                self.db.execute('UPDATE periods SET lost_reserved=lost_reserved+? WHERE period=?', (amount,month))
            self.db.execute("UPDATE leases SET state='lost' WHERE state='active'")
            return sum(x[1] for x in rows)
        return self.transaction(work)

    def reserve(self, month, limit, chunk):
        if not (0 < chunk <= limit <= 10**15):
            raise ValueError('Invalid quota or reservation')
        def work():
            latest = self.db.execute('SELECT max(period) FROM periods').fetchone()[0]
            if latest and month < latest:
                raise RuntimeError('Clock moved to an older month; keep gate closed')
            if self.db.execute("SELECT count(*) FROM leases WHERE state='active'").fetchone()[0]:
                raise RuntimeError('An authorization already exists')
            self.db.execute('INSERT OR IGNORE INTO periods(period) VALUES(?)', (month,))
            charged = self.db.execute('SELECT charged FROM periods WHERE period=?', (month,)).fetchone()[0]
            amount = min(chunk, max(0, limit-charged))
            if not amount:
                return None
            lease = {'id': uuid.uuid4().hex, 'period': month, 'amount': amount}
            self.db.execute('UPDATE periods SET charged=charged+? WHERE period=?', (amount,month))
            self.db.execute('INSERT INTO leases VALUES(?,?,?,?,?,?)',
                            (lease['id'],month,amount,None,'active',utcnow().isoformat()))
            return lease
        return self.transaction(work)

    def settle(self, lease_id, accepted, close_remaining=False):
        def work():
            row = self.db.execute('SELECT period,amount,state FROM leases WHERE id=?', (lease_id,)).fetchone()
            if not row or row[2] != 'active':
                raise RuntimeError('Stale or already settled authorization')
            month, amount, _ = row
            if not 0 <= accepted <= amount:
                raise RuntimeError('Kernel counter outside authorization; do not refund')
            tail=amount-accepted if close_remaining else 0
            self.db.execute('UPDATE periods SET charged=charged-?+?+?,measured=measured+?,lost_reserved=lost_reserved+? WHERE period=?',
                            (amount,accepted,tail,accepted,tail,month))
            self.db.execute('UPDATE leases SET state=?,accepted=? WHERE id=?',
                            ('exhausted' if close_remaining else 'settled',accepted,lease_id))
        self.transaction(work)

    def observe_bytes(self, amount, month=None):
        if amount < 0:
            raise ValueError('Negative measured delta')
        month = month or period()
        def work():
            self.db.execute('INSERT OR IGNORE INTO periods(period) VALUES(?)', (month,))
            self.db.execute('UPDATE periods SET charged=charged+?,measured=measured+? WHERE period=?', (amount,amount,month))
        self.transaction(work)

    def sample(self, peer, rx, tx, epoch, timestamp=None):
        stamp = timestamp or utcnow().isoformat()
        if min(rx,tx) < 0:
            raise ValueError('Negative transfer counter')
        def work():
            previous = self.db.execute('SELECT epoch,rx,tx FROM checkpoints WHERE id=?', (peer,)).fetchone()
            discontinuity = bool(previous and (previous[0] != epoch or rx < previous[1] or tx < previous[2]))
            if previous and not discontinuity:
                drx,dtx = rx-previous[1],tx-previous[2]
            elif previous:
                drx,dtx = rx,tx
            else:
                # An initial reading is a baseline, not retroactive monthly usage.
                drx,dtx = 0,0
            self.db.execute('INSERT OR REPLACE INTO checkpoints VALUES(?,?,?,?,?)', (peer,epoch,rx,tx,stamp))
            self.db.execute('INSERT INTO samples VALUES(?,?,?,?,?)', (stamp,peer,drx,dtx,int(discontinuity)))
            self.db.execute('''INSERT INTO daily VALUES(?,?,?,?,?) ON CONFLICT(day,peer) DO UPDATE SET
              rx=rx+excluded.rx,tx=tx+excluded.tx,gaps=gaps+excluded.gaps''',
                            (stamp[:10],peer,drx,dtx,int(discontinuity)))
        self.transaction(work)

    def observation(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO observations VALUES(?,?)', (key,json.dumps(value)))

    def prune(self, detail_days, daily_days):
        now = utcnow()
        def work():
            self.db.execute('DELETE FROM samples WHERE timestamp<?', ((now-dt.timedelta(days=detail_days)).isoformat(),))
            cutoff = (now-dt.timedelta(days=daily_days)).strftime('%Y-%m-%d')
            self.db.execute('DELETE FROM daily WHERE day<?', (cutoff,))
            self.db.execute("DELETE FROM leases WHERE period<? AND state!='active'", (cutoff[:7],))
            self.db.execute('DELETE FROM events WHERE period<?', (cutoff[:7],))
        self.transaction(work)

    def status(self, month=None):
        month = month or period()
        row = self.db.execute('SELECT charged,measured,lost_reserved FROM periods WHERE period=?', (month,)).fetchone() or (0,0,0)
        peers = []
        for peer,label in self.db.execute('SELECT id,label FROM peers ORDER BY label'):
            values = self.db.execute('SELECT coalesce(sum(rx),0),coalesce(sum(tx),0),coalesce(sum(gaps),0) FROM daily WHERE peer=? AND day LIKE ?', (peer,month+'-%')).fetchone()
            peers.append({'device':label,'peer_id':peer,'upload_bytes':values[0],'download_bytes':values[1],'counter_discontinuities':values[2]})
        return {'period_utc':month,'charged_including_reservations_bytes':row[0],
                'finalized_egress_bytes':row[1],'uncertain_reservations_bytes':row[2],
                'host_external_tx_bytes':self.db.execute("SELECT coalesce(sum(tx),0) FROM daily WHERE peer='__host_external__' AND day LIKE ?", (month+'-%',)).fetchone()[0],
                'daily_usage':[{'day':d,'device':label,'upload_bytes':rx,'download_bytes':tx,'counter_discontinuities':g}
                  for d,label,rx,tx,g in self.db.execute('SELECT d.day,p.label,d.rx,d.tx,d.gaps FROM daily d JOIN peers p ON p.id=d.peer WHERE d.day LIKE ? ORDER BY d.day,p.label',(month+'-%',))],
                'peers':peers,'observations':{k:json.loads(v) for k,v in self.db.execute('SELECT key,value FROM observations')},
                'events':[{'timestamp':t,'kind':k,'detail':json.loads(d)} for t,k,d in self.db.execute('SELECT timestamp,kind,detail FROM events WHERE period=? ORDER BY id', (month,))]}
