#!/usr/bin/env python3
"""Ledger tests offline; --kernel adds isolated network-none nftables tests on Oracle."""
import argparse
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import unittest
import uuid

from traffic_store import Store
from traffic_nft import Nft

ROOT=Path(__file__).resolve().parent.parent


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'traffic.db'
        self.store=Store(self.path,create=True)

    def tearDown(self):
        self.store.db.close();self.tmp.cleanup()

    def test_clean_settlement_and_exact_remaining_budget(self):
        lease=self.store.reserve('2026-11',1000,400)
        self.store.settle(lease['id'],250)
        self.assertEqual(self.store.status('2026-11')['charged_including_reservations_bytes'],250)
        with self.assertRaises(RuntimeError):self.store.settle(lease['id'],0)
        lease=self.store.reserve('2026-11',1000,1000)
        self.assertEqual(lease['amount'],750)
        self.store.settle(lease['id'],750)
        self.assertIsNone(self.store.reserve('2026-11',1000,400))

    def test_abrupt_process_death_does_not_refund_authorization(self):
        self.store.reserve('2026-11',1000,400)
        self.store.db.close();self.store=Store(self.path)
        self.assertEqual(self.store.recover(),400)
        self.assertEqual(self.store.recover(),0)
        lease=self.store.reserve('2026-11',1000,1000)
        self.assertEqual(lease['amount'],600)
        self.store.settle(lease['id'],600)
        self.assertIsNone(self.store.reserve('2026-11',1000,400))

    def test_last_packet_tail_closes_budget_without_infinite_refills(self):
        lease=self.store.reserve('2026-11',1000,1000)
        self.store.settle(lease['id'],980,close_remaining=True)
        self.assertIsNone(self.store.reserve('2026-11',1000,1000))
        status=self.store.status('2026-11')
        self.assertEqual(status['finalized_egress_bytes'],980)
        self.assertEqual(status['uncertain_reservations_bytes'],20)

    def test_real_killed_writer_and_sqlite_durability(self):
        code="import os,signal,sys;sys.path.insert(0,"+repr(str(ROOT/'scripts'))+");from traffic_store import Store;s=Store("+repr(str(self.path))+");s.reserve('2026-11',1000,400);os.kill(os.getpid(),signal.SIGKILL)"
        p=subprocess.run([sys.executable,'-c',code],capture_output=True)
        self.assertEqual(p.returncode,-signal.SIGKILL)
        self.assertEqual(self.store.recover(),400)
        self.assertEqual(self.store.status('2026-11')['charged_including_reservations_bytes'],400)

    def test_duplicate_controller_and_clock_rollback_refused(self):
        self.store.reserve('2026-11',1000,100)
        with self.assertRaises(RuntimeError):self.store.reserve('2026-11',1000,100)
        self.store.recover()
        with self.assertRaises(RuntimeError):self.store.reserve('2026-10',1000,100)
        lease=self.store.reserve('2026-12',1000,100)
        self.assertEqual(lease['amount'],100)
        self.assertEqual(self.store.status('2026-11')['uncertain_reservations_bytes'],100)

    def test_counter_baseline_delta_and_new_generation(self):
        s=self.store
        s.sample('mac',100,200,'a','2026-11-17T10:00:00+00:00')
        s.sample('mac',140,300,'a','2026-11-17T10:01:00+00:00')
        s.sample('mac',5,10,'b','2026-11-17T10:02:00+00:00')
        row=s.db.execute('SELECT rx,tx,gaps FROM daily').fetchone()
        self.assertEqual(row,(45,110,1))
        self.assertTrue(s.event('threshold_50',{'percent':50},'2026-11'))
        self.assertFalse(s.event('threshold_50',{'percent':50},'2026-11'))

    def test_no_creation_when_ledger_missing(self):
        with self.assertRaises(RuntimeError):Store(Path(self.tmp.name)/'absent.db')
        empty=Path(self.tmp.name)/'empty.db';empty.touch()
        with self.assertRaises(RuntimeError):Store(empty)
        with self.assertRaises(RuntimeError):Store(self.path,create=True)


def kernel_test():
    if platform.node()!='security-lab-vnic' or os.geteuid()!=0:
        raise SystemExit('Kernel test requires sudo on the confirmed lab VM')
    name='hermes-vpn-traffic-check-'+uuid.uuid4().hex[:10]
    image=json.loads((ROOT/'config/image-lock.json').read_text())['image']
    def run(*a):return subprocess.check_output(a,text=True).strip()
    nft=None
    try:
        run('docker','run','-d','--name',name,'--network','none','--read-only','--cap-drop','ALL',
            '--cap-add','NET_ADMIN','--security-opt','no-new-privileges:true','--memory','64m','--pids-limit','32',
            '--tmpfs','/etc/wireguard:rw,nosuid,nodev,size=1048576','--tmpfs','/run:rw,nosuid,nodev,size=1048576',
            '--entrypoint','/bin/sleep',image,'infinity')
        pid=int(run('docker','inspect','-f','{{.State.Pid}}',name))
        nft=Nft(pid);nft.command('ip','link','set','lo','up')
        # No external route exists. Count UDP in an output hook, including its
        # 28-byte IP/UDP headers, with no internet, real peer or production rule.
        def send(count):
            code="import socket\nr=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);r.bind(('127.0.0.1',48777));s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\nfor _ in range("+str(count)+"):\n try:s.sendto(b'x'*1000,('127.0.0.1',48777))\n except OSError:pass\n"
            nft.command('python3','-c',code)
        with tempfile.TemporaryDirectory() as folder:
            store=Store(Path(folder)/'quota.db',create=True)
            lease=store.reserve('2026-11',4096,4096)
            nft.install(lease=lease,test_port=48777)
            send(10)
            snap=nft.snapshot()
            assert 0<snap['accepted']<=4096 and snap['packets']==3,snap
            assert snap['quota_used']>=4096,'Quota usage units were not parsed as bytes'
            before=snap['accepted'];send(5)
            assert nft.snapshot()['accepted']==before,'Traffic passed an exhausted kernel quota'
            nft.freeze();store.settle(lease['id'],before)
            lease=store.reserve('2026-11',4096,4096)
            assert lease['amount']==4096-before
            nft.install(lease=lease,test_port=48777)
            send(5)
            assert nft.snapshot()['accepted']==0,'A packet larger than remaining budget was accepted'
            # No packet fits the last bytes: close the tail without issuing
            # the same unusable authorization over and over.
            nft.freeze();store.settle(lease['id'],0,close_remaining=True)
            assert store.reserve('2026-11',4096,4096) is None
            # A later calendar month gets new budget; the old month is retained.
            lease=store.reserve('2026-12',4096,4096)
            nft.install(lease=lease,test_port=48777);send(1)
            assert nft.snapshot()['accepted']==1028
            nft.freeze();store.settle(lease['id'],1028)
            # A real killed controller leaves only its prepaid kernel grant.
            crash_db=str(Path(folder)/'crash.db')
            code="import os,signal,sys;sys.path.insert(0,"+repr(str(ROOT/'scripts'))+");from traffic_store import Store;from traffic_nft import Nft;s=Store("+repr(crash_db)+",create=True);a=s.reserve('2026-11',4096,4096);n=Nft("+str(pid)+");n.install(lease=a,test_port=48777);os.kill(os.getpid(),signal.SIGKILL)"
            killed=subprocess.run([sys.executable,'-c',code],capture_output=True)
            assert killed.returncode==-signal.SIGKILL
            send(20);assert nft.snapshot()['accepted']==3084
            recovered=Store(crash_db);nft.freeze()
            assert recovered.recover()==4096
            assert recovered.reserve('2026-11',4096,4096) is None
            send(1);assert nft.snapshot()['accepted']==3084
            recovered.db.close()
            # Production syntax/hook coexistence also parses in this namespace.
            nft.install();nft.install(lease={'id':uuid.uuid4().hex,'amount':4096})
            nft.install(lease={'id':uuid.uuid4().hex,'amount':4096,'period':'2020-01'},test_port=48777)
            send(1);assert nft.snapshot()['accepted']==0,'An expired monthly authorization passed traffic'
            nft.freeze();store.db.close()
        result={'status':'passed','kernel_quota_hard_stop':True,'durable_crash_reservation':True,
                'month_rollover':True,'expired_month_blocked_by_kernel':True,'last_packet_tail_closed':True,'production_rule_syntax':True,'network':'none'}
    finally:
        if nft:nft.close()
        subprocess.run(['docker','rm','-f','-v',name],capture_output=True,check=True)
    result['temporary_container_removed']=True
    print(json.dumps(result))


if __name__=='__main__':
    if '--kernel' in sys.argv:
        kernel_test()
    else:
        unittest.main()
