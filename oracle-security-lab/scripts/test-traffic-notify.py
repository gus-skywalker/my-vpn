#!/usr/bin/env python3
"""Offline notification retry/deduplication, without Telegram or quota changes."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('notify',Path(__file__).with_name('traffic-notify.py'))
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)


class Tests(unittest.TestCase):
    def test_retry_restart_dedup_and_fixed_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'notifications.db';db=n.receipts(path)
            n.enqueue(db,[('2026-11','threshold_50'),('2026-11','initialized')],8*10**12)
            def fail(_):raise OSError()
            n.deliver(db,fail,now=100)
            self.assertEqual(db.execute('SELECT attempts,delivered FROM outbox').fetchone(),(1,None))
            sent=[];n.deliver(db,sent.append,now=110);self.assertEqual(sent,[])
            db.close();db=n.receipts(path)
            n.enqueue(db,[('2026-11','threshold_50')],8*10**12)
            n.deliver(db,sent.append,now=160);n.deliver(db,sent.append,now=200)
            self.assertEqual(len(sent),1)
            self.assertIn('50%',sent[0]);self.assertIn('8.0 TB',sent[0])
            self.assertEqual(db.execute('SELECT delivered FROM outbox').fetchone(),(160,))
            db.close()


if __name__=='__main__':unittest.main()
