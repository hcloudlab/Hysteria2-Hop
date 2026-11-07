import importlib.util, json, sqlite3, tempfile, unittest
from pathlib import Path
from unittest.mock import patch, Mock

HY2HOP_PATH = Path(__file__).resolve().parent.parent / 'hy2hop.py'
spec=importlib.util.spec_from_file_location('hy2hop',HY2HOP_PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
# Never touch the real host from unit tests.
m.setup_service = Mock(); m.other_firewall_hint = Mock(); m.legacy_nat_rules = lambda: []

class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'x-ui.db'
        con=sqlite3.connect(self.db)
        con.execute('CREATE TABLE inbounds (id INTEGER,remark TEXT,port INTEGER,enable INTEGER,stream_settings TEXT,listen TEXT,protocol TEXT)')
        self.con=con;self.addCleanup(con.close)
        self.patch=patch.object(m,'DB',self.db);self.patch.start();self.addCleanup(self.patch.stop)
    def add(self,ports='20000-30000',port=443,enabled=1,protocol='hysteria',ident=5):
        data={'finalmask':{'quicParams':{'udpHop':{'ports':ports,'interval':'5-10'}}}}
        self.con.execute('INSERT INTO inbounds VALUES (?,?,?,?,?,?,?)',(ident,'DMIT-Hy2-test',port,enabled,json.dumps(data),'',protocol));self.con.commit()
    def test_known_dmit_shape(self):
        self.add();cfg=m.choose();self.assertEqual((cfg['id'],cfg['port'],cfg['start'],cfg['end']),(5,443,20000,30000))
    def test_disabled_excluded(self):
        self.add(enabled=0)
        with self.assertRaisesRegex(RuntimeError,'未找到启用'):m.choose()
    def test_invalid_range_rejected(self):
        self.add(ports='30000-20000')
        with self.assertRaisesRegex(RuntimeError,'端口超出范围'):m.choose()
    def test_listener_inside_range_rejected(self):
        self.add(port=25000)
        with self.assertRaisesRegex(RuntimeError,'包含监听端口'):m.choose()
    def test_wrong_protocol_not_selected(self):
        self.add(protocol='vless')
        with self.assertRaisesRegex(RuntimeError,'未找到启用'):m.choose()
    def test_multiple_noninteractive_fails_closed(self):
        self.add();self.add(ident=6)
        with patch('sys.stdin.isatty',return_value=False):
            with self.assertRaisesRegex(RuntimeError,'--inbound-id'):m.choose()

if __name__=='__main__':unittest.main()
