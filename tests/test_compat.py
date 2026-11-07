"""Debian/Ubuntu multi-release compatibility and v2 hardening tests."""
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

HY2HOP_PATH = Path(__file__).resolve().parent.parent / 'hy2hop.py'
spec = importlib.util.spec_from_file_location('hy2hop_compat', HY2HOP_PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.setup_service = Mock(); m.other_firewall_hint = Mock(); m.legacy_nat_rules = lambda: []

CFG = {'id': 5, 'remark': 'x', 'port': 443, 'start': 20000, 'end': 30000}


def osr(**kv):
    return dict(kv)


class OsTests(unittest.TestCase):
    def test_supported_matrix(self):
        for ident, versions in m.SUPPORTED.items():
            for v in versions:
                m.check_os(osr(ID=ident, VERSION_ID=v))

    def test_rejects_old_and_unknown(self):
        for info in (osr(ID='debian', VERSION_ID='10'), osr(ID='ubuntu', VERSION_ID='18.04'),
                     osr(ID='centos', VERSION_ID='9'), osr(ID='debian')):
            with self.assertRaisesRegex(RuntimeError, '不支持'):
                m.check_os(info)

    def test_untested_derivative_needs_opt_in(self):
        info = osr(ID='linuxmint', ID_LIKE='ubuntu debian', VERSION_ID='22')
        with self.assertRaises(RuntimeError):
            m.check_os(info)
        with patch.dict(m.os.environ, {'HY2HOP_ALLOW_UNTESTED': '1'}):
            m.check_os(info)
        with patch.dict(m.os.environ, {'HY2HOP_ALLOW_UNTESTED': '1'}), self.assertRaises(RuntimeError):
            m.check_os(osr(ID='fedora', VERSION_ID='41'))

    def test_os_release_parser_quotes(self):
        with tempfile.NamedTemporaryFile('w', suffix='os-release', delete=False) as f:
            f.write('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n# c\n')
        info = m.os_release(Path(f.name))
        self.assertEqual((info['ID'], info['VERSION_ID']), ('debian', '12'))
        Path(f.name).unlink()

    def test_sbin_on_path_and_c_locale(self):
        self.assertIn('/usr/sbin', m.os.environ['PATH'].split(':'))
        self.assertEqual(m.CHILD_ENV['LC_ALL'], 'C')

    def test_boot_reload_skips_release_check(self):
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'check_os') as c, \
             patch.object(m.shutil, 'which', return_value='/bin/x'), patch.object(m, 'Path') as P:
            P.return_value.exists.return_value = True
            m.prerequisites(check_release=False)
        c.assert_not_called()


class RuleTests(unittest.TestCase):
    def test_rule_is_local_only_and_numeric_priority(self):
        s = m.rules(CFG, ['ip', 'ip6'])
        self.assertEqual(s.count('fib daddr type local udp dport 20000-30000 counter redirect to :443'), 2)
        self.assertIn('priority -100;', s)

    def test_unit_follows_nftables_service(self):
        u = m.unit_content()
        for line in ('PartOf=nftables.service', 'ReloadPropagatedFrom=nftables.service',
                     'WantedBy=multi-user.target nftables.service', 'ExecReload='):
            self.assertIn(line, u)

    def test_ip6_dropped_when_kernel_rejects(self):
        with patch.object(m, 'ipv6_available', return_value=True), \
             patch.object(m, 'run', return_value=Mock(returncode=1, stdout='', stderr='no')):
            self.assertEqual(m.families(CFG), ['ip'])
        with patch.object(m, 'ipv6_available', return_value=True), \
             patch.object(m, 'run', return_value=Mock(returncode=0, stdout='')):
            self.assertEqual(m.families(CFG), ['ip', 'ip6'])
        with patch.object(m, 'ipv6_available', return_value=False):
            self.assertEqual(m.families(CFG), ['ip'])


class NatConflictTests(unittest.TestCase):
    def c(self, rule):
        return m.nat_rule_conflicts(rule, 20000, 30000)

    def test_docker_tcp_publish_is_not_a_conflict(self):
        self.assertFalse(self.c('iifname != "docker0" meta l4proto tcp tcp dport 8080 counter dnat to 172.17.0.2:80'))
        self.assertFalse(self.c('-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80'))

    def test_udp_outside_range_ok_inside_conflicts(self):
        self.assertFalse(self.c('udp dport 53 dnat to 10.0.0.2'))
        self.assertTrue(self.c('udp dport 25000 dnat to 10.0.0.2'))
        self.assertTrue(self.c('udp dport { 53, 29000-31000 } redirect to :1'))
        self.assertFalse(self.c('-A PREROUTING -p udp -m multiport --dports 53,40000:41000 -j REDIRECT --to-ports 1'))
        self.assertTrue(self.c('-A PREROUTING -p udp -m udp --dport 19000:21000 -j DNAT --to-destination 1.2.3.4'))

    def test_generic_or_negated_conflicts(self):
        self.assertTrue(self.c('meta l4proto udp tproxy to :12345'))
        self.assertTrue(self.c('redirect to :1'))
        self.assertTrue(self.c('udp dport != 53 dnat to 1.2.3.4'))
        self.assertTrue(self.c('udp dport @ports dnat to 1.2.3.4'))

    def test_docker_ruleset_allows_install(self):
        ruleset = ('table ip nat {\n chain PREROUTING {\n  type nat hook prerouting priority dstnat; policy accept;\n'
                   '  fib daddr type local counter jump DOCKER\n }\n chain DOCKER {\n'
                   '  iifname != "docker0" meta l4proto tcp tcp dport 8080 counter dnat to 172.17.0.2:80\n }\n}\n')
        with patch.object(m, 'udp_sockets', return_value=[]), \
             patch.object(m, 'run', return_value=Mock(returncode=0, stdout=ruleset)):
            m.conflicts(CFG)

    def test_own_table_ignored(self):
        own = 'table ip hcloudlab_hy2hop {\n chain prerouting {\n  udp dport 20000-30000 redirect to :443\n }\n}\n'
        with patch.object(m, 'udp_sockets', return_value=[]), \
             patch.object(m, 'run', return_value=Mock(returncode=0, stdout=own)):
            m.conflicts(CFG)


class SocketTests(unittest.TestCase):
    def ss(self, out):
        return patch.object(m, 'run', return_value=Mock(returncode=0, stdout=out))

    def test_parse_formats(self):
        out = ('UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=1,fd=3))\n'
               'udp UNCONN 0 0 [::]:443 [::]:*\n'
               'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n'
               'UNCONN 0 0 *:8443 *:*\n')
        with self.ss(out):
            got = [(a, p) for a, p, _ in m.udp_sockets()]
        self.assertEqual(got, [('0.0.0.0', 443), ('[::]', 443), ('127.0.0.53%lo', 53), ('*', 8443)])

    def test_listener_loopback_only_rejected(self):
        with self.ss('UNCONN 0 0 127.0.0.1:443 0.0.0.0:*\n'):
            with self.assertRaisesRegex(RuntimeError, '回环'):
                m.listener(CFG)
        with self.ss('UNCONN 0 0 [::]:4430 [::]:*\n'):
            with self.assertRaisesRegex(RuntimeError, '未监听'):
                m.listener(CFG)
        with self.ss('UNCONN 0 0 [::]:443 [::]:*\n'):
            m.listener(CFG)

    def test_ephemeral_outbound_socket_does_not_block(self):
        cfg = dict(CFG, start=30000, end=50000)
        with patch.object(m, 'ephemeral_range', return_value=(32768, 60999)), \
             patch.object(m, 'udp_sockets', return_value=[('0.0.0.0', 40001, 'xray outbound')]), \
             patch.object(m, 'run', return_value=Mock(returncode=0, stdout='')):
            m.conflicts(cfg)
        with patch.object(m, 'ephemeral_range', return_value=(32768, 60999)), \
             patch.object(m, 'udp_sockets', return_value=[('0.0.0.0', 31000, 'service')]):
            with self.assertRaisesRegex(RuntimeError, '冲突'):
                m.conflicts(cfg)


class InboundTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'x-ui.db'
        con = sqlite3.connect(self.db)
        con.execute('CREATE TABLE inbounds (id INTEGER,remark TEXT,port INTEGER,enable INTEGER,'
                    'stream_settings TEXT,listen TEXT,protocol TEXT)')
        for ident, ports, port in ((5, '20000-30000', 443), (6, 'bad', 8443)):
            data = {'finalmask': {'quicParams': {'udpHop': {'ports': ports}}}}
            con.execute('INSERT INTO inbounds VALUES (?,?,?,?,?,?,?)',
                        (ident, 'r', port, 1, json.dumps(data), '', 'hysteria'))
        con.commit(); con.close()
        p = patch.object(m, 'DB', self.db); p.start(); self.addCleanup(p.stop)

    def test_broken_other_inbound_does_not_block(self):
        self.assertEqual(m.choose()['id'], 5)
        self.assertEqual(m.choose(5)['id'], 5)
        with self.assertRaisesRegex(RuntimeError, 'Hop Ports 格式错误'):
            m.choose(6)


class UpgradeTests(unittest.TestCase):
    def test_pre_v2_state_rebuilds_rules_once(self):
        old = {'config': CFG, 'families': ['ip'], 'ufw_owned': []}  # no version → v1 rule without fib
        with patch.object(m, 'read_state', return_value=old), patch.object(m, 'choose', return_value=CFG), \
             patch.object(m, 'listener'), patch.object(m, 'dependency'), patch.object(m, 'conflicts'), \
             patch.object(m, 'families', return_value=['ip']), patch.object(m, 'ufw_add', return_value=False), \
             patch.object(m, 'apply') as a, patch.object(m, 'write_state') as w:
            m.update()
        a.assert_called_once_with(CFG, ['ip'])
        w.assert_called_once()

    def test_state_records_version(self):
        with tempfile.TemporaryDirectory() as d, patch.object(m, 'BASE', Path(d)), \
             patch.object(m, 'STATE', Path(d) / 'state.json'):
            m.write_state({'config': CFG})
            self.assertEqual(json.loads((Path(d) / 'state.json').read_text())['version'], m.VERSION)


if __name__ == '__main__':
    unittest.main()
