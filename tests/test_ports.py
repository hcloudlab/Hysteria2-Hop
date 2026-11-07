import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

HY2HOP_PATH = Path(__file__).resolve().parent.parent / 'hy2hop.py'
spec = importlib.util.spec_from_file_location('hy2hop_ports', HY2HOP_PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
# Never touch the real host from unit tests.
m.setup_service = Mock(); m.other_firewall_hint = Mock(); m.legacy_nat_rules = lambda: []

CFG = {'id': 5, 'remark': 'DMIT-Hy2-test', 'port': 443, 'start': 20000, 'end': 30000}
NEW_CFG = {'id': 5, 'remark': 'DMIT-Hy2-test', 'port': 15447, 'start': 21000, 'end': 49000}


class PortOwnershipTests(unittest.TestCase):
    """Covers HCloudLab/Hysteria2-Hop listen-port UFW gap: install/update/restore/status
    must manage the UFW rule for the real listen port, not just the hop range."""

    def test_specs_returns_hop_and_listen_port(self):
        self.assertEqual(m.specs(CFG), ('20000:30000/udp', '443/udp'))

    def test_install_adds_both_ufw_rules_when_active(self):
        # Exercise the real ufw_add/ufw_active/ufw_has call chain; only subprocess.run is faked,
        # so this checks the actual 'ufw allow ...' command strings, not just a mocked helper.
        calls = []

        def fake_run(cmd, check=True, input_text=None):
            calls.append(cmd)
            if cmd[:2] == ['ufw', 'status']:
                return Mock(returncode=0, stdout='Status: active\n')
            if cmd[:3] == ['ufw', 'show', 'added']:
                return Mock(returncode=0, stdout='')
            return Mock(returncode=0, stdout='')

        with patch.object(m, 'choose', return_value=CFG), patch.object(m, 'listener'), \
             patch.object(m, 'dependency'), patch.object(m, 'owned_tables', return_value=[]), \
             patch.object(m, 'conflicts'), patch.object(m, 'families', return_value=['ip']), \
             patch.object(m, 'apply'), patch.object(m, 'setup_service'), \
             patch.object(m.shutil, 'which', return_value='/usr/sbin/ufw'), \
             patch.object(m, 'write_state') as w, patch.object(m, 'run', side_effect=fake_run):
            m.install()
        allow_calls = sorted(c for c in calls if c[:2] == ['ufw', 'allow'])
        self.assertEqual(allow_calls, [['ufw', 'allow', '20000:30000/udp'], ['ufw', 'allow', '443/udp']])
        w.assert_called_once()
        self.assertEqual(sorted(w.call_args.args[0]['ufw_owned']), ['20000:30000/udp', '443/udp'])

    def test_install_ufw_inactive_adds_nothing_and_does_not_error(self):
        def fake_run(cmd, check=True, input_text=None):
            if cmd[:2] == ['ufw', 'status']:
                return Mock(returncode=0, stdout='Status: inactive\n')
            return Mock(returncode=0, stdout='')

        with patch.object(m, 'choose', return_value=CFG), patch.object(m, 'listener'), \
             patch.object(m, 'dependency'), patch.object(m, 'owned_tables', return_value=[]), \
             patch.object(m, 'conflicts'), patch.object(m, 'families', return_value=['ip']), \
             patch.object(m, 'apply'), patch.object(m, 'setup_service'), \
             patch.object(m.shutil, 'which', return_value='/usr/sbin/ufw'), \
             patch.object(m, 'write_state') as w, patch.object(m, 'run', side_effect=fake_run) as r:
            m.install()
        self.assertFalse(any(c.args[0][:2] == ['ufw', 'allow'] for c in r.call_args_list))
        self.assertEqual(w.call_args.args[0]['ufw_owned'], [])

    def test_install_preexisting_rules_not_duplicated_or_reowned(self):
        def fake_run(cmd, check=True, input_text=None):
            if cmd[:2] == ['ufw', 'status']:
                return Mock(returncode=0, stdout='Status: active\n')
            if cmd[:3] == ['ufw', 'show', 'added']:
                return Mock(returncode=0, stdout='ufw allow 20000:30000/udp\nufw allow 443/udp\n')
            return Mock(returncode=0, stdout='')

        with patch.object(m, 'choose', return_value=CFG), patch.object(m, 'listener'), \
             patch.object(m, 'dependency'), patch.object(m, 'owned_tables', return_value=[]), \
             patch.object(m, 'conflicts'), patch.object(m, 'families', return_value=['ip']), \
             patch.object(m, 'apply'), patch.object(m, 'setup_service'), \
             patch.object(m.shutil, 'which', return_value='/usr/sbin/ufw'), \
             patch.object(m, 'write_state') as w, patch.object(m, 'run', side_effect=fake_run) as r:
            m.install()
        self.assertFalse(any(c.args[0][:2] == ['ufw', 'allow'] for c in r.call_args_list))
        self.assertEqual(w.call_args.args[0]['ufw_owned'], [])

    def test_install_ufw_add_failure_rolls_back_already_added_spec(self):
        def fake_ufw_add(s):
            if s == '443/udp':
                raise RuntimeError('ufw add failed')
            return True

        with patch.object(m, 'choose', return_value=CFG), patch.object(m, 'listener'), \
             patch.object(m, 'dependency'), patch.object(m, 'owned_tables', return_value=[]), \
             patch.object(m, 'conflicts'), patch.object(m, 'families', return_value=['ip']), \
             patch.object(m, 'ufw_add', side_effect=fake_ufw_add), patch.object(m, 'ufw_delete') as ud, \
             patch.object(m, 'delete_tables') as d, patch.object(m, 'clean_service') as c, \
             patch.object(m, 'apply') as a, patch.object(m, 'STATE') as s, patch.object(m, 'UNIT') as unit:
            s.exists.return_value = False
            unit.exists.return_value = False
            with self.assertRaisesRegex(RuntimeError, 'ufw add failed'):
                m.install()
        a.assert_not_called()
        ud.assert_called_once_with('20000:30000/udp')
        d.assert_called_once()
        c.assert_called_once()

    def test_update_changes_port_and_range_cleans_up_old_owned(self):
        old = {'config': CFG, 'families': ['ip'], 'version': m.VERSION, 'ufw_owned': ['20000:30000/udp', '443/udp']}
        with patch.object(m, 'read_state', return_value=old), patch.object(m, 'choose', return_value=NEW_CFG), \
             patch.object(m, 'listener'), patch.object(m, 'dependency'), patch.object(m, 'conflicts'), \
             patch.object(m, 'families', return_value=['ip']), patch.object(m, 'ufw_add', return_value=True) as ua, \
             patch.object(m, 'ufw_delete') as ud, patch.object(m, 'apply') as a, \
             patch.object(m, 'write_state') as w:
            m.update()
        ua.assert_any_call('21000:49000/udp')
        ua.assert_any_call('15447/udp')
        self.assertEqual(sorted(c.args[0] for c in ud.call_args_list), ['20000:30000/udp', '443/udp'])
        a.assert_called_once_with(NEW_CFG, ['ip'])
        final_state = w.call_args_list[-1].args[0]
        self.assertEqual(sorted(final_state['ufw_owned']), ['15447/udp', '21000:49000/udp'])

    def test_update_backfills_missing_listen_port_rule_from_old_version_state(self):
        # Pre-fix installs only ever recorded ownership of the hop-range spec.
        old = {'config': CFG, 'families': ['ip'], 'version': m.VERSION, 'ufw_owned': ['20000:30000/udp']}
        with patch.object(m, 'read_state', return_value=old), patch.object(m, 'choose', return_value=CFG), \
             patch.object(m, 'listener'), patch.object(m, 'dependency'), patch.object(m, 'conflicts'), \
             patch.object(m, 'families', return_value=['ip']), \
             patch.object(m, 'ufw_add', side_effect=lambda s: s == '443/udp') as ua, \
             patch.object(m, 'ufw_delete') as ud, patch.object(m, 'apply') as a, \
             patch.object(m, 'write_state') as w:
            m.update()
        ua.assert_called_once_with('443/udp')  # hop spec already owned, not re-added
        a.assert_not_called()  # nft mapping unchanged, no need to rebuild it
        ud.assert_not_called()  # nothing stale to clean up
        self.assertEqual(sorted(w.call_args.args[0]['ufw_owned']), ['20000:30000/udp', '443/udp'])

    def test_update_idempotent_when_fully_owned_and_unchanged(self):
        old = {'config': CFG, 'families': ['ip'], 'version': m.VERSION, 'ufw_owned': ['20000:30000/udp', '443/udp']}
        with patch.object(m, 'read_state', return_value=old), patch.object(m, 'choose', return_value=CFG), \
             patch.object(m, 'listener'), patch.object(m, 'dependency'), patch.object(m, 'conflicts'), \
             patch.object(m, 'families', return_value=['ip']), patch.object(m, 'ufw_add') as ua, \
             patch.object(m, 'apply') as a, patch.object(m, 'write_state') as w:
            m.update()
        ua.assert_not_called()
        a.assert_not_called()
        w.assert_not_called()

    def test_restore_removes_all_owned_specs_including_listen_port(self):
        state = {'config': CFG, 'families': ['ip'], 'ufw_owned': ['20000:30000/udp', '443/udp']}
        with patch.object(m, 'read_state', return_value=state), patch.object(m, 'run'), \
             patch.object(m, 'delete_tables') as d, patch.object(m, 'ufw_delete') as ud, \
             patch.object(m, 'clean_service') as c, patch.object(m, 'STATE') as s:
            m.restore()
        self.assertEqual(sorted(call.args[0] for call in ud.call_args_list), ['20000:30000/udp', '443/udp'])
        d.assert_called_once()
        c.assert_called_once()

    def test_status_fails_when_listen_port_rule_missing(self):
        state = {'config': CFG, 'families': ['ip']}

        def fake_run(cmd, check=True, input_text=None):
            if cmd[:3] == ['nft', 'list', 'chain']:
                return Mock(returncode=0, stdout='udp dport 20000-30000 counter redirect to :443\n')
            if cmd[:2] == ['systemctl', 'is-enabled']:
                return Mock(returncode=0, stdout='enabled\n')
            if cmd[:2] == ['ufw', 'status']:
                return Mock(returncode=0, stdout='Status: active\n')
            if cmd[:3] == ['ufw', 'show', 'added']:
                return Mock(returncode=0, stdout='ufw allow 20000:30000/udp\n')  # listen port missing
            return Mock(returncode=0, stdout='')

        with patch.object(m, 'read_state', return_value=state), patch.object(m, 'inbounds', return_value=([CFG], {})), \
             patch.object(m, 'listener'), patch.object(m.shutil, 'which', return_value='/usr/sbin/ufw'), \
             patch.object(m, 'run', side_effect=fake_run):
            rc = m.status()
        self.assertEqual(rc, 1)

    def test_status_passes_when_both_rules_present(self):
        state = {'config': CFG, 'families': ['ip']}

        def fake_run(cmd, check=True, input_text=None):
            if cmd[:3] == ['nft', 'list', 'chain']:
                return Mock(returncode=0, stdout='udp dport 20000-30000 counter redirect to :443\n')
            if cmd[:2] == ['systemctl', 'is-enabled']:
                return Mock(returncode=0, stdout='enabled\n')
            if cmd[:2] == ['ufw', 'status']:
                return Mock(returncode=0, stdout='Status: active\n')
            if cmd[:3] == ['ufw', 'show', 'added']:
                return Mock(returncode=0, stdout='ufw allow 20000:30000/udp\nufw allow 443/udp\n')
            return Mock(returncode=0, stdout='')

        with patch.object(m, 'read_state', return_value=state), patch.object(m, 'inbounds', return_value=([CFG], {})), \
             patch.object(m, 'listener'), patch.object(m.shutil, 'which', return_value='/usr/sbin/ufw'), \
             patch.object(m, 'run', side_effect=fake_run):
            rc = m.status()
        self.assertEqual(rc, 0)

    def test_status_ufw_inactive_does_not_report_missing_rules(self):
        state = {'config': CFG, 'families': ['ip']}

        def fake_run(cmd, check=True, input_text=None):
            if cmd[:3] == ['nft', 'list', 'chain']:
                return Mock(returncode=0, stdout='udp dport 20000-30000 counter redirect to :443\n')
            if cmd[:2] == ['systemctl', 'is-enabled']:
                return Mock(returncode=0, stdout='enabled\n')
            if cmd[:2] == ['ufw', 'status']:
                return Mock(returncode=0, stdout='Status: inactive\n')
            return Mock(returncode=0, stdout='')

        with patch.object(m, 'read_state', return_value=state), patch.object(m, 'inbounds', return_value=([CFG], {})), \
             patch.object(m, 'listener'), patch.object(m, 'run', side_effect=fake_run):
            rc = m.status()
        self.assertEqual(rc, 0)

    def test_update_nat_apply_failure_rolls_back_ufw_and_nft(self):
        old = {'config': CFG, 'families': ['ip'], 'version': m.VERSION, 'ufw_owned': ['20000:30000/udp', '443/udp']}
        with patch.object(m, 'read_state', return_value=old), patch.object(m, 'choose', return_value=NEW_CFG), \
             patch.object(m, 'listener'), patch.object(m, 'dependency'), patch.object(m, 'conflicts'), \
             patch.object(m, 'families', return_value=['ip']), patch.object(m, 'ufw_add', return_value=True), \
             patch.object(m, 'ufw_delete') as ud, patch.object(m, 'apply', side_effect=RuntimeError('nat failed')) as a, \
             patch.object(m, 'write_state') as w:
            with self.assertRaisesRegex(RuntimeError, 'nat failed'):
                m.update()
        # apply() only attempted once (the failing forward call); no old config to roll back to
        # since apply never successfully switched over.
        a.assert_called_once_with(NEW_CFG, ['ip'])
        # Newly added specs for the new config get rolled back; old owned specs untouched.
        self.assertEqual(sorted(c.args[0] for c in ud.call_args_list), ['15447/udp', '21000:49000/udp'])
        w.assert_called_once_with(old)


if __name__ == '__main__':
    unittest.main()
