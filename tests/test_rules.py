import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
HY2HOP_PATH = Path(__file__).resolve().parent.parent / 'hy2hop.py'
spec=importlib.util.spec_from_file_location('hy2hop_rules',HY2HOP_PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
# Never touch the real host from unit tests.
m.setup_service = Mock(); m.other_firewall_hint = Mock(); m.legacy_nat_rules = lambda: []
CFG={'id':5,'remark':'DMIT-Hy2-test','port':443,'start':20000,'end':30000}
class RulesTests(unittest.TestCase):
 def test_dual_stack(self):
  s=m.rules(CFG,['ip','ip6']);self.assertEqual(s.count('redirect to :443'),2)
 def test_owned_only(self):
  s=m.rules(CFG,['ip'],['ip']);self.assertIn('delete table ip hcloudlab_hy2hop',s);self.assertNotIn('flush ruleset',s)
 def test_conflict_listener(self):
  with patch.object(m,'run',return_value=Mock(returncode=0,stdout='UNCONN 0 0 0.0.0.0:25000 0.0.0.0:*\n')):
   with self.assertRaisesRegex(RuntimeError,'冲突'):m.conflicts(CFG)
 def test_nat_conflict(self):
  ss=Mock(returncode=0,stdout='');nft=Mock(returncode=0,stdout='table ip nat {\n udp dport 25000 redirect to :443\n}\n')
  with patch.object(m,'run',side_effect=[ss,nft]):
   with self.assertRaisesRegex(RuntimeError,'NAT'):m.conflicts(CFG)
 def test_ufw_preexisting(self):
  with patch.object(m,'ufw_active',return_value=True),patch.object(m,'ufw_has',return_value=True),patch.object(m,'run') as r:
   self.assertFalse(m.ufw_add('20000:30000/udp'));r.assert_not_called()
 def test_ufw_new(self):
  with patch.object(m,'ufw_active',return_value=True),patch.object(m,'ufw_has',return_value=False),patch.object(m,'run') as r:
   self.assertTrue(m.ufw_add('20000:30000/udp'));r.assert_called_once()
 def test_orphan_refusal(self):
  with patch.object(m,'read_state',return_value=None),patch.object(m,'UNIT',Mock(exists=lambda:True)):
   with self.assertRaisesRegex(RuntimeError,'无状态'):m.restore()
 def test_atomic_batch(self):
  with patch.object(m,'run') as r,patch.object(m,'owned_tables',return_value=['ip']):
   m.apply(CFG,['ip']);self.assertEqual(r.call_args.args[0],['nft','-f','-'])
 def test_no_install_dep_when_present(self):
  with patch.object(m.shutil,'which',return_value='/usr/sbin/nft'),patch.object(m,'run') as r:
   m.dependency();r.assert_not_called()
 def test_update_noop(self):
  old={'config':CFG,'families':['ip'],'version':m.VERSION,'ufw_owned':['20000:30000/udp','443/udp']}
  with patch.object(m,'read_state',return_value=old),patch.object(m,'choose',return_value=CFG),patch.object(m,'listener'),patch.object(m,'dependency'),patch.object(m,'conflicts'),patch.object(m,'families',return_value=['ip']),patch.object(m,'apply') as a,patch.object(m,'ufw_add') as ua,patch.object(m,'write_state') as w:
   m.update();a.assert_not_called();ua.assert_not_called();w.assert_not_called()
 def test_install_rollback(self):
  with patch.object(m,'choose',return_value=CFG),patch.object(m,'listener'),patch.object(m,'dependency'),patch.object(m,'owned_tables',return_value=[]),patch.object(m,'conflicts'),patch.object(m,'families',return_value=['ip']),patch.object(m,'ufw_add',return_value=True),patch.object(m,'apply',side_effect=RuntimeError('injected')),patch.object(m,'delete_tables') as d,patch.object(m,'ufw_delete') as u,patch.object(m,'clean_service') as c,patch.object(m,'STATE') as s,patch.object(m,'UNIT') as unit:
   s.exists.return_value=False;unit.exists.return_value=False
   with self.assertRaisesRegex(RuntimeError,'injected'):m.install()
   d.assert_called_once();self.assertEqual(u.call_count,2);c.assert_called_once()
 def test_update_rollback(self):
  old={'config':dict(CFG,start=10000,end=11000),'families':['ip'],'ufw_owned':['10000:11000/udp']}
  with patch.object(m,'read_state',return_value=old),patch.object(m,'choose',return_value=CFG),patch.object(m,'listener'),patch.object(m,'dependency'),patch.object(m,'conflicts'),patch.object(m,'families',return_value=['ip']),patch.object(m,'ufw_add',return_value=True),patch.object(m,'apply',side_effect=[None,None]) as a,patch.object(m,'write_state',side_effect=[RuntimeError('disk full'),None]),patch.object(m,'ufw_delete') as u:
   with self.assertRaisesRegex(RuntimeError,'disk full'):m.update()
   self.assertEqual(a.call_count,2);self.assertEqual(u.call_count,2)
if __name__=='__main__':unittest.main()
