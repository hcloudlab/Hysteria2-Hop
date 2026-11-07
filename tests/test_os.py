import importlib.util
import unittest
from pathlib import Path

path = Path(__file__).resolve().parent.parent / 'hy2hop.py'
spec = importlib.util.spec_from_file_location('hy2hop_os', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SupportedOsTests(unittest.TestCase):
    def test_ubuntu_2404_retained(self):
        self.assertTrue(module.supported_os('ID=ubuntu\nVERSION_ID="24.04"\n'))

    def test_debian_12(self):
        self.assertTrue(module.supported_os('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'))

    def test_debian_13(self):
        self.assertTrue(module.supported_os('ID=debian\nVERSION_ID=13\n'))

    def test_reject_unsupported(self):
        for data in ('ID=debian\nVERSION_ID=11\n',
                     'ID=ubuntu\nVERSION_ID=22.04\n',
                     'ID=linuxmint\nID_LIKE=ubuntu\nVERSION_ID=24.04\n',
                     'ID=debian\n',
                     'ID=debian\nVERSION_ID=12.1\n'):
            with self.subTest(data=data):
                self.assertFalse(module.supported_os(data))


if __name__ == '__main__':
    unittest.main()
