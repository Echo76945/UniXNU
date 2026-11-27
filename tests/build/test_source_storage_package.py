"""Validate source-storage package lookup for assembled board kits."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'build-sheng-source-storage.py'
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location('build_sheng_source_storage', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SourceStoragePackageTests(unittest.TestCase):
    def test_board_kit_is_preferred(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = root / 'tree'
            tree.mkdir()
            device = root / 'device'
            device.mkdir()
            (device / 'board.toml').write_text('[board]\nkit = "muyu"\n')
            directories = MODULE.package_dirs_for(tree, device)
            self.assertIn(device / 'kits' / 'muyu', directories)
            self.assertIn(tree / 'kits' / 'muyu', directories)
            self.assertLess(directories.index(tree / 'kits' / 'muyu'),
                            directories.index(tree / 'kits' / 'sheng'))

    def test_legacy_sheng_kit_remains_a_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = root / 'tree'
            tree.mkdir()
            device = root / 'device'
            directories = MODULE.package_dirs_for(tree, device)
            self.assertEqual(directories, [device / 'package', device / 'kits' / 'sheng',
                                            tree / 'kits' / 'sheng'])

    def test_environment_device_is_used(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = root / 'tree'
            device = root / 'device'
            with mock.patch.dict(MODULE.os.environ, {'UNIXNU_DEVICE': str(device)}):
                self.assertEqual(MODULE.resolve_device(tree), device.resolve())


if __name__ == '__main__':
    unittest.main()
