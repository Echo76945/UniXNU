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

    def test_incomplete_optional_group_is_not_partially_selected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = root / 'tree'
            device = root / 'device'
            package = device / 'package'
            package.mkdir(parents=True)
            (package / 'BootProcessProbe.c').write_text('/* present */\n')
            present, missing, skipped = MODULE.optional_ios27_sources(
                MODULE.package_dirs_for(tree, device), device, tree)
            self.assertEqual(present, [])
            self.assertEqual(missing, [
                'BootUiTraceProbe.c', 'BootProcessWorker.c', 'BootDiagExport.c',
                'BootLatencyTrace.h', 'BootLatencyFiles.h', 'TouchTrace.h',
                'WifiFirmware.c', 'WifiFirmware.h', 'BluetoothFirmware.c',
                'BluetoothFirmware.h',
            ])
            self.assertEqual(skipped, ['boot-process-capture'])

    def test_complete_optional_group_is_selected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = root / 'tree'
            device = root / 'device'
            package = device / 'package'
            package.mkdir(parents=True)
            for name in ('BootProcessProbe.c', 'BootUiTraceProbe.c', 'BootProcessWorker.c'):
                (package / name).write_text('/* present */\n')
            present, missing, skipped = MODULE.optional_ios27_sources(
                MODULE.package_dirs_for(tree, device), device, tree)
            self.assertEqual(present, [
                package / 'BootProcessProbe.c',
                package / 'BootUiTraceProbe.c',
                package / 'BootProcessWorker.c',
            ])
            self.assertNotIn('boot-process-capture', skipped)

    def test_boot_log_stubs_and_real_boot_reset_are_discovered(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = root / 'tree'
            device = root / 'device'
            package = device / 'package'
            package.mkdir(parents=True)
            stubs = package / 'BootLogStubs.c'
            reset = package / 'BootReset.c'
            stubs.write_text('/* weak board helpers */\n')
            reset.write_text('/* board reset implementation */\n')
            directories = MODULE.package_dirs_for(tree, device)
            self.assertEqual(
                MODULE.find_device_source('BootLogStubs.c', directories, device, tree), stubs)
            self.assertEqual(
                MODULE.find_device_source('BootReset.c', directories, device, tree), reset)

    def test_source_storage_defaults_cover_arm64e_weak_addresses(self):
        text = MODULE.source_storage_link_defaults()
        self.assertIn('int native_ufs_store_write_cached(', text)
        self.assertIn('return native_ufs_store_write(', text)
        self.assertIn('bool ml_static_mfree_prepare(', text)
        self.assertIn('void (*arm64_platform_sleep_hook)(boolean_t boot_cpu);', text)
        self.assertEqual(text.count('__attribute__((weak, visibility("hidden")))'), 3)


if __name__ == '__main__':
    unittest.main()
