"""A cached comparison kernel must belong to the requested build inputs."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'reference', Path(__file__).with_name('build-fileset-release-reference.py'))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


class ReferenceCacheTests(unittest.TestCase):
    def test_only_known_comparison_symbols_are_stubbed(self):
        build_log = '''Undefined symbols for architecture arm64e:
  "_corecrypto_kext_start", referenced from:
      _source_corecrypto14_bootstrap in prng_random.o
  "_native_ram_block_volume_seed", referenced from:
      _load_init_program in kern_exec.o
  "_arm64_platform_sleep_hook", referenced from:
      ArmCpu::start(IOService*) in libArmCpu.a(ArmCpu.o)
  "_boot_cache_input_capture", referenced from:
      _boot_cache_init in bsd_init.o
  "_unexpected_symbol", referenced from:
      _bug in bug.o
'''
        self.assertEqual(reference.reference_stub_names(build_log), [
            '_arm64_platform_sleep_hook',
            '_boot_cache_input_capture',
            '_native_ram_block_volume_seed',
        ])

    def test_link_diagnostic_reports_only_the_undefined_symbol_block(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'build.log'
            log.write_text('prefix noise\n'
                           'Undefined symbols for architecture arm64e:\n'
                           '  "_corecrypto_kext_start", referenced from:\n'
                           '      _source_corecrypto14_bootstrap in prng_random.o\n'
                           'ld: symbol(s) not found for architecture arm64e\n'
                           'make: *** [build_all] Error 2\n')
            detail = reference.link_diagnostic(log)
            self.assertIn('"_corecrypto_kext_start"', detail)
            self.assertNotIn('prefix noise', detail)
            self.assertNotIn('make: ***', detail)

    def test_latest_nested_link_log_uses_the_isolated_build_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            older = root / 'lto-old/lto-build.log'
            newer = root / 'lto-new/lto-build.log'
            older.parent.mkdir()
            newer.parent.mkdir()
            older.write_text('old')
            newer.write_text('new')
            os.utime(older, (1, 1))
            os.utime(newer, (2, 2))
            self.assertEqual(reference.latest_nested_link_log(root), newer)

    def test_lto_filelist_paths_are_relative_to_the_object_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nonltolink.filelist').write_text('lastkernelconstructor.o\nnonlto.o\n')
            self.assertEqual(reference.linked_objects(root, True),
                             [str(root / name) for name in
                              ('lastkernelconstructor.o', 'nonlto.o', 'justlto.o')])

    def test_builder_rebuilds_snapshot_as_lto_then_reuses_matching_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = ['.cache/xnu-work/osfmk/arm64/sleh.c',
                     '.cache/xnu-work/config/Private.exports',
                     '.cache/xnu-work/config/Private.arm64.exports',
                     '.cache/fakeroot/usr/include/header.h',
                     'build/corecrypto-2023/libcorecrypto_kernel_noasm-namespaced.a',
                     'build/libpthread-kernel/libpthread_kernel.a',
                     'build/armdt-platform/libArmDTPlatform.a',
                     'build/armcpu/libArmCpu.a']
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('')
            builds = []

            def make(command, **kwargs):
                if command[:2] == ['xcrun', 'nm']:
                    return SimpleNamespace(returncode=0, stdout='')
                values = dict(arg.split('=', 1) for arg in command if '=' in arg)
                mode = values['BUILD_LTO']
                builds.append(mode)
                output = Path(values['OBJROOT']) / 'RELEASE_ARM64_BCM2837'
                output.mkdir(parents=True, exist_ok=True)
                if mode == '1':
                    (output / 'nonltolink.filelist').write_text('')
                    (output / 'justlto.o').write_bytes(b'object')
                else:
                    (output / 'link.filelist').write_text('')
                (output / 'mach.release.bcm2837.unstripped').write_text(mode)
                return SimpleNamespace(returncode=0)

            argv = ['reference', '--tree', str(root)]
            with patch.object(reference.subprocess, 'run', side_effect=make), \
                    patch.object(reference.subprocess, 'check_output', return_value='compiler'), \
                    patch('sys.argv', argv):
                reference.main()
                self.assertEqual(builds, ['0', '0'])
                argv.append('--lto')
                reference.main()
                self.assertEqual(builds, ['0', '0', '1', '1'])
                reference.main()
                self.assertEqual(builds, ['0', '0', '1', '1'])
                final = root / 'build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf'
                self.assertEqual(final.read_text(), '1')

    def test_second_link_failure_reports_the_nested_undefined_symbols(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = ['.cache/xnu-work/osfmk/arm64/sleh.c',
                     '.cache/xnu-work/config/Private.exports',
                     '.cache/xnu-work/config/Private.arm64.exports',
                     '.cache/fakeroot/usr/include/header.h',
                     'build/corecrypto-2023/libcorecrypto_kernel_noasm-namespaced.a',
                     'build/libpthread-kernel/libpthread_kernel.a',
                     'build/armdt-platform/libArmDTPlatform.a',
                     'build/armcpu/libArmCpu.a']
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('')
            link_calls = 0

            def fail_links(command, **kwargs):
                nonlocal link_calls
                if command[:2] == ['xcrun', 'nm']:
                    return SimpleNamespace(returncode=0, stdout='')
                values = dict(arg.split('=', 1) for arg in command if '=' in arg)
                output = Path(values['OBJROOT']) / 'RELEASE_ARM64_BCM2837'
                output.mkdir(parents=True, exist_ok=True)
                (output / 'nonltolink.filelist').write_text('')
                (output / 'justlto.o').mkdir(exist_ok=True)
                link_calls += 1
                diagnostic = (
                    'Undefined symbols for architecture arm64e:\n'
                    f'  "_missing_second_link_{link_calls}", referenced from:\n'
                    '      _source_corecrypto14_bootstrap in prng_random.o\n'
                    'ld: symbol(s) not found for architecture arm64e\n')
                kwargs['stdout'].write(diagnostic)
                nested = output.parent / 'lto-build.log'
                with nested.open('a') as log:
                    log.write(diagnostic)
                return SimpleNamespace(returncode=2)

            argv = ['reference', '--tree', str(root), '--lto']
            with patch.object(reference.subprocess, 'run', side_effect=fail_links), \
                    patch.object(reference.subprocess, 'check_output', return_value='compiler'), \
                    patch('sys.argv', argv):
                with self.assertRaises(SystemExit) as stopped:
                    reference.main()
            self.assertEqual(link_calls, 2)
            self.assertIn('RELEASE reference second link failed (2)', str(stopped.exception))
            self.assertIn('_missing_second_link_2', str(stopped.exception))
            self.assertIn('lto-build.log', str(stopped.exception))

    def test_old_snapshot_cannot_satisfy_lto_request(self):
        with tempfile.TemporaryDirectory() as directory:
            final = Path(directory) / 'reference'
            record = Path(directory) / 'record.json'
            final.write_bytes(b'comparison kernel')
            snapshot = {'mode': 'snapshot', 'source': 'old'}
            self.assertFalse(reference.reusable(final, record, snapshot))
            record.write_text(json.dumps({'inputs': snapshot, 'sha256': reference.file_hash(final)}))
            self.assertTrue(reference.reusable(final, record, snapshot))
            self.assertFalse(reference.reusable(final, record, dict(snapshot, mode='lto')))
            self.assertFalse(reference.reusable(final, record, dict(snapshot, source='changed')))
            final.write_bytes(b'corrupt kernel')
            self.assertFalse(reference.reusable(final, record, snapshot))

    def test_source_content_and_linked_sdk_headers_invalidate_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            header = source / 'header.h'
            header.write_text('old')
            timestamp = header.stat().st_mtime_ns
            first = reference.tree_hash(source)
            header.write_text('new')
            os.utime(header, ns=(timestamp, timestamp))
            self.assertNotEqual(first, reference.tree_hash(source))
            sdk = root / 'sdk'
            sdk.mkdir()
            try:
                (sdk / 'include').symlink_to(source, target_is_directory=True)
            except OSError as error:
                if os.name == 'nt' and getattr(error, 'winerror', None) == 1314:
                    self.skipTest('Windows symlink privilege is not available')
                raise
            first = reference.tree_hash(sdk)
            header.write_text('next')
            self.assertNotEqual(first, reference.tree_hash(sdk))


if __name__ == '__main__':
    unittest.main()
