"""Native-only kernel staging must not fetch or prelink the original kernelcache."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from unixnu import kernel
from unixnu.cli import parser
from unixnu.util import Error


class NativeKernelTests(unittest.TestCase):
    def test_prelink_failure_preserves_previous_output_and_keeps_diagnostics(self):
        self.check_prelink_publication(fail=True)

    def test_prelink_success_publishes_image_and_relocates_record_paths(self):
        self.check_prelink_publication(fail=False)

    def check_prelink_publication(self, fail):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, cache = root / 'native', root / 'cache'
            source.write_bytes(b'native')
            cache.write_bytes(b'cache')
            ctx = SimpleNamespace(tree=root, work=root, logs=root, args=SimpleNamespace(skip_prelink=False),
                                  option=lambda *args: cache,
                                  board={'kernel': {'prelink': {'kernel': 'native', 'tool': 'emit.py', 'slide': '0'}}})
            output = root / 'kernel/kernel.macho'
            output.parent.mkdir()
            output.write_bytes(b'old image')
            output.with_suffix('.json').write_text('{"old": true}')
            output.with_suffix('.map.json').write_text('{"cached": true}')

            def emit(command, **kwargs):
                self.assertEqual(output.read_bytes(), b'old image')
                candidate = command[command.index('--output') + 1]
                self.assertNotEqual(candidate, output)
                self.assertFalse(candidate.exists())
                self.assertEqual(json.loads(candidate.with_suffix('.map.json').read_text()), {'cached': True})
                candidate.with_suffix('.json').write_text(json.dumps({
                    'output': str(candidate.resolve()), 'map': str(candidate.with_suffix('.map.json').resolve())}))
                candidate.write_bytes(b'new image')
                if fail:
                    raise Error('incomplete pairing')

            with patch.object(kernel, 'run', side_effect=emit):
                if fail:
                    with self.assertRaisesRegex(Error, 'incomplete pairing'):
                        kernel.prelink(ctx)
                    self.assertEqual(output.read_bytes(), b'old image')
                    self.assertEqual(json.loads(output.with_suffix('.json').read_text()), {'old': True})
                else:
                    self.assertEqual(kernel.prelink(ctx, adreno_abi='built ABI'), output)
                    self.assertEqual(output.read_bytes(), b'new image')
            report = json.loads(output.with_suffix('.failed.json' if fail else '.json').read_text())
            self.assertEqual(report['output'], str(output.resolve()))
            self.assertEqual(report['map'], str(output.with_suffix('.map.json').resolve()))
            if not fail:
                self.assertEqual(report['adreno_abi_sha256'], 'built ABI')
            self.assertEqual(list(output.parent.glob('.prelink-*')), [])

    def test_skip_prelink_keeps_bytes_and_does_not_fetch_ipsw(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = struct.pack('<8I', 0xfeedfacf, 0x100000c, 2, 2, 0, 0, 0, 0) + b'native seal'
            source = root / 'native'
            source.write_bytes(data)
            ctx = SimpleNamespace(tree=root, work=root / 'out',
                                  args=parser().parse_args(['prelink', '--skip-prelink']),
                                  board={'kernel': {'prelink': {'kernel': 'native'}}})
            with patch.object(kernel.ipsw, 'Ipsw', side_effect=AssertionError('must not fetch')):
                output = kernel.prelink(ctx, adreno_abi='built ABI')
                kernel.prelink(ctx)
                kernel.require_adreno_abi(output, 'built ABI')
                source.write_bytes(data + b'different kernel')
                kernel.prelink(ctx)
                with self.assertRaisesRegex(Error, 'does not match the Adreno ABI'):
                    kernel.require_adreno_abi(output, 'built ABI')
                source.write_bytes(data)
                kernel.prelink(ctx, adreno_abi='built ABI')
            self.assertEqual(output.read_bytes(), data)
            report = json.loads(output.with_suffix('.json').read_text())
            self.assertTrue(report['prelink_skipped'])
            self.assertFalse(report['kernelcache_kexts_added'])
            self.assertEqual(report['candidate_sha256'], hashlib.sha256(data).hexdigest())

    def test_source_gpu_addon_requires_matching_abi_and_kernel(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / 'kernel.macho'
            image.write_bytes(b'prepared kernel')
            record = image.with_suffix('.json')
            metadata = {'candidate_sha256': hashlib.sha256(image.read_bytes()).hexdigest()}
            record.write_text(json.dumps(metadata))
            with self.assertRaisesRegex(Error, 'does not match the Adreno ABI'):
                kernel.require_adreno_abi(image, 'new ABI')
            metadata['adreno_abi_sha256'] = 'old ABI'
            record.write_text(json.dumps(metadata))
            with self.assertRaisesRegex(Error, 'does not match the Adreno ABI'):
                kernel.require_adreno_abi(image, 'new ABI')
            metadata['adreno_abi_sha256'] = 'new ABI'
            record.write_text(json.dumps(metadata))
            kernel.require_adreno_abi(image, 'new ABI')
            image.write_bytes(b'replaced kernel')
            with self.assertRaisesRegex(Error, 'does not match the Adreno ABI'):
                kernel.require_adreno_abi(image, 'new ABI')

    def test_bad_input_preserves_previous_image_and_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / 'input', root / 'kernel.macho'
            output.write_bytes(b'previous')
            output.with_suffix('.json').write_text('{}')
            for data in (b'bad', struct.pack('<8I', 0xfeedfacf, 0x100000c, 2, 12, 0, 0, 0, 0)):
                source.write_bytes(data)
                with self.assertRaisesRegex(Error, 'MH_EXECUTE'):
                    kernel.stage_native(source, output)
                self.assertEqual(output.read_bytes(), b'previous')
                self.assertEqual(output.with_suffix('.json').read_text(), '{}')


class PrelinkRegressionTests(unittest.TestCase):
    def record(self, *symbols):
        return {
            'collection_slide': '0x100',
            'missing': {},
            'stubbed': {},
            'native_original_branches': [{'symbol': symbol} for symbol in symbols],
        }

    def policy(self, **updates):
        result = {
            'missing': {},
            'stubbed': {},
            'required_original_branches': [],
            'required_original_branches_deferred': [],
        }
        result.update(updates)
        return result

    def deferred(self, symbol='adapter', **updates):
        result = {
            'symbol': symbol,
            'reason': 'The current M1 archive set does not contain the adapter.',
            'restore_when': 'The adapter archive is selected and emits this branch.',
        }
        result.update(updates)
        return result

    def test_active_original_branch_is_still_required(self):
        with self.assertRaisesRegex(Error, 'required absolute adapter branch relocations: adapter'):
            kernel.check_prelink_regressions(
                self.record(), self.policy(required_original_branches=['adapter']))

    def test_missing_deferred_original_branch_is_recorded(self):
        report = kernel.check_prelink_regressions(
            self.record(), self.policy(required_original_branches_deferred=[self.deferred()]))
        self.assertEqual(report['deferred_original_branches'], [{
            'symbol': 'adapter',
            'status': 'missing',
            'reason': 'The current M1 archive set does not contain the adapter.',
            'restore_when': 'The adapter archive is selected and emits this branch.',
            'bindings': [],
        }])

    def test_recovered_deferred_original_branch_keeps_emitter_binding(self):
        binding = {'symbol': 'adapter', 'source': '0x1000', 'target': '0x2000', 'owner': 'IOKit'}
        record = self.record()
        record['native_original_branches'] = [binding]
        report = kernel.check_prelink_regressions(
            record, self.policy(required_original_branches_deferred=[self.deferred()]))
        self.assertEqual(report['deferred_original_branches'][0]['status'], 'recovered')
        self.assertEqual(report['deferred_original_branches'][0]['bindings'], [binding])

    def test_active_and_deferred_original_branch_overlap_is_rejected(self):
        with self.assertRaisesRegex(Error, 'both required and deferred: adapter'):
            kernel.check_prelink_regressions(
                self.record('adapter'),
                self.policy(required_original_branches=['adapter'],
                            required_original_branches_deferred=[self.deferred()]))

    def test_deferred_original_branch_requires_reason_and_restore_condition(self):
        for field in ('reason', 'restore_when'):
            with self.subTest(field=field):
                entry = self.deferred()
                del entry[field]
                with self.assertRaisesRegex(Error, field):
                    kernel.check_prelink_regressions(
                        self.record(),
                        self.policy(required_original_branches_deferred=[entry]))

    def test_prelink_persists_regression_summary_in_published_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, cache = root / 'native', root / 'cache'
            source.write_bytes(b'native')
            cache.write_bytes(b'cache')
            policy = root / 'policy.json'
            policy.write_text(json.dumps(self.policy(
                kernelcache_sha256=hashlib.sha256(cache.read_bytes()).hexdigest(),
                required_original_branches_deferred=[self.deferred()])))
            ctx = SimpleNamespace(
                tree=root, work=root, logs=root,
                args=SimpleNamespace(skip_prelink=False),
                option=lambda *args: cache,
                board={'kernel': {'prelink': {
                    'kernel': 'native', 'tool': 'emit.py', 'slide': '0',
                    'regression_policy': 'policy.json',
                }}})
            output = root / 'kernel/kernel.macho'

            def emit(command, **kwargs):
                candidate = Path(command[command.index('--output') + 1])
                candidate.with_suffix('.json').write_text(json.dumps(self.record()))
                candidate.write_bytes(b'new image')

            with patch.object(kernel, 'run', side_effect=emit):
                kernel.prelink(ctx)
            report = json.loads(output.with_suffix('.json').read_text())
            self.assertEqual(
                report['prelink_regression']['deferred_original_branches'][0]['status'],
                'missing')


if __name__ == '__main__':
    unittest.main()
