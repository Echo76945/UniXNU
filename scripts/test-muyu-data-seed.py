#!/usr/bin/env python3

import importlib.util
import struct
import tempfile
import unittest
import uuid
from pathlib import Path

SCRIPT = Path(__file__).with_name('muyu-data-seed.py')
SPEC = importlib.util.spec_from_file_location('muyu_data_seed', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

PAGE = 4096
OLD_UUID = uuid.UUID('11111111-2222-3333-4444-555555555555')
NEW_UUID = uuid.UUID('58B481F8-4243-4430-BF60-DDD1638D4C6E')


def raw_image():
    image = bytearray(4 * PAGE)
    image[32:36] = b'NXSB'
    struct.pack_into('<I', image, 36, PAGE)
    image[72:88] = uuid.UUID('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE').bytes

    block = 2 * PAGE
    image[block + 32:block + 36] = b'APSB'
    image[block + MODULE.APFS_VOLUME_UUID_OFFSET:block + MODULE.APFS_VOLUME_UUID_OFFSET + 16] = OLD_UUID.bytes
    image[block:block + 8] = MODULE.fletcher64(image[block + 8:block + PAGE])
    return image


def packed(image):
    logical, extents = len(image), []
    for offset in range(0, len(image), PAGE):
        page = image[offset:offset + PAGE]
        if any(page):
            if extents and extents[-1][0] + len(extents[-1][1]) == offset:
                extents[-1][1].extend(page)
            else:
                extents.append((offset, bytearray(page)))
    result = bytearray(struct.pack('<8sIIQQ', b'DBRDISK1', 1, PAGE, logical, len(extents)))
    for offset, data in extents:
        result.extend(struct.pack('<QQ', offset, len(data)))
    for _, data in extents:
        result.extend(data)
    return bytes(result)


class MuyuDataSeedTest(unittest.TestCase):
    def test_sets_and_verifies_volume_uuid(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / 'seed.raw'
            raw.write_bytes(raw_image())
            MODULE.set_volume_uuid(raw, NEW_UUID)

            image = raw.read_bytes()
            block = 2 * PAGE
            self.assertEqual(image[block + 240:block + 256], NEW_UUID.bytes)
            self.assertEqual(MODULE.fletcher64(image[block + 8:block + PAGE]), image[block:block + 8])

            packed_path = Path(directory) / 'seed.dbr'
            packed_path.write_bytes(packed(image))
            report = MODULE.inspect_packed(packed_path, NEW_UUID)
            self.assertEqual(report['volume_uuid'], str(NEW_UUID).upper())
            self.assertEqual(report['volume_superblocks'], 1)

    def test_rejects_a_different_volume_uuid(self):
        with tempfile.TemporaryDirectory() as directory:
            packed_path = Path(directory) / 'seed.dbr'
            packed_path.write_bytes(packed(raw_image()))
            with self.assertRaises(SystemExit):
                MODULE.inspect_packed(packed_path, NEW_UUID)


if __name__ == '__main__':
    unittest.main()
