#!/usr/bin/env python3
"""Set or verify the APFS volume UUID in a Muyu Data seed candidate."""

import argparse
import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path

PAGE = 4096
APFS_VOLUME_UUID_OFFSET = 240


def fletcher64(data):
    data = memoryview(data)
    if len(data) % 4:
        raise ValueError('Fletcher64 input is not word aligned')
    lo = hi = 0
    for (word,) in struct.iter_unpack('<I', data):
        lo = (lo + word) % 0xFFFFFFFF
        hi = (hi + lo) % 0xFFFFFFFF
    c0 = 0xFFFFFFFF - ((lo + hi) % 0xFFFFFFFF)
    c1 = 0xFFFFFFFF - ((lo + c0) % 0xFFFFFFFF)
    return struct.pack('<II', c0, c1)


def set_volume_uuid(raw_path, expected):
    data = bytearray(raw_path.read_bytes())
    if len(data) < PAGE or data[32:36] != b'NXSB':
        raise SystemExit(f'{raw_path}: no APFS container superblock')
    block_size = struct.unpack_from('<I', data, 36)[0]
    if block_size != PAGE:
        raise SystemExit(f'{raw_path}: block size is {block_size}, expected {PAGE}')

    old_uuids = set()
    changed = 0
    for block in range(0, len(data) - block_size + 1, block_size):
        if data[block + 32:block + 36] != b'APSB':
            continue
        if fletcher64(data[block + 8:block + block_size]) != data[block:block + 8]:
            raise SystemExit(f'{raw_path}: invalid APFS volume superblock checksum at {block}')
        old_uuids.add(bytes(data[block + APFS_VOLUME_UUID_OFFSET:block + APFS_VOLUME_UUID_OFFSET + 16]))
        data[block + APFS_VOLUME_UUID_OFFSET:block + APFS_VOLUME_UUID_OFFSET + 16] = expected.bytes
        data[block:block + 8] = fletcher64(data[block + 8:block + block_size])
        changed += 1

    if len(old_uuids) != 1:
        raise SystemExit(f'{raw_path}: expected one volume UUID, found {len(old_uuids)}')
    if changed == 0:
        raise SystemExit(f'{raw_path}: no APFS volume superblock found')
    with raw_path.open('r+b') as stream:
        stream.write(data)
        stream.flush()
    print(json.dumps({
        'old_volume_uuid': str(uuid.UUID(bytes=next(iter(old_uuids)))).upper(),
        'volume_uuid': str(expected).upper(),
        'superblocks_updated': changed,
    }, indent=2))


def inspect_packed(packed_path, expected):
    blob = packed_path.read_bytes()
    if len(blob) < 32 or blob[:8] != b'DBRDISK1':
        raise SystemExit(f'{packed_path}: not a packed DBRDISK1 image')
    magic, version, page, logical, count = struct.unpack_from('<8sIIQQ', blob)
    if magic != b'DBRDISK1' or version != 1 or page != PAGE or not logical or logical % PAGE:
        raise SystemExit(f'{packed_path}: invalid packed header')
    if count > 65536 or count > (len(blob) - 32) // 16:
        raise SystemExit(f'{packed_path}: invalid extent count')

    cursor = 32 + 16 * count
    end = 0
    extents = []
    for _ in range(count):
        offset, length = struct.unpack_from('<QQ', blob, 32 + 16 * len(extents))
        if (not length or (offset | length) % PAGE or offset < end or
                offset > logical or length > logical - offset or length > len(blob) - cursor):
            raise SystemExit(f'{packed_path}: invalid packed extent')
        extents.append((offset, memoryview(blob)[cursor:cursor + length]))
        cursor += length
        end = offset + length
    if cursor != len(blob):
        raise SystemExit(f'{packed_path}: trailing packed bytes')

    container = None
    if extents and extents[0][0] == 0 and len(extents[0][1]) >= PAGE:
        first = extents[0][1][:PAGE]
        if first[32:36] != b'NXSB':
            raise SystemExit(f'{packed_path}: logical disk does not start with APFS NXSB')
        container = {
            'block_size': struct.unpack_from('<I', first, 36)[0],
            'container_uuid': str(uuid.UUID(bytes=bytes(first[72:88]))).upper(),
        }
        if container['block_size'] != PAGE:
            raise SystemExit(f'{packed_path}: unexpected APFS block size')

    volume_uuids = set()
    superblocks = 0
    for extent_offset, data in extents:
        for at in range(0, len(data) - PAGE + 1, PAGE):
            block = data[at:at + PAGE]
            if block[32:36] != b'APSB':
                continue
            if fletcher64(block[8:]) != block[:8]:
                raise SystemExit(f'{packed_path}: invalid APFS volume checksum at {extent_offset + at}')
            volume_uuids.add(bytes(block[APFS_VOLUME_UUID_OFFSET:APFS_VOLUME_UUID_OFFSET + 16]))
            superblocks += 1

    expected_bytes = expected.bytes
    if volume_uuids != {expected_bytes}:
        found = ', '.join(str(uuid.UUID(bytes=value)).upper() for value in sorted(volume_uuids)) or 'none'
        raise SystemExit(f'{packed_path}: expected volume UUID {str(expected).upper()}, found {found}')

    return {
        'logical_bytes': logical,
        'logical_gib': logical / 1024**3,
        'packed_bytes': len(blob),
        'packed_sha256': hashlib.sha256(blob).hexdigest(),
        'extents': count,
        'volume_uuid': str(expected).upper(),
        'volume_superblocks': superblocks,
        'container': container,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)

    setter = commands.add_parser('set-uuid')
    setter.add_argument('raw', type=Path)
    setter.add_argument('uuid', type=uuid.UUID)

    inspector = commands.add_parser('inspect-packed')
    inspector.add_argument('packed', type=Path)
    inspector.add_argument('--uuid', type=uuid.UUID, required=True)
    inspector.add_argument('--json', type=Path)
    args = parser.parse_args()

    if args.command == 'set-uuid':
        set_volume_uuid(args.raw, args.uuid)
        return

    result = inspect_packed(args.packed, args.uuid)
    text = json.dumps(result, indent=2) + '\n'
    if args.json:
        args.json.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(str(error))
