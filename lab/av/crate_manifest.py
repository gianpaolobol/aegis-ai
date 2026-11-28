# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Offline Cargo archive declaration comparison; never execution or clearance."""
import base64
import binascii
import gzip
import hashlib
import io
import json
import re
import runpy
import sys
import tarfile
import tomllib
import unittest
import zlib
from datetime import date
from pathlib import Path

MAX_ARCHIVE = 8 * 1024 * 1024
MAX_EXPANDED = 16 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_MANIFEST = 64 * 1024
MAX_NOTICE_BYTES = 256 * 1024
MAX_NOTICE_FILES = 32
NOTICE_NAME = re.compile(r'(?:LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)(?:[._-][A-Za-z0-9._-]{1,100})?', re.ASCII | re.IGNORECASE)
MAX_BATCH_BYTES = 16 * 1024 * 1024
MAX_BATCH_ARCHIVES = 32
MAX_BATCH_COMPRESSED = 12 * 1024 * 1024


def compare(row, raw, expected_sha256, observed_date):
    """Caller-supplied checksum is not a trusted registry signature.
    Never extracts to disk, invokes Cargo, imports archive code or accesses network.
    Narrow archive profile: unsupported members are rejected, not ignored.
    """
    try:
        name, version = row['name'], row['version']
        purl = row['declared_purl']
        if (row['source_identity_scope'] != 'unqualified-cargo'
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', name)
                or not re.fullmatch(r'[0-9A-Za-z.+-]{1,128}', version)
                or purl != 'pkg:cargo/' + name + '@' + version
                or date.fromisoformat(observed_date).isoformat() != observed_date
                or type(raw) is not bytes or not 1 <= len(raw) <= MAX_ARCHIVE
                or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256)
                or hashlib.sha256(raw).hexdigest() != expected_sha256):
            return None
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            expanded = stream.read(MAX_EXPANDED + 1)
        if not 1 <= len(expanded) <= MAX_EXPANDED:
            return None
        root = name + '-' + version
        seen, manifest = set(), None
        notices = []
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
            for member in archive:
                path = member.name
                parts = path.split('/')
                if (len(seen) >= MAX_ENTRIES or path in seen or len(path) > 1024
                        or parts[0] != root or any(p in ('', '.', '..') for p in parts)
                        or '\\' in path or any(ord(c) < 32 for c in path)
                        or not (member.isfile() or member.isdir()) or member.issparse()
                        or member.size < 0 or (member.isdir() and member.size != 0)
                        or (path == root and not member.isdir())):
                    return None
                seen.add(path)
                if path == root + '/Cargo.toml':
                    if not member.isfile() or not 1 <= member.size <= MAX_MANIFEST:
                        return None
                    with archive.extractfile(member) as stream:
                        manifest = stream.read(MAX_MANIFEST + 1)
                    if len(manifest) != member.size:
                        return None
                # Narrow root-level notice candidate inventory, not a license parser.
                elif len(parts) == 2 and NOTICE_NAME.fullmatch(parts[1]) and member.isfile():
                    if len(notices) >= MAX_NOTICE_FILES or not 1 <= member.size <= MAX_NOTICE_BYTES:
                        return None
                    with archive.extractfile(member) as stream:
                        notice = stream.read(MAX_NOTICE_BYTES + 1)
                    if len(notice) != member.size:
                        return None
                    notices.append({'name': parts[1], 'size': len(notice),
                                    'sha256': hashlib.sha256(notice).hexdigest()})
            # Reject a missing terminator or hidden nonzero data after the logical archive.
            tail = expanded[archive.offset:]
            if len(tail) < 1024 or any(tail):
                return None
        if manifest is None:
            return None
        package = tomllib.loads(manifest.decode('utf-8')).get('package')
        if (type(package) is not dict or package.get('name') != name
                or package.get('version') != version or 'license-file' in package
                or type(package.get('license')) is not str
                or row['declared_licenses'] != ['expression:' + package['license']]):
            return None
        return {'schema': 'aegis-local-crate-comparison-v1', 'declared_purl': purl,
                'observed_date': observed_date, 'archive_sha256': expected_sha256,
                'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
                'root_notice_candidates': sorted(notices, key=lambda item: item['name']),
                'notice_inventory_scope': 'root-filename-pattern-only',
                'notice_review': 'not-performed',
                'declaration_comparison': 'exact-match', 'checksum_origin': 'caller-supplied',
                'source_authentication': 'not-performed', 'license_review': 'not-performed',
                'linkage_review': 'not-performed', 'execution_approved': False}
    except (ValueError, TypeError, KeyError, AttributeError, OSError, EOFError,
            tarfile.TarError, zlib.error, RecursionError, OverflowError):
        return None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def compare_batch(queue, raw):
    """Atomic advisory comparison of supplied archives, never evidence promotion.
    JSON stdin only; no paths, network, extraction, subprocess or new trust.
    Bound input, row count, per-archive and cumulative compressed bytes.
    """
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BATCH_BYTES:
        return None
    try:
        items = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
        if type(items) is not list or not 1 <= len(items) <= MAX_BATCH_ARCHIVES:
            return None
        rows = {row['declared_purl']: row for row in queue}
        if len(rows) != len(queue):
            return None
        seen, matched, total = set(), [], 0
        for item in items:
            if type(item) is not dict or set(item) != {
                    'declared_purl', 'archive_sha256', 'observed_date', 'archive_base64'}:
                return None
            purl, digest, observed, encoded = (item[k] for k in
                ('declared_purl', 'archive_sha256', 'observed_date', 'archive_base64'))
            if not all(type(v) is str for v in (purl, digest, observed, encoded)):
                return None
            if (not 1 <= len(purl) <= 512 or len(digest) != 64 or len(observed) != 10
                    or not 1 <= len(encoded) <= 4 * ((MAX_ARCHIVE + 2) // 3)
                    or purl in seen or purl not in rows):
                return None
            archive = base64.b64decode(encoded, validate=True)
            if not 1 <= len(archive) <= MAX_ARCHIVE:
                return None
            total += len(archive)
            if total > MAX_BATCH_COMPRESSED:
                return None
            result = compare(rows[purl], archive, digest, observed)
            if result is None:
                return None
            matched.append(result)
            seen.add(purl)
        return {'schema': 'aegis-local-crate-batch-v1', 'matched': len(matched),
                'observations': sorted(matched, key=lambda row: row['declared_purl']),
                'checksum_origin': 'caller-supplied', 'source_authentication': 'not-performed',
                'license_review': 'not-performed', 'linkage_review': 'not-performed',
                'execution_approved': False}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, binascii.Error):
        return None


class Fixtures(unittest.TestCase):
    row = {'name': 'fixture', 'version': '1.0.0', 'declared_purl': 'pkg:cargo/fixture@1.0.0',
           'source_identity_scope': 'unqualified-cargo', 'declared_licenses': ['expression:MIT']}
    manifest = b'[package]\nname="fixture"\nversion="1.0.0"\nlicense="MIT"\n'
    path = 'fixture-1.0.0/Cargo.toml'

    def archive(self, entries):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for path, payload, kind in entries:
                info = tarfile.TarInfo(path)
                info.type = kind
                info.size = len(payload)
                if kind == tarfile.SYMTYPE:
                    info.linkname = 'other'
                tar.addfile(info, io.BytesIO(payload))
        return buf.getvalue()

    def check(self, raw, row=None):
        return compare(self.row if row is None else row, raw,
                       hashlib.sha256(raw).hexdigest(), '2026-11-28')

    def test_match_does_not_clear(self):
        result = self.check(self.archive([(self.path, self.manifest, tarfile.REGTYPE)]))
        self.assertEqual(result['manifest_sha256'], hashlib.sha256(self.manifest).hexdigest())
        self.assertFalse(result['execution_approved'])
        self.assertEqual(result['source_authentication'], 'not-performed')
        self.assertEqual(result['license_review'], 'not-performed')

    def test_identity_license_and_digest(self):
        for old, new in [(b'fixture', b'other'), (b'1.0.0', b'2.0.0'),
                         (b'MIT', b'Apache-2.0')]:
            self.assertIsNone(self.check(self.archive([(self.path, self.manifest.replace(old, new), tarfile.REGTYPE)])))
        raw = self.archive([(self.path, self.manifest, tarfile.REGTYPE)])
        self.assertIsNone(compare(self.row, raw, '0' * 64, '2026-11-28'))
        self.assertIsNone(compare(self.row, raw, hashlib.sha256(raw).hexdigest(), '2026-02-30'))
        self.assertIsNone(self.check(raw, dict(self.row, source_identity_scope='workspace-qualified')))

    def test_unsafe_and_duplicate_entries(self):
        valid = (self.path, self.manifest, tarfile.REGTYPE)
        for extra in [valid, ('fixture-1.0.0/../other', b'x', tarfile.REGTYPE),
                      ('/other', b'x', tarfile.REGTYPE),
                      ('fixture-1.0.0/link', b'', tarfile.SYMTYPE),
                      ('fixture-1.0.0/pipe', b'', tarfile.FIFOTYPE)]:
            self.assertIsNone(self.check(self.archive([valid, extra])))

    def test_truncated_or_trailing_archive(self):
        raw = self.archive([(self.path, self.manifest, tarfile.REGTYPE)])
        expanded = gzip.decompress(raw)
        self.assertIsNone(self.check(gzip.compress(expanded[:1024])))
        self.assertIsNone(self.check(gzip.compress(expanded + b"hidden")))
        self.assertIsNone(self.check(raw[:-1]))

    def test_missing_invalid_and_bounds(self):
        self.assertIsNone(self.check(self.archive([])))
        self.assertIsNone(self.check(b'not gzip'))
        self.assertIsNone(self.check(self.archive([(self.path, b'x' * (MAX_MANIFEST + 1), tarfile.REGTYPE)])))
        self.assertIsNone(self.check(gzip.compress(b'x' * (MAX_EXPANDED + 1))))
        self.assertIsNone(self.check(b'x' * (MAX_ARCHIVE + 1)))


    def test_root_notice_inventory_is_partial(self):
        valid = (self.path, self.manifest, tarfile.REGTYPE)
        a = ('fixture-1.0.0/LICENSE-MIT', b'synthetic MIT notice', tarfile.REGTYPE)
        b = ('fixture-1.0.0/NOTICE.txt', b'synthetic notice', tarfile.REGTYPE)
        nested = ('fixture-1.0.0/vendor/LICENSE', b'nested synthetic', tarfile.REGTYPE)
        result = self.check(self.archive([valid, b, nested, a]))
        self.assertEqual(result['root_notice_candidates'], [
            {'name': 'LICENSE-MIT', 'size': len(a[1]), 'sha256': hashlib.sha256(a[1]).hexdigest()},
            {'name': 'NOTICE.txt', 'size': len(b[1]), 'sha256': hashlib.sha256(b[1]).hexdigest()}])
        self.assertEqual(result['root_notice_candidates'],
                         self.check(self.archive([a, valid, b]))['root_notice_candidates'])
        self.assertEqual(result['notice_inventory_scope'], 'root-filename-pattern-only')
        self.assertEqual(result['notice_review'], 'not-performed')
        self.assertFalse(result['execution_approved'])
        self.assertEqual(self.check(self.archive([valid]))['root_notice_candidates'], [])

    def test_notice_limits_and_no_partial_result(self):
        valid = (self.path, self.manifest, tarfile.REGTYPE)
        for payload in (b'', b'x' * (MAX_NOTICE_BYTES + 1)):
            self.assertIsNone(self.check(self.archive([valid, ('fixture-1.0.0/LICENSE', payload, tarfile.REGTYPE)])))
        entries = [('fixture-1.0.0/NOTICE-' + str(i), b'x', tarfile.REGTYPE)
                   for i in range(MAX_NOTICE_FILES + 1)]
        self.assertIsNone(self.check(self.archive([valid] + entries)))
        self.assertEqual(len(self.check(self.archive([valid] + entries[:-1]))['root_notice_candidates']),
                         MAX_NOTICE_FILES)

    def batch_fixture(self):
        second = dict(self.row, name='fixture-two', declared_purl='pkg:cargo/fixture-two@1.0.0')
        def item(row):
            name = row['name']
            path = name + '-1.0.0/Cargo.toml'
            manifest = self.manifest.replace(b'fixture', name.encode('ascii'))
            archive = self.archive([(path, manifest, tarfile.REGTYPE)])
            return {'declared_purl': row['declared_purl'],
                    'archive_sha256': hashlib.sha256(archive).hexdigest(),
                    'observed_date': '2026-11-28',
                    'archive_base64': base64.b64encode(archive).decode('ascii')}
        return [self.row, second], item(self.row), item(second)

    def test_batch_stable_and_advisory(self):
        queue, a, b = self.batch_fixture()
        def check(items):
            return compare_batch(queue, json.dumps(items).encode())
        result = check([b, a])
        self.assertEqual(result, check([a, b]))
        self.assertEqual(result['matched'], 2)
        self.assertFalse(result['execution_approved'])
        self.assertEqual(result['license_review'], 'not-performed')
        self.assertTrue(all(not x['execution_approved'] for x in result['observations']))

    def test_batch_atomic_rejection(self):
        queue, a, b = self.batch_fixture()
        for bad in (a, dict(b, archive_sha256='0' * 64),
                    dict(b, archive_base64='!'), dict(b, observed_date='2026-02-30'),
                    dict(b, declared_purl='pkg:cargo/unknown@1.0.0'),
                    dict(b, observed_date=None), dict(b, extra=True)):
            self.assertIsNone(compare_batch(queue, json.dumps([a, bad]).encode()))
        self.assertIsNone(compare_batch(queue, b'[{"declared_purl":"a","declared_purl":"b"}]'))
        self.assertIsNone(compare_batch(queue + [self.row], json.dumps([a]).encode()))

    def test_batch_limits(self):
        queue, a, b = self.batch_fixture()
        self.assertIsNone(compare_batch(queue, b'[]'))
        self.assertIsNone(compare_batch(queue, json.dumps([a] * (MAX_BATCH_ARCHIVES + 1)).encode()))
        self.assertIsNone(compare_batch(queue, b'x' * (MAX_BATCH_BYTES + 1)))
        from unittest.mock import patch
        with patch(__name__ + '.MAX_BATCH_COMPRESSED', len(base64.b64decode(a['archive_base64']))):
            self.assertIsNotNone(compare_batch(queue, json.dumps([a]).encode()))
            self.assertIsNone(compare_batch(queue, json.dumps([a, b]).encode()))


def main():
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]])
    batch = sys.argv[1:] == ['--compare-batch']
    if not batch and (len(sys.argv) != 5 or sys.argv[1] != '--compare'):
        print('Use --self-test, --compare PURL SHA256 DATE (.crate bytes on stdin), or --compare-batch (JSON stdin).')
        return 2
    try:
        helper = runpy.run_path(str(Path(__file__).with_name('review_candidate.py')))
        with helper['REPORT'].open('rb') as stream:
            queue = helper['retained_review_queue'](stream.read(helper['MAX_BYTES'] + 1))
        if queue is None:
            result = None
        elif batch:
            result = compare_batch(queue['queue'], sys.stdin.buffer.read(MAX_BATCH_BYTES + 1))
        else:
            rows = [r for r in queue['queue'] if r['declared_purl'] == sys.argv[2]]
            result = compare(rows[0], sys.stdin.buffer.read(MAX_ARCHIVE + 1), sys.argv[3], sys.argv[4]) if len(rows) == 1 else None
    except (OSError, ValueError, KeyError):
        result = None
    if result is None:
        print('Local archive comparison unavailable or inconsistent.')
        return 1
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
