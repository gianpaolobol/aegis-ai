# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Offline Cargo archive declaration comparison; never execution or clearance."""
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
                'declaration_comparison': 'exact-match', 'checksum_origin': 'caller-supplied',
                'source_authentication': 'not-performed', 'license_review': 'not-performed',
                'linkage_review': 'not-performed', 'execution_approved': False}
    except (ValueError, TypeError, KeyError, AttributeError, OSError, EOFError,
            tarfile.TarError, zlib.error, RecursionError, OverflowError):
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


def main():
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]])
    if len(sys.argv) != 5 or sys.argv[1] != '--compare':
        print('Use --self-test or --compare PURL SHA256 DATE (.crate bytes on stdin).')
        return 2
    try:
        helper = runpy.run_path(str(Path(__file__).with_name('review_candidate.py')))
        with helper['REPORT'].open('rb') as stream:
            queue = helper['retained_review_queue'](stream.read(helper['MAX_BYTES'] + 1))
        rows = [] if queue is None else [r for r in queue['queue'] if r['declared_purl'] == sys.argv[2]]
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
