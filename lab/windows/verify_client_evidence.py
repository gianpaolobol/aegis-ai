# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
# [Codex] ADE-099: exact-byte offline client evidence binding.
"""Verify supplied byte hashes, not signatures, lab authenticity or release readiness."""
import base64
import hashlib
import json
import runpy
import sys
import unittest
from pathlib import Path

MAX_PACKAGE = 12 * 1024 * 1024
MAX_EVIDENCE = 256 * 1024
MAX_INPUT = 20 * 1024 * 1024
RECORD = runpy.run_path(str(Path(__file__).with_name('validate_client_record.py')))
CHECKS = RECORD['CHECKS']


def decode(value, limit):
    if type(value) is not str or not 1 <= len(value) <= 4 * ((limit + 2) // 3):
        raise ValueError('invalid encoded size')
    raw = base64.b64decode(value, validate=True)
    if not 1 <= len(raw) <= limit or base64.b64encode(raw).decode('ascii') != value:
        raise ValueError('invalid encoded bytes')
    return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def reject_constant(_):
    raise ValueError('invalid constant')


def verify(raw, commit, package):
    if (type(raw) is not bytes or not 1 <= len(raw) <= MAX_INPUT
            or not RECORD['hex_digest'](commit, 40) or not RECORD['hex_digest'](package, 64)):
        return False
    try:
        bundle = json.loads(raw.decode('utf-8'), object_pairs_hook=RECORD['unique'],
                            parse_constant=reject_constant)
        if type(bundle) is not dict or set(bundle) != {'record', 'package_base64', 'evidence_base64'}:
            return False
        record = bundle['record']
        if not RECORD['validate'](json.dumps(record, ensure_ascii=True).encode('ascii'), commit, package):
            return False
        evidence = bundle['evidence_base64']
        if type(evidence) is not dict or set(evidence) != set(CHECKS):
            return False
        if digest(decode(bundle['package_base64'], MAX_PACKAGE)) != package:
            return False
        return all(digest(decode(evidence[key], MAX_EVIDENCE)) == record['checks'][key]['evidence_sha256']
                   for key in CHECKS)
    except (ValueError, TypeError, RecursionError, OverflowError):
        return False


def report(matched):
    return {'supplied_bytes_match': matched, 'evidence_authenticated': False,
            'signature_verified': False, 'installation_verified': False, 'release_approved': False}


class Fixtures(unittest.TestCase):
    commit = 'a' * 40
    package = b'synthetic package bytes, not an executable'

    def bundle(self):
        evidence = {key: ('synthetic check ' + key).encode('ascii') for key in CHECKS}
        def encode(raw):
            return base64.b64encode(raw).decode('ascii')
        return {'record': {'schema': 'aegis-client-lab-v1', 'commit': self.commit,
                           'package_sha256': digest(self.package), 'environment': 'disposable-windows-client-x64',
                           'checks': {key: {'status': 'pass', 'evidence_sha256': digest(value)}
                                      for key, value in evidence.items()}},
                'package_base64': encode(self.package),
                'evidence_base64': {key: encode(value) for key, value in evidence.items()}}

    def check(self, bundle):
        return verify(json.dumps(bundle).encode(), self.commit, digest(self.package))

    def test_matching_bytes_only(self):
        self.assertTrue(self.check(self.bundle()))
        self.assertEqual(report(True), {'supplied_bytes_match': True, 'evidence_authenticated': False,
                                       'signature_verified': False, 'installation_verified': False,
                                       'release_approved': False})

    def test_each_evidence_must_match(self):
        for key in CHECKS:
            bundle = self.bundle()
            bundle['evidence_base64'][key] = 'eA=='
            self.assertFalse(self.check(bundle))
            del bundle['evidence_base64'][key]
            self.assertFalse(self.check(bundle))

    def test_package_and_independent_binding(self):
        bundle = self.bundle()
        self.assertFalse(verify(json.dumps(bundle).encode(), 'b' * 40, digest(self.package)))
        self.assertFalse(verify(json.dumps(bundle).encode(), self.commit, 'b' * 64))
        bundle['package_base64'] = 'eA=='
        self.assertFalse(self.check(bundle))

    def test_record_and_extra_evidence(self):
        bundle = self.bundle()
        bundle['record']['checks'][CHECKS[0]]['status'] = 'fail'
        self.assertFalse(self.check(bundle))
        bundle = self.bundle()
        bundle['evidence_base64']['extra'] = 'eA=='
        self.assertFalse(self.check(bundle))
        self.assertFalse(self.check(dict(self.bundle(), approval=True)))

    def test_malformed_and_noncanonical(self):
        for value in ('', '!', 'eB==', 'eA==\n', None, 7):
            bundle = self.bundle()
            bundle['evidence_base64'][CHECKS[0]] = value
            self.assertFalse(self.check(bundle))
        for raw in (b'[]', b'\xff', b'{"record":1,"record":2}', b'{"record":NaN}'):
            self.assertFalse(verify(raw, self.commit, digest(self.package)))

    def test_size_boundaries(self):
        for size in (MAX_EVIDENCE, MAX_EVIDENCE + 1):
            data = b'x' * size
            bundle = self.bundle()
            bundle['evidence_base64'][CHECKS[0]] = base64.b64encode(data).decode('ascii')
            bundle['record']['checks'][CHECKS[0]]['evidence_sha256'] = digest(data)
            self.assertEqual(self.check(bundle), size == MAX_EVIDENCE)
        self.assertFalse(verify(b'x' * (MAX_INPUT + 1), self.commit, digest(self.package)))
        with self.assertRaises(ValueError):
            decode('eA==', 0)


def main():
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]])
    if len(sys.argv) != 3:
        print('Use --self-test or COMMIT PACKAGE_SHA256 with bounded JSON stdin.')
        return 2
    matched = verify(sys.stdin.buffer.read(MAX_INPUT + 1), sys.argv[1], sys.argv[2])
    print(json.dumps(report(matched)))
    return 0 if matched else 1


if __name__ == '__main__':
    sys.exit(main())
