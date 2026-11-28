# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
# [Codex] ADE-098: offline Windows client lab record consistency check.
"""Validate record shape and exact candidate binding, never attest a lab run."""
import json
import re
import sys
import unittest

MAX_BYTES = 16384
CHECKS = tuple('WIN-LAB-%02d' % i for i in range(1, 8))
FIELDS = {'schema', 'commit', 'package_sha256', 'environment', 'checks'}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def hex_digest(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % size, value) is not None


def validate(raw, commit, package):
    if (type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES
            or not hex_digest(commit, 40) or not hex_digest(package, 64)):
        return False
    try:
        record = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
        if type(record) is not dict or set(record) != FIELDS:
            return False
        if (record['schema'] != 'aegis-client-lab-v1' or record['commit'] != commit
                or record['package_sha256'] != package
                or record['environment'] != 'disposable-windows-client-x64'):
            return False
        checks = record['checks']
        if type(checks) is not dict or set(checks) != set(CHECKS):
            return False
        for entry in checks.values():
            if (type(entry) is not dict or set(entry) != {'status', 'evidence_sha256'}
                    or entry['status'] != 'pass' or not hex_digest(entry['evidence_sha256'], 64)):
                return False
        return True
    except (ValueError, TypeError, RecursionError):
        return False


class Fixtures(unittest.TestCase):
    commit = 'a' * 40
    package = 'b' * 64

    def record(self):
        return {'schema': 'aegis-client-lab-v1', 'commit': self.commit,
                'package_sha256': self.package, 'environment': 'disposable-windows-client-x64',
                'checks': {key: {'status': 'pass', 'evidence_sha256': 'c' * 64} for key in CHECKS}}

    def check(self, record):
        return validate(json.dumps(record).encode(), self.commit, self.package)

    def test_complete_fixture(self):
        self.assertTrue(self.check(self.record()))

    def test_candidate_binding(self):
        for key, value in [('commit', 'd' * 40), ('package_sha256', 'd' * 64),
                           ('environment', 'github-hosted-runner')]:
            self.assertFalse(self.check(dict(self.record(), **{key: value})))

    def test_missing_and_failed_checks(self):
        for key in CHECKS:
            record = self.record()
            del record['checks'][key]
            self.assertFalse(self.check(record))
            for status in ('fail', 'skipped', 'unknown', True):
                record = self.record()
                record['checks'][key]['status'] = status
                self.assertFalse(self.check(record))

    def test_bad_evidence(self):
        for digest in (None, 1, 'c' * 63, 'G' * 64):
            record = self.record()
            record['checks'][CHECKS[0]]['evidence_sha256'] = digest
            self.assertFalse(self.check(record))

    def test_duplicate_extra_and_bounds(self):
        for raw in (b'{"schema":1,"schema":2}', b'x' * (MAX_BYTES + 1), b'\xff', b'[]'):
            self.assertFalse(validate(raw, self.commit, self.package))
        self.assertFalse(self.check(dict(self.record(), approval=True)))
        record = self.record()
        record['checks']['other'] = record['checks'][CHECKS[0]]
        self.assertFalse(self.check(record))


def main():
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]])
    if len(sys.argv) != 3:
        print('Use --self-test or COMMIT PACKAGE_SHA256 with JSON on stdin.')
        return 2
    consistent = validate(sys.stdin.buffer.read(MAX_BYTES + 1), sys.argv[1], sys.argv[2])
    print(json.dumps({'record_consistent': consistent, 'evidence_authenticated': False,
                      'installation_verified': False, 'release_approved': False}))
    return 0 if consistent else 1


if __name__ == '__main__':
    sys.exit(main())
