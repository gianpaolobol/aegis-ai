# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Optional YARA-X integration rehearsal. Fixed harmless inputs only."""
import importlib.metadata
import sys
import unittest
from types import SimpleNamespace

VERSION = '1.24.0'
RULE_ID = 'aegis_fixture_marker'
RULE = '''rule aegis_fixture_marker {
    strings:
        $marker = "AEGIS_SYNTHETIC_MARKER_2026"
    condition:
        $marker
}'''
MAX_BYTES = 65536
CASES = ((b'AEGIS_SYNTHETIC_MARKER_2026', 'FixtureMatch'),
         (b'ordinary synthetic text', 'NoFixtureMatch'),
         (b'', 'NoFixtureMatch'))


def evaluate(engine, data):
    if type(data) is not bytes or len(data) > MAX_BYTES:
        return 'InvalidInput'
    try:
        rules = engine.compile(RULE)
        if rules.imports():
            return 'Unavailable'
        scanner = engine.Scanner(rules)
        scanner.set_timeout(2)
        scanner.max_matches_per_pattern(1)
        result = scanner.scan(data)
        ids = tuple(rule.identifier for rule in result.matching_rules)
        if ids == (RULE_ID,):
            return 'FixtureMatch'
        if ids == ():
            return 'NoFixtureMatch'
        return 'Unavailable'
    except Exception:
        return 'Unavailable'


def real_rehearsal():
    # The operator must provision an independently reviewed, hash-pinned wheel
    # in an isolated offline environment first. This script never installs it.
    try:
        if importlib.metadata.version('yara-x') != VERSION:
            raise ValueError('version mismatch')
        import yara_x
    except Exception:
        print('Engine unavailable or version not approved for this rehearsal.')
        return 2
    for payload, expected in CASES:
        if evaluate(yara_x, payload) != expected:
            print('Engine fixture rehearsal failed.')
            return 1
    print('PASS: three harmless YARA-X fixtures; not malware detection validation.')
    return 0


class AdapterTests(unittest.TestCase):
    def engine(self, ids=(), imports=(), fail=False):
        self.calls = []
        calls = self.calls
        class Scanner:
            def __init__(self, rules):
                calls.append('scanner')
            def set_timeout(self, seconds):
                calls.append(('timeout', seconds))
            def max_matches_per_pattern(self, limit):
                calls.append(('limit', limit))
            def scan(self, data):
                calls.append('scan')
                if fail:
                    raise TimeoutError('SYNTHETIC_PRIVATE')
                return SimpleNamespace(matching_rules=[SimpleNamespace(identifier=i) for i in ids])
        def compile_rule(source):
            calls.append('compile')
            if source != RULE:
                raise ValueError('unexpected rule')
            return SimpleNamespace(imports=lambda: imports)
        return SimpleNamespace(compile=compile_rule, Scanner=Scanner)

    def test_match_and_limits(self):
        self.assertEqual(evaluate(self.engine((RULE_ID,)), CASES[0][0]), 'FixtureMatch')
        self.assertEqual(self.calls, ['compile','scanner',('timeout',2),('limit',1),'scan'])

    def test_no_match_not_clean(self):
        self.assertEqual(evaluate(self.engine(), b''), 'NoFixtureMatch')

    def test_invalid_input_no_engine(self):
        for data in ('text', bytearray(b'x'), b'x' * (MAX_BYTES + 1)):
            self.assertEqual(evaluate(self.engine(), data), 'InvalidInput')
            self.assertEqual(self.calls, [])

    def test_boundary(self):
        self.assertEqual(evaluate(self.engine(), b'x' * MAX_BYTES), 'NoFixtureMatch')

    def test_unexpected_or_duplicate_rule(self):
        for ids in (('unknown',), (RULE_ID, RULE_ID)):
            self.assertEqual(evaluate(self.engine(ids), b'x'), 'Unavailable')

    def test_imports_blocked(self):
        self.assertEqual(evaluate(self.engine(imports=('pe',)), b'x'), 'Unavailable')
        self.assertEqual(self.calls, ['compile'])

    def test_timeout_no_disclosure(self):
        self.assertEqual(evaluate(self.engine(fail=True), b'x'), 'Unavailable')

    def test_compile_failure(self):
        self.assertEqual(evaluate(None, b'x'), 'Unavailable')


if __name__ == '__main__':
    if sys.argv[1:] == ['--mock-tests']:
        unittest.main(argv=[sys.argv[0]])
    elif sys.argv[1:] == ['--engine-self-test']:
        sys.exit(real_rehearsal())
    else:
        print('Use --mock-tests or --engine-self-test in an authorized offline lab.')
        sys.exit(2)
