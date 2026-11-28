# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Offline advisory for aggregate Defender event metadata; no native actions."""
import json
import sys
import unittest

IDS = ('1116', '1117', '1118', '1119', '5001', '5013')
MAX_BYTES = 2048


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate key')
        out[key] = value
    return out


def triage(raw):
    result = {'schema': 'aegis-edr-advisory-v1', 'priority': 'unknown',
              'reasons': [], 'coverage': 'unknown', 'action_authorized': False,
              'remediation_verified': False, 'absence_of_compromise_verified': False}
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
            return result
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
        if type(obj) is not dict or set(obj) != {'window_hours', 'coverage', 'counts'}:
            return result
        if type(obj['window_hours']) is not int or obj['window_hours'] != 24:
            return result
        coverage, counts = obj['coverage'], obj['counts']
        if coverage not in ('query-exhausted', 'limited') or type(counts) is not dict or set(counts) != set(IDS):
            return result
        if any(type(n) is not int or not 0 <= n <= 256 for n in counts.values()):
            return result
        total = sum(counts.values())
        if total > 256 or (coverage == 'limited' and total != 256):
            return result
        reasons = [label for key, label in (
            ('1119', 'critical-action-failure-record'), ('5001', 'real-time-disabled-record'),
            ('1118', 'action-failure-record'), ('1116', 'detection-record'),
            ('5013', 'tamper-block-record'), ('1117', 'action-record')) if counts[key]]
        priority = ('urgent-review' if counts['1119'] or counts['5001'] else
                    'review' if reasons or coverage == 'limited' else 'no-selected-records')
        result.update(priority=priority, reasons=reasons, coverage=coverage)
        return result
    except (ValueError, TypeError, RecursionError, OverflowError):
        return result


class Fixtures(unittest.TestCase):
    def fixture(self, coverage='query-exhausted', **counts):
        return json.dumps({'window_hours': 24, 'coverage': coverage,
                           'counts': dict.fromkeys(IDS, 0) | counts}).encode()

    def test_empty_not_safe(self):
        r = triage(self.fixture())
        self.assertEqual(r['priority'], 'no-selected-records')
        self.assertFalse(r['absence_of_compromise_verified'])

    def test_detection_and_action_not_remediation(self):
        r = triage(self.fixture(**{'1116': 1, '1117': 1}))
        self.assertEqual(r['priority'], 'review')
        self.assertFalse(r['remediation_verified'])
        self.assertFalse(r['action_authorized'])

    def test_urgent_precedes_other_records(self):
        for key in ('1119', '5001'):
            r = triage(self.fixture(**{key: 1, '1117': 1}))
            self.assertEqual(r['priority'], 'urgent-review')
            self.assertFalse(r['action_authorized'])

    def test_bounds(self):
        self.assertEqual(triage(self.fixture('limited', **{'1117': 256}))['priority'], 'review')
        for raw in (self.fixture('limited', **{'1117': 255}), self.fixture(**{'1117': 256, '1116': 1}), self.fixture(**{'1117': -1})):
            self.assertEqual(triage(raw)['priority'], 'unknown')

    def test_invalid_types_and_unknown_keys(self):
        for value in (True, '1', 1.0, None):
            self.assertEqual(triage(self.fixture(**{'1116': value}))['priority'], 'unknown')
        self.assertEqual(triage(self.fixture(**{'9999': 1}))['priority'], 'unknown')

    def test_bad_input_no_disclosure(self):
        for raw in (b'', b'x' * (MAX_BYTES + 1), b'\xff', b'{"counts":{},"counts":{}}', b'{"secret":"SYNTHETIC-PRIVATE"}', self.fixture('unknown')):
            r = triage(raw)
            self.assertEqual(r['priority'], 'unknown')
            self.assertNotIn('SYNTHETIC-PRIVATE', str(r))


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]])
    elif not sys.argv[1:]:
        report = triage(sys.stdin.buffer.read(MAX_BYTES + 1))
        print(json.dumps(report, sort_keys=True))
        sys.exit(1 if report['priority'] == 'unknown' else 0)
    else:
        sys.exit(2)
