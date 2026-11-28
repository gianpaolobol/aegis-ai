# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""V0.2 synthetic endpoint evidence fusion, advisory only; no OS access."""
import json
import unittest
from edr_triage import IDS, triage, unique

MAX_BYTES = 4096


def correlate(raw):
    report = {'schema': 'aegis-endpoint-fusion-v1', 'priority': 'unknown',
              'coverage': 'unknown', 'reasons': [], 'action_authorized': False,
              'remediation_verified': False, 'absence_of_compromise_verified': False}
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
            return report
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
        if type(obj) is not dict or set(obj) != {'events', 'realtime', 'signatures'}:
            return report
        realtime, signatures = obj['realtime'], obj['signatures']
        if realtime not in ('enabled', 'disabled', 'unknown') or signatures not in ('current', 'stale', 'unknown'):
            return report
        events = triage(json.dumps(obj['events']).encode())
        reasons = list(events['reasons'])
        if realtime == 'disabled':
            reasons.append('realtime-reported-disabled')
        if signatures == 'stale':
            reasons.append('signatures-reported-stale')
        if realtime == 'unknown':
            reasons.append('realtime-unavailable')
        if signatures == 'unknown':
            reasons.append('signature-status-unavailable')
        if events['coverage'] == 'unknown':
            reasons.append('event-source-unavailable')
        elif events['coverage'] == 'limited':
            reasons.append('event-sample-limited')
        complete = (events['coverage'] == 'query-exhausted' and
                    realtime != 'unknown' and signatures != 'unknown')
        if realtime == 'disabled' or events['priority'] == 'urgent-review':
            priority = 'urgent-review'
        elif reasons:
            priority = 'review'
        else:
            priority = 'no-selected-indicators'
        report.update(priority=priority, reasons=reasons,
                      coverage='inputs-present' if complete else 'partial')
        return report
    except (ValueError, TypeError, RecursionError, OverflowError):
        return report


class Fixtures(unittest.TestCase):
    def sample(self, realtime='enabled', signatures='current', coverage='query-exhausted', **counts):
        return json.dumps({'realtime': realtime, 'signatures': signatures,
                           'events': {'window_hours': 24, 'coverage': coverage,
                                      'counts': dict.fromkeys(IDS, 0) | counts}}).encode()

    def test_clear_inputs_not_safety(self):
        r = correlate(self.sample())
        self.assertEqual((r['priority'], r['coverage']), ('no-selected-indicators', 'inputs-present'))
        self.assertFalse(r['absence_of_compromise_verified'])

    def test_urgent_survives_missing_other_source(self):
        r = correlate(self.sample('disabled', 'unknown', 'unknown'))
        self.assertEqual((r['priority'], r['coverage']), ('urgent-review', 'partial'))
        self.assertIn('event-source-unavailable', r['reasons'])
        self.assertEqual(correlate(self.sample('unknown', 'unknown', **{'5001': 1}))['priority'], 'urgent-review')

    def test_history_not_overruled_by_current_status(self):
        r = correlate(self.sample(**{'5001': 1, '1117': 2}))
        self.assertEqual(r['priority'], 'urgent-review')
        self.assertFalse(r['remediation_verified'])
        self.assertFalse(r['action_authorized'])

    def test_stale_and_detection_both_visible(self):
        r = correlate(self.sample(signatures='stale', **{'1116': 1}))
        self.assertEqual(r['priority'], 'review')
        self.assertEqual(r['reasons'], ['detection-record', 'signatures-reported-stale'])

    def test_sample_limit_and_bad_counts(self):
        for n in (255, 256, 257):
            r = correlate(self.sample(coverage='limited', **{'1117': n}))
            self.assertEqual((r['priority'], r['coverage']), ('review', 'partial'))
            self.assertIn('event-sample-limited' if n == 256 else 'event-source-unavailable', r['reasons'])

    def test_invalid_input_no_disclosure(self):
        for raw in (b'', b'x' * (MAX_BYTES + 1), b'\xff', b'{"events":{},"events":{}}',
                    self.sample(realtime='SYNTHETIC-PRIVATE'), self.sample(signatures=True)):
            r = correlate(raw)
            self.assertEqual(r['priority'], 'unknown')
            self.assertNotIn('SYNTHETIC-PRIVATE', str(r))
            self.assertFalse(r['action_authorized'])


if __name__ == '__main__':
    unittest.main()
