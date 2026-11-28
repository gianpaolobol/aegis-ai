# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""V0.3 offline network configuration triage; synthetic metadata only."""
import json
import unittest

MAX_BYTES = 4096
PROFILES = ('domain', 'private', 'public')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def choice(value, options):
    return value if type(value) is str and value in options else 'unknown'


def assess(raw):
    report = dict(schema='aegis-network-posture-v1', priority='unknown',
                  coverage='unknown', reasons=[], action_authorized=False,
                  connectivity_verified=False, tunnel_verified=False,
                  dns_protection_verified=False, active_profile_verified=False)
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
            return report
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
        if type(obj) is not dict or set(obj) != {'firewall', 'dns', 'vpn'}:
            return report
    except (ValueError, TypeError, RecursionError, OverflowError):
        return report
    firewall = obj['firewall']
    if type(firewall) is not dict or not set(firewall) <= set(PROFILES):
        firewall = {}
    gaps, findings = [], []
    urgent = False
    for profile in PROFILES:
        row = firewall.get(profile)
        if type(row) is not dict or set(row) != {'enabled', 'inbound'}:
            row = {}
        enabled = choice(row.get('enabled'), ('enabled', 'disabled'))
        inbound = choice(row.get('inbound'), ('block', 'allow'))
        if enabled == 'disabled':
            findings.append(profile + '-firewall-reported-disabled')
            urgent = True
        if inbound == 'allow':
            findings.append(profile + '-default-inbound-reported-allow')
        if enabled == 'unknown' or inbound == 'unknown':
            gaps.append(profile + '-firewall-incomplete')
    dns = choice(obj['dns'], ('addresses-reported', 'empty-reported'))
    if dns == 'empty-reported':
        findings.append('dns-empty-reported-not-proof-of-absence')
    elif dns == 'unknown':
        gaps.append('dns-inventory-unavailable')
    vpn = choice(obj['vpn'], ('connected-reported', 'disconnected-reported', 'no-profiles-reported'))
    if vpn == 'unknown':
        gaps.append('vpn-inventory-unavailable')
    # VPN is optional. Disconnected/absent profiles are not findings.
    report.update(priority='urgent-review' if urgent else 'review' if findings or gaps else 'no-selected-indicators',
                  coverage='partial' if gaps else 'inputs-present', reasons=findings + gaps)
    return report


class Fixtures(unittest.TestCase):
    def sample(self):
        return {'firewall': {p: {'enabled': 'enabled', 'inbound': 'block'} for p in PROFILES},
                'dns': 'addresses-reported', 'vpn': 'no-profiles-reported'}

    def run_sample(self, obj):
        return assess(json.dumps(obj).encode())

    def test_complete_does_not_prove_security(self):
        r = self.run_sample(self.sample())
        self.assertEqual((r['priority'], r['coverage']), ('no-selected-indicators', 'inputs-present'))
        for k, v in r.items():
            if k.endswith('_verified') or k == 'action_authorized':
                self.assertIs(v, False)

    def test_disabled_survives_missing_sources(self):
        obj = self.sample()
        obj['firewall']['public']['enabled'] = 'disabled'
        obj['dns'] = None
        obj['vpn'] = 'unknown'
        r = self.run_sample(obj)
        self.assertEqual((r['priority'], r['coverage']), ('urgent-review', 'partial'))
        self.assertIn('public-firewall-reported-disabled', r['reasons'])

    def test_inbound_allow_and_empty_dns(self):
        obj = self.sample()
        obj['firewall']['private']['inbound'] = 'allow'
        obj['dns'] = 'empty-reported'
        self.assertEqual(self.run_sample(obj)['reasons'], ['private-default-inbound-reported-allow', 'dns-empty-reported-not-proof-of-absence'])

    def test_vpn_optional(self):
        for value in ('connected-reported', 'disconnected-reported', 'no-profiles-reported'):
            obj = self.sample()
            obj['vpn'] = value
            self.assertEqual(self.run_sample(obj)['priority'], 'no-selected-indicators')
            self.assertFalse(self.run_sample(obj)['tunnel_verified'])

    def test_malformed_profile_does_not_hide_other_finding(self):
        obj = self.sample()
        obj['firewall']['domain'] = {'enabled': True, 'inbound': 'SYNTHETIC-PRIVATE'}
        obj['firewall']['private']['enabled'] = 'disabled'
        r = self.run_sample(obj)
        self.assertEqual(r['priority'], 'urgent-review')
        self.assertIn('domain-firewall-incomplete', r['reasons'])
        self.assertNotIn('SYNTHETIC-PRIVATE', str(r))

    def test_unknown_extra_profile_rejects_firewall_source(self):
        obj = self.sample()
        obj['firewall']['SYNTHETIC-PRIVATE'] = {}
        r = self.run_sample(obj)
        self.assertEqual(r['coverage'], 'partial')
        self.assertEqual(r['reasons'], [p + '-firewall-incomplete' for p in PROFILES])

    def test_invalid_and_duplicate_input(self):
        for raw in (b'', b'x' * (MAX_BYTES + 1), b'\xff', b'[]', b'{"dns":1,"dns":2}',
                    b'{"firewall":{"domain":{},"domain":{}},"dns":null,"vpn":null}',
                    b'[' * 1500 + b']' * 1500):
            r = assess(raw)
            self.assertEqual(r['priority'], 'unknown')
            self.assertFalse(r['action_authorized'])

    def test_partial_profile_and_types(self):
        obj = self.sample()
        del obj['firewall']['public']
        obj['dns'] = ['addresses-reported']
        obj['vpn'] = True
        self.assertEqual(self.run_sample(obj)['reasons'], ['public-firewall-incomplete', 'dns-inventory-unavailable', 'vpn-inventory-unavailable'])


if __name__ == '__main__':
    unittest.main()
