# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Offline V0.4 URL structure advisory. Never opens or resolves a URL."""
import ipaddress
import re
import unittest
from urllib.parse import urlsplit

MAX_CHARS = 2048
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def assess(value):
    result = dict(schema='aegis-url-advisory-v1', priority='unknown', reasons=[],
                  reputation_verified=False, destination_verified=False,
                  navigation_authorized=False)

    def finish(priority, *reasons):
        return dict(result, priority=priority, reasons=list(reasons))

    if type(value) is not str or not 1 <= len(value) <= MAX_CHARS:
        return finish('unknown', 'invalid-input')
    # Reject before urllib normalizes whitespace/control characters. Unicode
    # and backslashes require a browser-specific canonicalization review.
    if any(not 33 <= ord(c) <= 126 for c in value) or '\\' in value:
        return finish('review', 'ambiguous-characters')
    if re.search(r'%(?![0-9a-fA-F]{2})', value):
        return finish('review', 'invalid-percent-encoding')
    try:
        parts = urlsplit(value)
        if parts.scheme not in ('http', 'https'):
            return finish('review', 'unsupported-scheme')
        if not parts.netloc or not parts.hostname:
            return finish('review', 'missing-host')
        if '%' in parts.netloc:
            return finish('review', 'encoded-authority')
        if parts.username is not None or parts.password is not None:
            return finish('review', 'userinfo-present')
        host = parts.hostname
        port = parts.port
        if parts.netloc.endswith(':') or port == 0:
            return finish('review', 'invalid-port')
        reasons = []
        if parts.scheme == 'http':
            reasons.append('unencrypted-scheme')
        try:
            ipaddress.ip_address(host)
            reasons.append('ip-literal')
        except ValueError:
            labels = host.split('.')
            if (len(host) > 253 or len(labels) < 2 or
                    not all(LABEL.fullmatch(label) for label in labels) or
                    not any('a' <= c <= 'z' for c in labels[-1])):
                return finish('review', 'ambiguous-host')
            if any(label.startswith('xn--') for label in labels):
                reasons.append('idn-label')
        if port is not None and port != (443 if parts.scheme == 'https' else 80):
            reasons.append('nonstandard-port')
        return finish('review' if reasons else 'no-selected-indicators', *reasons)
    except (ValueError, UnicodeError):
        return finish('review', 'invalid-url-structure')


class Fixtures(unittest.TestCase):
    def test_https_is_not_trust(self):
        r = assess('https://example.invalid/fixture?q=FAKE-CANARY')
        self.assertEqual(r['priority'], 'no-selected-indicators')
        self.assertFalse(r['reputation_verified'])
        self.assertFalse(r['destination_verified'])
        self.assertFalse(r['navigation_authorized'])
        self.assertNotIn('FAKE-CANARY', str(r))

    def test_http_and_port(self):
        self.assertEqual(assess('http://example.invalid:8080')['reasons'],
                         ['unencrypted-scheme', 'nonstandard-port'])

    def test_ip_literals(self):
        for url in ('https://192.0.2.1', 'https://[2001:db8::1]'):
            self.assertIn('ip-literal', assess(url)['reasons'])

    def test_idn(self):
        self.assertEqual(assess('https://xn--bcher-kva.invalid')['reasons'], ['idn-label'])

    def test_userinfo_privacy(self):
        r = assess('https://FAKE-CANARY@example.invalid')
        self.assertEqual(r['reasons'], ['userinfo-present'])
        self.assertNotIn('FAKE-CANARY', str(r))

    def test_ambiguous_characters(self):
        for url in (' https://example.invalid', 'https://example.invalid\n',
                    'https://example.invalid\\fixture', 'https://b\u00fccher.invalid'):
            self.assertEqual(assess(url)['reasons'], ['ambiguous-characters'])

    def test_authority_and_encoding(self):
        self.assertEqual(assess('https://%65xample.invalid')['reasons'], ['encoded-authority'])
        self.assertEqual(assess('https://example.invalid/%x')['reasons'], ['invalid-percent-encoding'])
        for url in ('https://example.invalid:99999', 'https://example.invalid:',
                    'https://example.invalid:0', 'https://[2001:db8::1'):
            self.assertEqual(assess(url)['priority'], 'review')

    def test_unsupported_and_ambiguous_hosts(self):
        for url in ('file:///fixture', '//example.invalid', 'https:///fixture',
                    'https://single', 'https://example.invalid.', 'https://123.456'):
            self.assertEqual(assess(url)['priority'], 'review')

    def test_input_bounds(self):
        for value in (None, b'https://example.invalid', '', 'x' * (MAX_CHARS + 1)):
            self.assertEqual(assess(value)['priority'], 'unknown')

    def test_no_authorization_in_all_outcomes(self):
        for value in ('https://example.invalid', 'http://example.invalid', None):
            self.assertFalse(assess(value)['navigation_authorized'])


if __name__ == '__main__':
    unittest.main()
