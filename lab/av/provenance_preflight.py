# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Bounded offline PyPI provenance preflight, NOT cryptographic verification."""
import base64
import binascii
import hashlib
import json
import sys
import unittest
from pathlib import Path

FILENAME = "yara_x-1.24.0-cp39-abi3-win_amd64.whl"
DIGEST = "ce52bbf23683f47515bf493ee3d7c8346f3742c0dc5c654c389b8495b3dbfaca"
REPO = "VirusTotal/yara-x"
WORKFLOW = "release.yaml"
PREDICATE = "https://docs.pypi.org/attestations/publish/v1"
STATEMENT = "https://in-toto.io/Statement/v1"
MAX_BYTES = 1024 * 1024
MAX_STATEMENT = 16384

def unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate")
        out[k] = v
    return out

def bad_constant(_):
    raise ValueError("invalid JSON constant")

def parse(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=bad_constant)

def one_version(obj):
    return type(obj) is dict and type(obj.get("version")) is int and obj["version"] == 1

def b64(value, limit):
    if type(value) is not str or not 1 <= len(value) <= 4 * ((limit + 2) // 3):
        raise ValueError("invalid encoded field")
    data = base64.b64decode(value, validate=True)
    if not 1 <= len(data) <= limit:
        raise ValueError("invalid field size")
    return data

def preflight(raw):
    """Only exact structural/declared subject binding; signatures remain unverified.
    Narrow single-publisher/single-publish-attestation profile. A different valid
    profile requires review, not a silent fallback. Never emits raw input.
    """
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        return None
    try:
        obj = parse(raw)
        if not one_version(obj):
            return None
        bundles = obj.get("attestation_bundles")
        if type(bundles) is not list or len(bundles) != 1:
            return None
        bundle = bundles[0]
        pub = bundle["publisher"]
        if (pub["kind"] != "GitHub" or pub["repository"] != REPO
                or pub["workflow"] != WORKFLOW):
            return None
        attestations = bundle["attestations"]
        if type(attestations) is not list or len(attestations) != 1:
            return None
        att = attestations[0]
        if not one_version(att):
            return None
        env = att["envelope"]
        b64(env["signature"], 4096)
        statement = parse(b64(env["statement"], MAX_STATEMENT))
        if (type(statement) is not dict or statement.get("_type") != STATEMENT
                or statement.get("predicateType") != PREDICATE
                or statement.get("subject") != [{"name": FILENAME,
                                                   "digest": {"sha256": DIGEST}}]):
            return None
        material = att["verification_material"]
        b64(material["certificate"], 16384)
        entries = material["transparency_entries"]
        if type(entries) is not list or not 1 <= len(entries) <= 8:
            return None
        if any(type(entry) is not dict or not entry for entry in entries):
            return None
        return {"schema": "aegis-provenance-preflight-v1",
                "provenance_sha256": hashlib.sha256(raw).hexdigest(),
                "declared_subject_sha256": DIGEST,
                "declared_publisher": REPO, "declared_workflow": WORKFLOW,
                "structural_preflight": "matched",
                "cryptographic_verification": "not-performed",
                "certificate_identity_verification": "not-performed",
                "license_review": "not-performed", "execution_approved": False}
    except (ValueError, TypeError, KeyError, IndexError, AttributeError,
            UnicodeError, binascii.Error, RecursionError):
        return None

class Fixtures(unittest.TestCase):
    def fixture(self):
        enc = lambda b: base64.b64encode(b).decode("ascii")
        st = {"_type": STATEMENT, "predicateType": PREDICATE,
              "subject": [{"name": FILENAME, "digest": {"sha256": DIGEST}}],
              "predicate": None}
        return {"version": 1, "attestation_bundles": [{
            "publisher": {"kind": "GitHub", "repository": REPO, "workflow": WORKFLOW},
            "attestations": [{"version": 1, "envelope": {
                "signature": enc(b"fake signature"), "statement": enc(json.dumps(st).encode())},
                "verification_material": {"certificate": enc(b"fake certificate"),
                                           "transparency_entries": [{"synthetic": True}]}}]}]}
    def run_obj(self, obj):
        return preflight(json.dumps(obj).encode())
    def att(self, obj):
        return obj["attestation_bundles"][0]["attestations"][0]
    def test_structural_match_is_never_approval(self):
        r = self.run_obj(self.fixture())
        self.assertEqual(r["structural_preflight"], "matched")
        self.assertEqual(r["cryptographic_verification"], "not-performed")
        self.assertFalse(r["execution_approved"])
    def test_wrong_publisher(self):
        for field in ("kind", "repository", "workflow"):
            obj = self.fixture()
            obj["attestation_bundles"][0]["publisher"][field] = "wrong"
            self.assertIsNone(self.run_obj(obj))
    def test_wrong_statement(self):
        for field in ("_type", "predicateType", "subject"):
            obj = self.fixture()
            env = self.att(obj)["envelope"]
            st = parse(base64.b64decode(env["statement"]))
            st[field] = "wrong"
            env["statement"] = base64.b64encode(json.dumps(st).encode()).decode()
            self.assertIsNone(self.run_obj(obj))
        for field in ("name", "digest"):
            obj = self.fixture()
            env = self.att(obj)["envelope"]
            st = parse(base64.b64decode(env["statement"]))
            st["subject"][0][field] = "wrong"
            env["statement"] = base64.b64encode(json.dumps(st).encode()).decode()
            self.assertIsNone(self.run_obj(obj))
    def test_ambiguous_bundles_and_attestations(self):
        obj = self.fixture()
        obj["attestation_bundles"] *= 2
        self.assertIsNone(self.run_obj(obj))
        obj = self.fixture()
        obj["attestation_bundles"][0]["attestations"] *= 2
        self.assertIsNone(self.run_obj(obj))
    def test_invalid_encoding_and_material(self):
        for field in ("signature", "statement"):
            obj = self.fixture()
            self.att(obj)["envelope"][field] = "!"
            self.assertIsNone(self.run_obj(obj))
        for field in ("certificate", "transparency_entries"):
            obj = self.fixture()
            self.att(obj)["verification_material"][field] = []
            self.assertIsNone(self.run_obj(obj))
    def test_bad_version_and_duplicate_keys(self):
        for version in (True, 2, "1"):
            obj = self.fixture()
            obj["version"] = version
            self.assertIsNone(self.run_obj(obj))
        self.assertIsNone(preflight(b'{"version":1,"version":1}'))
        self.assertIsNone(preflight(b'{"version":NaN}'))
    def test_bounds_and_shapes(self):
        for raw in (b"", b"x" * (MAX_BYTES + 1), b"[]", b"null", b"\xff"):
            self.assertIsNone(preflight(raw))
        obj = self.fixture()
        self.att(obj)["verification_material"]["transparency_entries"] = [{}]
        self.assertIsNone(self.run_obj(obj))
        obj = self.fixture()
        self.att(obj)["envelope"]["statement"] = base64.b64encode(
            b"x" * (MAX_STATEMENT + 1)).decode()
        self.assertIsNone(self.run_obj(obj))

def main():
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]])
    if len(sys.argv) == 3 and sys.argv[1] == "--inspect":
        try:
            with Path(sys.argv[2]).open("rb") as stream:
                result = preflight(stream.read(MAX_BYTES + 1))
        except OSError:
            result = None
        if result is None:
            print("Provenance structural preflight unavailable or unexpected.")
            return 1
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
        return 0
    return 2

if __name__ == "__main__":
    sys.exit(main())
