# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Offline review queue for retained declarations; never approves execution or distribution."""
import hashlib
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

WHEEL = "ce52bbf23683f47515bf493ee3d7c8346f3742c0dc5c654c389b8495b3dbfaca"
SBOM = "dac154f8c401cf5f6270c646c2f828a73bc38ed22629c0fc09d75b65ec030e23"
REPORT_SHA256 = "64a6fe87a2de29eb6787a01aca7e9e7f698a3a5284587f1507a6fe6a3e008a83"
REPORT = Path(__file__).resolve().parents[2] / "docs/evidence/yara-x-1.24.0-win-amd64-sbom-components.json"
MAX_BYTES = 1024 * 1024

def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out

def reject_constant(_):
    raise ValueError("invalid constant")

def text_label(value):
    return (type(value) is str and 0 < len(value) <= 512
            and bool(value.strip()) and all(32 <= ord(c) <= 126 for c in value))

def matches_report(raw, expected_sha256):
    """Exact retained bytes only; not upstream provenance or license clearance."""
    return (type(raw) is bytes and 1 <= len(raw) <= MAX_BYTES
            and hashlib.sha256(raw).hexdigest() == expected_sha256)

def retained_review_queue(raw):
    if not matches_report(raw, REPORT_SHA256):
        return None
    result = review_queue(raw)
    if result is not None:
        result["retained_report_sha256"] = REPORT_SHA256
    return result

def review_queue(raw):
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                         parse_constant=reject_constant)
        if (type(obj) is not dict or obj.get("schema") != "aegis-sbom-component-evidence-v1"
                or obj.get("sbom_sha256") != SBOM or obj.get("coverage") != "top-level-only"
                or obj.get("execution_approved") is not False
                or obj.get("license_review") != "not-performed"
                or obj.get("provenance_review") != "not-performed"
                or any(obj.get(field) != "not-performed" for field in (
                    "dependency_linkage_review", "license_expression_validation",
                    "purl_validation", "schema_validation"))
                or type(obj.get("components_with_nested_entries")) is not int
                or obj["components_with_nested_entries"] != 0):
            return None
        if obj.get("source", {}).get("wheel_sha256") != WHEEL:
            return None
        rows = obj.get("components")
        if type(rows) is not list or not 1 <= len(rows) <= 4096:
            return None
        if type(obj.get("top_level_components")) is not int or obj["top_level_components"] != len(rows):
            return None
        counts, flags = Counter(), Counter()
        purls = set()
        queue = []
        for i, row in enumerate(rows):
            if type(row) is not dict or type(row.get("source_index")) is not int or row["source_index"] != i:
                return None
            if row.get("review_status") != "pending":
                return None
            name, version, purl = (row.get(k) for k in ("name", "version", "declared_purl"))
            if not all(text_label(v) for v in (name, version, purl)) or purl in purls:
                return None
            purls.add(purl)
            licenses = row.get("declared_licenses")
            if (type(licenses) is not list or not 1 <= len(licenses) <= 64
                    or not all(text_label(v) for v in licenses)
                    or len(set(licenses)) != len(licenses)):
                return None
            counts.update(licenses)
            labels = " ".join(licenses)
            reasons = []
            if "LGPL-" in labels:
                reasons.append("LGPL-declaration")
            if "Unicode-" in labels:
                reasons.append("Unicode-notice")
            if " WITH " in labels:
                reasons.append("exception")
            if " OR " in labels or " AND " in labels:
                reasons.append("compound-expression")
            if not reasons:
                reasons.append("ordinary-notice-review")
            flags.update(reasons)
            queue.append({"source_index": i, "name": name, "version": version,
                          "declared_purl": purl, "declared_licenses": licenses,
                          "review_reasons": reasons, "review_status": "pending"})
        declared = obj.get("declared_license_counts")
        if type(declared) is not dict or any(type(n) is not int or n <= 0 for n in declared.values()):
            return None
        if dict(counts) != declared:
            return None
        for field in ("missing_declared_license", "missing_purl", "missing_version", "repeated_exact_purl_groups"):
            if type(obj.get(field)) is not int or obj[field] != 0:
                return None
        queue.sort(key=lambda r: (not any(x in r["review_reasons"] for x in
                     ("LGPL-declaration", "Unicode-notice", "exception")), r["source_index"]))
        return {"schema": "aegis-review-queue-v1", "wheel_sha256": WHEEL,
                "declared_sbom_sha256": SBOM, "components": len(rows),
                "license_groups": len(counts), "review_reason_counts": dict(sorted(flags.items())),
                "license_review": "not-performed", "provenance_review": "not-performed",
                "execution_approved": False, "queue": queue}
    except (ValueError, TypeError, AttributeError, RecursionError):
        return None

class Fixtures(unittest.TestCase):
    def fixture(self):
        return {"schema":"aegis-sbom-component-evidence-v1", "sbom_sha256":SBOM,
                "coverage":"top-level-only", "execution_approved":False,
                "license_review":"not-performed", "provenance_review":"not-performed",
                "dependency_linkage_review":"not-performed",
                "license_expression_validation":"not-performed",
                "purl_validation":"not-performed", "schema_validation":"not-performed",
                "components_with_nested_entries":0,
                "source":{"wheel_sha256":WHEEL}, "top_level_components":2,
                "missing_declared_license":0,"missing_purl":0,"missing_version":0,
                "repeated_exact_purl_groups":0,
                "declared_license_counts":{"expression:MIT":1,"expression:MIT OR LGPL-2.1-or-later":1},
                "components":[{"source_index":0,"name":"fixture-a","version":"1",
                    "declared_purl":"pkg:cargo/fixture-a@1","declared_licenses":["expression:MIT"],
                    "review_status":"pending"},{"source_index":1,"name":"fixture-b","version":"1",
                    "declared_purl":"pkg:cargo/fixture-b@1","declared_licenses":["expression:MIT OR LGPL-2.1-or-later"],
                    "review_status":"pending"}]}
    def run_obj(self, obj):
        return review_queue(json.dumps(obj).encode())
    def test_priority_and_no_approval(self):
        r = self.run_obj(self.fixture())
        self.assertEqual(r["components"], 2)
        self.assertEqual(r["queue"][0]["name"], "fixture-b")
        self.assertFalse(r["execution_approved"])
        self.assertEqual(r["license_review"], "not-performed")
    def test_retained_bytes_gate(self):
        # No actual wheel or external data: the parser and exact-byte gate are separate.
        raw = json.dumps(self.fixture()).encode()
        expected = hashlib.sha256(raw).hexdigest()
        self.assertTrue(matches_report(raw, expected))
        self.assertFalse(matches_report(raw + b" ", expected))
        self.assertIsNotNone(review_queue(raw + b" "))
        self.assertIsNone(retained_review_queue(raw))
        self.assertIsNone(retained_review_queue(raw + b" "))
        self.assertFalse(matches_report(b"", hashlib.sha256(b"").hexdigest()))
        oversized = b"x" * (MAX_BYTES + 1)
        self.assertFalse(matches_report(oversized, hashlib.sha256(oversized).hexdigest()))

    def test_unreviewed_scope_required(self):
        for field in ("dependency_linkage_review", "license_expression_validation",
                      "purl_validation", "schema_validation"):
            for value in ("passed", None):
                obj = self.fixture()
                obj[field] = value
                self.assertIsNone(self.run_obj(obj))
        for value in (True, 1, None):
            obj = self.fixture()
            obj["components_with_nested_entries"] = value
            self.assertIsNone(self.run_obj(obj))

    def test_wrong_binding(self):
        for field in ("sbom_sha256","source"):
            obj = self.fixture()
            obj[field] = {}
            self.assertIsNone(self.run_obj(obj))
    def test_inconsistent_counts(self):
        for field in ("top_level_components","declared_license_counts","missing_purl"):
            obj = self.fixture()
            obj[field] = True
            self.assertIsNone(self.run_obj(obj))
    def test_false_clearance(self):
        obj = self.fixture()
        obj["execution_approved"] = True
        self.assertIsNone(self.run_obj(obj))
        obj = self.fixture()
        obj["components"][0]["review_status"] = "approved"
        self.assertIsNone(self.run_obj(obj))
    def test_duplicate_or_wrong_index(self):
        obj = self.fixture()
        obj["components"][1]["declared_purl"] = obj["components"][0]["declared_purl"]
        self.assertIsNone(self.run_obj(obj))
        obj = self.fixture()
        obj["components"][0]["source_index"] = False
        self.assertIsNone(self.run_obj(obj))
    def test_duplicate_json_and_size(self):
        self.assertIsNone(review_queue(b'{"schema":0,"schema":1}'))
        self.assertIsNone(review_queue(b'x' * (MAX_BYTES + 1)))
    def test_invalid_license(self):
        obj = self.fixture()
        obj["components"][0]["declared_licenses"] = ["expression:MIT","expression:MIT"]
        self.assertIsNone(self.run_obj(obj))
    def test_untrusted_labels(self):
        obj = self.fixture()
        obj["components"][0]["name"] = "fixture\\n"
        obj["components"][0]["name"] += chr(10)
        self.assertIsNone(self.run_obj(obj))

def main():
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]])
    elif sys.argv[1:] == ["--review-queue"]:
        try:
            with REPORT.open("rb") as stream:
                result = retained_review_queue(stream.read(MAX_BYTES + 1))
        except OSError:
            result = None
        if result is None:
            print("Review queue unavailable or inconsistent.")
            return 1
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
        return 0
    else:
        print("Use --self-test or --review-queue.")
        return 2

if __name__ == "__main__":
    sys.exit(main())
