# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Offline, read-only preflight for a single candidate YARA-X Windows wheel.
Not an attestation verifier, package installer or approval to execute code.
"""
import hashlib
import json
import base64
import csv
import re
import io
from pathlib import Path
import stat
import sys
import unittest
import zipfile
from email.parser import BytesParser
from email.policy import default

FILENAME = "yara_x-1.24.0-cp39-abi3-win_amd64.whl"
SHA256 = "ce52bbf23683f47515bf493ee3d7c8346f3742c0dc5c654c389b8495b3dbfaca"
MAX_WHEEL = 16 * 1024 * 1024
MAX_METADATA = 256 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_RECORD = 256 * 1024
PREFIX = "yara_x-1.24.0.dist-info/"



def valid_windows_members(items):
    """Conservative Windows wheel namespace profile; never extracts files."""
    seen = {}
    explicit = set()
    for item in items:
        name = item.filename
        if item.orig_filename != name or not name or len(name) > 1024:
            return False
        is_dir = item.is_dir()
        parts = (name[:-1] if is_dir else name).split("/")
        if len(parts) > 32:
            return False
        mode = stat.S_IFMT(item.external_attr >> 16)
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
            return False
        if (mode == stat.S_IFDIR and not is_dir) or (mode == stat.S_IFREG and is_dir):
            return False
        for part in parts:
            # Narrow ASCII profile for this exact candidate; no short-name aliases.
            if (not re.fullmatch(r"[A-Za-z0-9_.+ -]{1,255}", part)
                    or part.startswith(" ") or part.endswith((" ", "."))
                    or part in (".", "..")):
                return False
            stem = part.split(".", 1)[0].rstrip(" ").upper()
            if (stem in ("CON", "PRN", "AUX", "NUL")
                    or re.fullmatch(r"(?:COM|LPT)[0-9]", stem)):
                return False
        for depth in range(1, len(parts) + 1):
            spelling = "/".join(parts[:depth])
            key = spelling.lower()
            directory = depth < len(parts) or is_dir
            previous = seen.get(key)
            if previous is not None and previous != (spelling, directory):
                return False
            seen[key] = (spelling, directory)
        if key in explicit:
            return False
        explicit.add(key)
    return True


def verify_record(z, items):
    """Strict candidate profile: SHA-256 only, no legacy detached signatures."""
    files = {i.filename: i for i in items if not i.is_dir()}
    record = PREFIX + "RECORD"
    if record not in files or files[record].file_size > MAX_RECORD:
        return False
    if any(n in files for n in (record + ".jws", record + ".p7s")):
        return False
    if sum(i.file_size for i in files.values()) > MAX_EXPANDED:
        return False
    with z.open(files[record]) as stream:
        raw = stream.read(MAX_RECORD + 1)
    if len(raw) > MAX_RECORD:
        return False
    rows = {}
    for row in csv.reader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True):
        if len(row) != 3 or row[0] in rows or row[0] not in files:
            return False
        rows[row[0]] = (row[1], row[2])
    if rows.keys() != files.keys() or rows[record] != ("", ""):
        return False
    for name, item in files.items():
        if name == record:
            continue
        digest, size = rows[name]
        if (not re.fullmatch(r"sha256=[A-Za-z0-9_-]{43}", digest)
                or size != str(item.file_size)):
            return False
        h = hashlib.sha256()
        count = 0
        with z.open(item) as stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                count += len(chunk)
                if count > item.file_size:
                    return False
                h.update(chunk)
        actual = "sha256=" + base64.urlsafe_b64encode(h.digest()).decode("ascii").rstrip("=")
        if count != item.file_size or actual != digest:
            return False
    return True


def inspect_bytes(data, expected):
    if type(data) is not bytes or len(data) > MAX_WHEEL:
        return "InvalidSize"
    if hashlib.sha256(data).hexdigest() != expected:
        return "DigestMismatch"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            items = z.infolist()
            if len(items) > 2048:
                return "InvalidArchive"
            if not valid_windows_members(items):
                return "InvalidArchive"
            def metadata(name):
                item = z.getinfo(PREFIX + name)
                if item.file_size > MAX_METADATA:
                    raise ValueError()
                with z.open(item) as stream:
                    raw = stream.read(MAX_METADATA + 1)
                if len(raw) > MAX_METADATA:
                    raise ValueError()
                return BytesParser(policy=default).parsebytes(raw)
            m = metadata("METADATA")
            w = metadata("WHEEL")
            if (m.defects or w.defects or m.get_all("Name") != ["yara-x"] or
                m.get_all("Version") != ["1.24.0"] or
                w.get_all("Tag") != ["cp39-abi3-win_amd64"]):
                return "MetadataMismatch"
            if not verify_record(z, items):
                return "RecordMismatch"
            if m.get_all("Requires-Dist"):
                return "DependencyReviewRequired"
            return "DigestAndMetadataMatch"
    except Exception:
        return "InvalidArchive"


def read_candidate(path):
    p = Path(path)
    if p.name != FILENAME or p.is_symlink() or not p.is_file():
        raise ValueError("candidate unavailable")
    with p.open("rb") as f:
        if not stat.S_ISREG(__import__("os").fstat(f.fileno()).st_mode):
            raise ValueError("candidate unavailable")
        return f.read(MAX_WHEEL + 1)


def inspect_path(path):
    try:
        return inspect_bytes(read_candidate(path), SHA256)
    except (OSError, ValueError):
        return "Unavailable"


def inventory_bytes(data, expected):
    """Evidence only: exact archive bytes, no extraction, import or approval."""
    if inspect_bytes(data, expected) != "DigestAndMetadataMatch":
        return None
    try:
        entries = []
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for item in sorted(z.infolist(), key=lambda i: i.filename):
                if item.is_dir():
                    continue
                name = item.filename
                lower = name.lower()
                leaf = lower.rsplit("/", 1)[-1]
                # Candidate hints, not legal conclusions or a complete linkage graph.
                notice = (lower.startswith(PREFIX.lower() + "licenses/") or
                          leaf.startswith(("license", "licence", "notice", "copying", "copyright")))
                native = leaf.endswith((".pyd", ".dll", ".exe", ".lib", ".so", ".dylib"))
                digest = hashlib.sha256()
                count = 0
                with z.open(item) as stream:
                    while True:
                        chunk = stream.read(65536)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > item.file_size:
                            return None
                        digest.update(chunk)
                if count != item.file_size:
                    return None
                entries.append({"path": name, "size": count, "sha256": digest.hexdigest(),
                                "notice_candidate": notice, "native_candidate": native})
        return {"schema": "aegis-wheel-evidence-v1",
                "archive_sha256": hashlib.sha256(data).hexdigest(),
                "coverage": "archive-members-only",
                "license_review": "not-performed",
                "provenance_review": "not-performed",
                "execution_approved": False, "members": entries}
    except Exception:
        return None


SBOM_MEMBER = PREFIX + "sboms/yara-x-py.cyclonedx.json"
SBOM_SHA256 = "dac154f8c401cf5f6270c646c2f828a73bc38ed22629c0fc09d75b65ec030e23"
MAX_SBOM = 1024 * 1024
MAX_COMPONENTS = 4096


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("non-JSON constant")


def sbom_summary(raw, expected):
    """Bounded top-level component evidence; NOT full CycloneDX validation."""
    if type(raw) is not bytes or len(raw) > MAX_SBOM:
        return None
    if hashlib.sha256(raw).hexdigest() != expected:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                         parse_constant=reject_constant)
        if (not isinstance(obj, dict) or obj.get("bomFormat") != "CycloneDX"
                or obj.get("specVersion") not in ("1.4", "1.5", "1.6", "1.7")):
            return None
        components = obj.get("components")
        if not isinstance(components, list) or not 1 <= len(components) <= MAX_COMPONENTS:
            return None
        refs = set()
        missing_version = missing_purl = nested = missing_license = 0
        identifiers = {}
        def label(value):
            # Narrow printable ASCII metadata, never interpreted as commands.
            return (isinstance(value, str) and 0 < len(value) <= 512
                    and all(32 <= ord(c) <= 126 for c in value)
                    and bool(value.strip()))
        for comp in components:
            if not isinstance(comp, dict) or not label(comp.get("name")):
                return None
            ref = comp.get("bom-ref")
            if ref is not None:
                if not label(ref) or ref in refs:
                    return None
                refs.add(ref)
            if not label(comp.get("version")):
                missing_version += 1
            if not label(comp.get("purl")):
                missing_purl += 1
            if comp.get("components"):
                nested += 1
            licenses = comp.get("licenses", [])
            if not isinstance(licenses, list) or len(licenses) > 64:
                return None
            declared = set()
            for entry in licenses:
                if not isinstance(entry, dict):
                    return None
                if ("expression" in entry) == ("license" in entry):
                    return None
                if "expression" in entry:
                    value = entry["expression"]
                    kind = "expression"
                else:
                    license_obj = entry["license"]
                    if not isinstance(license_obj, dict):
                        return None
                    if ("id" in license_obj) == ("name" in license_obj):
                        return None
                    kind = "id" if "id" in license_obj else "name"
                    value = license_obj[kind]
                if not label(value):
                    return None
                declared.add(kind + ":" + value)
            if not declared:
                missing_license += 1
            for item in declared:
                identifiers[item] = identifiers.get(item, 0) + 1
                if len(identifiers) > 256:
                    return None
        return {"schema": "aegis-sbom-summary-v1", "sbom_sha256": expected,
                "spec_version": obj["specVersion"], "top_level_components": len(components),
                "missing_declared_license": missing_license, "missing_version": missing_version,
                "missing_purl": missing_purl, "components_with_nested_entries": nested,
                "declared_license_counts": identifiers,
                "coverage": "top-level-only", "schema_validation": "not-performed",
                "license_review": "not-performed", "provenance_review": "not-performed",
                "execution_approved": False}
    except (ValueError, TypeError, RecursionError):
        return None


def embedded_sbom_summary(data, expected, sbom_expected):
    if inspect_bytes(data, expected) != "DigestAndMetadataMatch":
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            item = z.getinfo(SBOM_MEMBER)
            if item.file_size > MAX_SBOM:
                return None
            with z.open(item) as stream:
                raw = stream.read(MAX_SBOM + 1)
            if len(raw) != item.file_size:
                return None
        return sbom_summary(raw, sbom_expected)
    except (KeyError, OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        return None


class Fixtures(unittest.TestCase):
    def wheel(self, name="yara-x", version="1.24.0", tag="cp39-abi3-win_amd64",
              extra="", member=None, record_mode="valid", member_data=b"synthetic"):
        b = io.BytesIO()
        contents = {
            PREFIX + "METADATA": f"Name: {name}\nVersion: {version}\n{extra}\n".encode(),
            PREFIX + "WHEEL": f"Tag: {tag}\n\n".encode(),
        }
        if member:
            contents[member] = member_data
        record = PREFIX + "RECORD"
        out = io.StringIO(newline="")
        writer = csv.writer(out)
        for index, (key, value) in enumerate(contents.items()):
            digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode().rstrip("=")
            row = [key, "sha256=" + digest, str(len(value))]
            if index == 0:
                if record_mode == "bad_hash":
                    row[1] = "sha256=" + "A" * 43
                elif record_mode == "bad_size":
                    row[2] = "0"
                elif record_mode == "weak_hash":
                    row[1] = "sha1=" + "A" * 27
                elif record_mode == "omitted":
                    continue
                elif record_mode == "duplicate":
                    writer.writerow(row)
            writer.writerow(row)
        writer.writerow([record, "", ""])
        if record_mode == "extra":
            writer.writerow(["absent.txt", "", ""])
        with zipfile.ZipFile(b, "w") as z:
            for key, value in contents.items():
                z.writestr(key, value)
            if record_mode != "missing":
                z.writestr(record, out.getvalue())
        return b.getvalue()
    def check(self, data):
        return inspect_bytes(data, hashlib.sha256(data).hexdigest())
    def test_match_is_not_approval(self):
        self.assertEqual(self.check(self.wheel()), "DigestAndMetadataMatch")
    def test_record_failures(self):
        for mode in ("missing", "bad_hash", "bad_size", "weak_hash", "omitted",
                     "duplicate", "extra"):
            with self.subTest(mode=mode):
                self.assertEqual(self.check(self.wheel(record_mode=mode)), "RecordMismatch")
    def test_expanded_limit(self):
        from unittest.mock import patch
        with patch(__name__ + ".MAX_EXPANDED", 1):
            self.assertEqual(self.check(self.wheel()), "RecordMismatch")
    def test_changed_bytes(self):
        d = self.wheel()
        self.assertEqual(inspect_bytes(d+b"x", hashlib.sha256(d).hexdigest()), "DigestMismatch")
    def test_mismatched_metadata(self):
        for d in (self.wheel(name="other"), self.wheel(version="0"), self.wheel(tag="other"),
                  self.wheel(extra="Name: duplicate\n")):
            self.assertEqual(self.check(d), "MetadataMismatch")
    def test_dependency_requires_review(self):
        self.assertEqual(self.check(self.wheel(extra="Requires-Dist: synthetic\n")), "DependencyReviewRequired")
    def test_unsafe_archive_names(self):
        for n in ("../example", "/example", "C:/example", "a/../b",
                  PREFIX+"metadata"):
            self.assertEqual(self.check(self.wheel(member=n)), "InvalidArchive")

    def test_windows_namespace(self):
        for name in ("CON", "nested/AUX.txt", "com1.log", "LPT9",
                     "COM\u00b9.txt", "a/NUL .txt", "x.", " x", "x ",
                     "dir./child", "dir /child", "x~1.txt", "a//b",
                     "bad?.txt", "bad\tname", "caf\u00e9.txt"):
            with self.subTest(name=name):
                self.assertEqual(self.check(self.wheel(member=name)), "InvalidArchive")

    def test_windows_hierarchy(self):
        def member(name):
            return zipfile.ZipInfo(name)
        for names in (("a", "a/b"), ("a/b", "a"), ("A/b", "a/c"),
                      ("a/", "a"), ("a", "A"), ("a/", "a/")):
            with self.subTest(names=names):
                self.assertFalse(valid_windows_members([member(n) for n in names]))
        for names in (("a/", "a/b", "a/c"), ("a/b", "a/"),
                      ("a/b", "a/c"), ("x-1.0.dist-info/METADATA",)):
            self.assertTrue(valid_windows_members([member(n) for n in names]))

    def test_windows_special_members(self):
        for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR):
            item = zipfile.ZipInfo("synthetic")
            item.external_attr = mode << 16
            self.assertFalse(valid_windows_members([item]))
        item = zipfile.ZipInfo("synthetic")
        item.external_attr = stat.S_IFDIR << 16
        self.assertFalse(valid_windows_members([item]))
        item = zipfile.ZipInfo("synthetic/")
        item.external_attr = stat.S_IFREG << 16
        self.assertFalse(valid_windows_members([item]))
        item = zipfile.ZipInfo("synthetic\x00alias")
        self.assertFalse(valid_windows_members([item]))

    def test_invalid_archive_and_size(self):
        self.assertEqual(self.check(b"not zip"), "InvalidArchive")
        self.assertEqual(inspect_bytes(b"x"*(MAX_WHEEL+1), ""), "InvalidSize")
    def test_inventory_exact_and_deterministic(self):
        data = self.wheel(member=PREFIX + "licenses/LICENSE.txt")
        expected = hashlib.sha256(data).hexdigest()
        evidence = inventory_bytes(data, expected)
        self.assertEqual(evidence, inventory_bytes(data, expected))
        self.assertEqual(evidence["archive_sha256"], expected)
        self.assertFalse(evidence["execution_approved"])
        self.assertEqual(evidence["license_review"], "not-performed")
        self.assertEqual(evidence["provenance_review"], "not-performed")
        self.assertEqual(evidence["coverage"], "archive-members-only")
        paths = [entry["path"] for entry in evidence["members"]]
        self.assertEqual(paths, sorted(paths))
        self.assertIn(PREFIX + "RECORD", paths)
        notice = next(e for e in evidence["members"] if e["notice_candidate"])
        self.assertEqual(notice["path"], PREFIX + "licenses/LICENSE.txt")
        self.assertEqual(notice["size"], len(b"synthetic"))
        self.assertEqual(notice["sha256"], hashlib.sha256(b"synthetic").hexdigest())
        self.assertFalse(notice["native_candidate"])

    def test_inventory_native_hint_not_approval(self):
        data = self.wheel(member="yara_x/fixture.PYD")
        evidence = inventory_bytes(data, hashlib.sha256(data).hexdigest())
        self.assertEqual([e["path"] for e in evidence["members"] if e["native_candidate"]],
                         ["yara_x/fixture.PYD"])
        self.assertFalse(any(e["notice_candidate"] for e in evidence["members"]))
        self.assertFalse(evidence["execution_approved"])

    def test_inventory_refuses_invalid_preflight(self):
        for data in (self.wheel(record_mode="bad_hash"),
                     self.wheel(member="CON"), self.wheel(extra="Requires-Dist: synthetic\n")):
            self.assertIsNone(inventory_bytes(data, hashlib.sha256(data).hexdigest()))
        data = self.wheel()
        self.assertIsNone(inventory_bytes(data, "0" * 64))

    def test_missing_path(self):
        self.assertEqual(inspect_path("not-the-candidate.whl"), "Unavailable")
    def test_oversize_metadata(self):
        self.assertEqual(self.check(self.wheel(extra="Summary: " + "x"*MAX_METADATA)), "InvalidArchive")


    def test_sbom_summary_declarations_not_approval(self):
        obj = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"name": "fixture-a", "version": "1", "purl": "pkg:cargo/fixture-a@1",
             "bom-ref": "a", "licenses": [{"license": {"id": "MIT"}},
                                          {"license": {"id": "MIT"}}]},
            {"name": "fixture-b", "licenses": [{"expression": "MIT OR Apache-2.0"}]},
            {"name": "fixture-c", "components": [{"name": "nested"}]}]}
        raw = json.dumps(obj).encode()
        report = sbom_summary(raw, hashlib.sha256(raw).hexdigest())
        self.assertEqual(report["top_level_components"], 3)
        self.assertEqual(report["missing_declared_license"], 1)
        self.assertEqual(report["missing_version"], 2)
        self.assertEqual(report["missing_purl"], 2)
        self.assertEqual(report["components_with_nested_entries"], 1)
        self.assertEqual(report["declared_license_counts"], {"id:MIT": 1,
                                                             "expression:MIT OR Apache-2.0": 1})
        self.assertFalse(report["execution_approved"])
        self.assertEqual(report["schema_validation"], "not-performed")
    def test_sbom_rejects_malformed(self):
        for raw in (b'{"bomFormat":"CycloneDX","bomFormat":"other"}',
                    b'{"bomFormat":"CycloneDX","specVersion":"9","components":[]}',
                    b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[NaN]}',
                    b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","bom-ref":"x"},{"name":"b","bom-ref":"x"}]}',
                    b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","licenses":[{"license":{"id":"MIT","name":"other"}}]}]}',
                    b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","licenses":[{"expression":"MIT","license":{"id":"MIT"}}]}]}',
                    b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","licenses":[{"expression":" " }]}]}',
                    b'\xff', b'[' * 2000):
            with self.subTest(raw=raw[:80]):
                self.assertIsNone(sbom_summary(raw, hashlib.sha256(raw).hexdigest()))
    def test_sbom_bounds_and_digest(self):
        raw = b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}'
        self.assertIsNone(sbom_summary(raw, "0" * 64))
        self.assertIsNone(sbom_summary(b"x" * (MAX_SBOM+1), "0" * 64))
        obj = {"bomFormat": "CycloneDX", "specVersion": "1.6",
               "components": [{"name": "a"}] * (MAX_COMPONENTS+1)}
        raw = json.dumps(obj).encode()
        self.assertIsNone(sbom_summary(raw, hashlib.sha256(raw).hexdigest()))
    def test_embedded_sbom_requires_archive_and_member_digest(self):
        data = self.wheel(member=SBOM_MEMBER, member_data=b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}')
        digest = hashlib.sha256(data).hexdigest()
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            member_hash = hashlib.sha256(z.read(SBOM_MEMBER)).hexdigest()
        self.assertIsNotNone(embedded_sbom_summary(data, digest, member_hash))
        self.assertIsNone(embedded_sbom_summary(data, digest, "0" * 64))
        self.assertIsNone(embedded_sbom_summary(data, "0" * 64, member_hash))
        absent = self.wheel()
        self.assertIsNone(embedded_sbom_summary(absent, hashlib.sha256(absent).hexdigest(), member_hash))


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]])
    elif len(sys.argv) == 3 and sys.argv[1] == "--inspect":
        result = inspect_path(sys.argv[2])
        print(result + "; independent attestation, license, advisory and lab review still required.")
        sys.exit(0 if result == "DigestAndMetadataMatch" else 2)
    elif len(sys.argv) == 3 and sys.argv[1] == "--inventory":
        try:
            evidence = inventory_bytes(read_candidate(sys.argv[2]), SHA256)
        except (OSError, ValueError):
            evidence = None
        if evidence is None:
            sys.exit("Candidate inventory unavailable; preflight required.")
        print(json.dumps(evidence, sort_keys=True, ensure_ascii=True))
    elif len(sys.argv) == 3 and sys.argv[1] == "--sbom-summary":
        try:
            evidence = embedded_sbom_summary(read_candidate(sys.argv[2]), SHA256, SBOM_SHA256)
        except (OSError, ValueError):
            evidence = None
        if evidence is None:
            sys.exit("Candidate SBOM summary unavailable; review required.")
        print(json.dumps(evidence, sort_keys=True, ensure_ascii=True))
    else:
        sys.exit("Use --self-test, --inspect, --inventory or --sbom-summary with the explicitly selected offline candidate.")
