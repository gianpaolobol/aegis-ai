# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Offline, read-only preflight for a single candidate YARA-X Windows wheel.
Not an attestation verifier, package installer or approval to execute code.
"""
import hashlib
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
            names = [i.filename for i in items]
            if len(names) != len(set(n.casefold() for n in names)):
                return "InvalidArchive"
            for item in items:
                name = item.filename
                if (not name or name.startswith("/") or chr(92) in name or
                    ":" in name or any(p in ("", ".", "..") for p in name.rstrip("/").split("/")) or
                    stat.S_ISLNK(item.external_attr >> 16)):
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


def inspect_path(path):
    try:
        p = Path(path)
        if p.name != FILENAME or p.is_symlink() or not p.is_file():
            return "Unavailable"
        with p.open("rb") as f:
            if not stat.S_ISREG(__import__("os").fstat(f.fileno()).st_mode):
                return "Unavailable"
            data = f.read(MAX_WHEEL + 1)
        return inspect_bytes(data, SHA256)
    except (OSError, ValueError):
        return "Unavailable"


class Fixtures(unittest.TestCase):
    def wheel(self, name="yara-x", version="1.24.0", tag="cp39-abi3-win_amd64",
              extra="", member=None, record_mode="valid"):
        b = io.BytesIO()
        contents = {
            PREFIX + "METADATA": f"Name: {name}\nVersion: {version}\n{extra}\n".encode(),
            PREFIX + "WHEEL": f"Tag: {tag}\n\n".encode(),
        }
        if member:
            contents[member] = b"synthetic"
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
    def test_invalid_archive_and_size(self):
        self.assertEqual(self.check(b"not zip"), "InvalidArchive")
        self.assertEqual(inspect_bytes(b"x"*(MAX_WHEEL+1), ""), "InvalidSize")
    def test_missing_path(self):
        self.assertEqual(inspect_path("not-the-candidate.whl"), "Unavailable")
    def test_oversize_metadata(self):
        self.assertEqual(self.check(self.wheel(extra="Summary: " + "x"*MAX_METADATA)), "InvalidArchive")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]])
    elif len(sys.argv) == 3 and sys.argv[1] == "--inspect":
        result = inspect_path(sys.argv[2])
        print(result + "; independent attestation, license, advisory and lab review still required.")
        sys.exit(0 if result == "DigestAndMetadataMatch" else 2)
    else:
        sys.exit("Use --self-test or --inspect with the explicitly selected offline candidate.")
