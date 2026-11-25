# Copyright 2026 Gian Paolo Franceschini. See LICENSE.
"""Offline, read-only preflight for a single candidate YARA-X Windows wheel.
Not an attestation verifier, package installer or approval to execute code.
"""
import hashlib
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
PREFIX = "yara_x-1.24.0.dist-info/"


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
              extra="", member=None):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr(PREFIX + "METADATA", f"Name: {name}\nVersion: {version}\n{extra}\n")
            z.writestr(PREFIX + "WHEEL", f"Tag: {tag}\n\n")
            if member:
                z.writestr(member, "synthetic")
        return b.getvalue()
    def check(self, data):
        return inspect_bytes(data, hashlib.sha256(data).hexdigest())
    def test_match_is_not_approval(self):
        self.assertEqual(self.check(self.wheel()), "DigestAndMetadataMatch")
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
