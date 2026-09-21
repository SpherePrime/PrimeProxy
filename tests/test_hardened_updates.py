import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import utils.fast_download as _fdmod
from config import get_store, reset_cache
from utils import file_integrity, hardened_file_ops, versioning
from utils.fast_download import download, download_verified


class HardenedFileOpsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sp-hfo-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _path(self, name):
        return self.tmp / name

    def test_sha256_file_matches_streaming_hashlib(self):
        data = os.urandom(1024 * 1024 * 2 + 123)
        target = self._path("payload.bin")
        target.write_bytes(data)
        self.assertEqual(
            hardened_file_ops.sha256_file(target),
            hashlib.sha256(data).hexdigest(),
        )

    def test_sha256_file_empty_and_small(self):
        empty = self._path("empty.bin")
        empty.write_bytes(b"")
        self.assertEqual(hardened_file_ops.sha256_file(empty), hashlib.sha256(b"").hexdigest())
        small = self._path("small.bin")
        small.write_bytes(b"abc")
        self.assertEqual(hardened_file_ops.sha256_file(small), hashlib.sha256(b"abc").hexdigest())

    def test_atomic_write_bytes_exact_content_no_tmp_left(self):
        target = self._path("cfg.dat")
        hardened_file_ops.atomic_write_bytes(target, b"\x00\x01\xff\xfe")
        self.assertEqual(target.read_bytes(), b"\x00\x01\xff\xfe")
        self.assertEqual(list(self.tmp.glob("*.tmp")), [])

    def test_atomic_write_bytes_replaces_existing(self):
        target = self._path("cfg.dat")
        hardened_file_ops.atomic_write_bytes(target, b"one")
        hardened_file_ops.atomic_write_bytes(target, b"two")
        self.assertEqual(target.read_bytes(), b"two")
        self.assertEqual(list(self.tmp.glob("*.tmp")), [])

    def test_atomic_write_text_normalizes_newlines(self):
        target = self._path("note.txt")
        hardened_file_ops.atomic_write_text(target, "a\r\nb\r")
        self.assertEqual(target.read_text(encoding="utf-8"), "a\nb\n")

    def test_atomic_write_text_ensures_trailing_newline(self):
        target = self._path("note.txt")
        hardened_file_ops.atomic_write_text(target, "line")
        self.assertEqual(target.read_text(encoding="utf-8"), "line\n")

    def test_atomic_write_text_empty(self):
        target = self._path("note.txt")
        hardened_file_ops.atomic_write_text(target, "")
        self.assertEqual(target.read_text(encoding="utf-8"), "")

    def test_replace_file_safe_moves_and_overwrites(self):
        src = self._path("src.txt")
        dst = self._path("dst.txt")
        src.write_bytes(b"s")
        dst.write_bytes(b"d")
        hardened_file_ops.replace_file_safe(src, dst)
        self.assertFalse(src.exists())
        self.assertEqual(dst.read_bytes(), b"s")

    def test_safe_join_keeps_regular_paths(self):
        base = self._path("base")
        got = hardened_file_ops.safe_join(base, "sub", "file.txt")
        self.assertEqual(got, base / "sub" / "file.txt")
        self.assertNotIn("..", got.parts)

    def test_safe_join_allows_resolved_inside(self):
        base = self._path("base")
        got = hardened_file_ops.safe_join(base, "sub", "..", "a.txt")
        self.assertEqual(got.resolve(), base.resolve() / "a.txt")

    def test_safe_join_rejects_escape(self):
        base = self._path("base")
        outside = str(self.tmp.resolve())
        for parts in (("..",), ("../x",), ("a", "..", "..", "x"), (outside,), ("a", outside)):
            with self.subTest(parts=parts):
                with self.assertRaises(ValueError):
                    hardened_file_ops.safe_join(base, *parts)

    def test_verify_file_sha256(self):
        target = self._path("f.bin")
        target.write_bytes(b"data")
        good = hardened_file_ops.sha256_file(target)
        self.assertTrue(hardened_file_ops.verify_file_sha256(target, good))
        self.assertTrue(hardened_file_ops.verify_file_sha256(target, good.upper()))
        self.assertFalse(hardened_file_ops.verify_file_sha256(target, "0" * 64))
        self.assertFalse(hardened_file_ops.verify_file_sha256(target, None))
        self.assertFalse(hardened_file_ops.verify_file_sha256(self._path("missing.bin"), good))

    def test_compare_bytes(self):
        self.assertTrue(hardened_file_ops.compare_bytes(b"abc", b"abc"))
        self.assertTrue(hardened_file_ops.compare_bytes(bytearray(b"abc"), b"abc"))
        self.assertFalse(hardened_file_ops.compare_bytes(b"abc", b"abd"))
        self.assertFalse(hardened_file_ops.compare_bytes(b"abc", b"abcd"))
        self.assertFalse(hardened_file_ops.compare_bytes(None, b"abc"))
        self.assertFalse(hardened_file_ops.compare_bytes(b"abc", "abc"))

    def test_file_size(self):
        target = self._path("f.bin")
        target.write_bytes(b"12345")
        self.assertEqual(hardened_file_ops.file_size(target), 5)


class _FakeResp:
    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self.headers = {}

    def read(self, size=-1):
        return next(self._chunks, b"")

    def close(self):
        return None


class FastDownloadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sp-dl-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src"
        self.src.mkdir()
        self.dest = self.tmp / "dest.bin"

    def _source_uri(self, name, data):
        path = self.src / name
        path.write_bytes(data)
        return path.as_uri()

    def test_download_file_scheme(self):
        data = os.urandom(2048)
        url = self._source_uri("f.bin", data)
        res = download(url, self.dest, timeout=(1, 1))
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["size"], len(data))
        self.assertEqual(self.dest.read_bytes(), data)
        self.assertEqual(res["path"], str(self.dest))
        self.assertGreaterEqual(res["elapsed"], 0)

    def test_download_unreachable_reports_errors(self):
        res = download("http://127.0.0.1:9/x.json", self.dest, timeout=(1, 1))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "download_failed")
        self.assertEqual(len(res["errors"]), 2)
        self.assertFalse(self.dest.exists())

    def test_download_sha256_ok_and_mismatch(self):
        data = b"hello world"
        url = self._source_uri("h.bin", data)
        sha = hashlib.sha256(data).hexdigest()
        res = download(url, self.dest, sha256=sha, timeout=(1, 1))
        self.assertTrue(res["ok"], res)
        bad = download(url, self.dest, sha256="0" * 64, timeout=(1, 1))
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["error"], "checksum")

    def test_download_max_bytes_aborts(self):
        url = self._source_uri("big.bin", b"a" * 100)
        res = download(url, self.dest, max_bytes=50, timeout=(1, 1))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "size_limit")
        self.assertFalse(self.dest.exists())

    def test_download_cancelled_via_stop_event(self):
        event = threading.Event()
        with patch("utils.fast_download._open", return_value=_FakeResp([b"x" * 4096] * 20)):
            res = download(
                "file:///fake.bin",
                self.dest,
                timeout=(1, 1),
                progress_cb=lambda *_: event.set(),
                stop_event=event,
            )
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "cancelled")
        self.assertFalse(self.dest.exists())

    def test_download_retries_then_succeeds(self):
        original_open = _fdmod._open

        def flaky(url, timeout):
            flaky.calls += 1
            if flaky.calls == 1:
                raise URLError("transient")
            return original_open(url, timeout)

        flaky.calls = 0
        data = b"retry me"
        url = self._source_uri("r.bin", data)
        with patch("utils.fast_download._open", flaky):
            res = download(url, self.dest, timeout=(1, 1))
        self.assertTrue(res["ok"], res)
        self.assertEqual(flaky.calls, 2)
        self.assertEqual(self.dest.read_bytes(), data)

    def test_download_retries_exhausted(self):
        def always_fail(url, timeout):
            raise URLError("nope")

        with patch("utils.fast_download._open", always_fail):
            res = download("https://example.invalid/x.bin", self.dest, timeout=(1, 1))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "download_failed")
        self.assertEqual(len(res["errors"]), 2)
        for item in res["errors"]:
            self.assertIn("attempt", item)

    def test_download_cleans_part_files(self):
        url = self._source_uri("m.json", b"{}")
        res = download(url, self.dest, timeout=(1, 1))
        self.assertTrue(res["ok"])
        self.assertEqual(list(self.tmp.glob("*.part")), [])

    def test_download_verified_falls_back_to_next_url(self):
        good = self._source_uri("good.bin", b"2222")
        res = download_verified(
            ["http://127.0.0.1:9/a.bin", good],
            self.dest,
            timeout=(1, 1),
        )
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["url"], good)
        self.assertEqual(res["tried"], 2)
        self.assertEqual(self.dest.read_bytes(), b"2222")

    def test_download_verified_all_fail(self):
        res = download_verified(
            ["http://127.0.0.1:9/a.bin", "http://127.0.0.1:9/b.bin"],
            self.dest,
            timeout=(1, 1),
        )
        self.assertFalse(res["ok"])
        self.assertEqual(len(res["errors"]), 2)

    def test_download_progress_cb_reports_total_and_done(self):
        data = b"y" * 5000
        url = self._source_uri("p.bin", data)
        seen = []
        res = download(
            url,
            self.dest,
            timeout=(1, 1),
            progress_cb=lambda done, total: seen.append((done, total)),
        )
        self.assertTrue(res["ok"])
        self.assertEqual(sum(done for done, _ in seen), len(data))
        self.assertEqual(seen[-1], (len(data), len(data)))


class VersioningTest(unittest.TestCase):
    def test_parse_version_numbers(self):
        self.assertEqual(versioning.parse_version("1.9.1"), ((1, 9, 1), ""))
        self.assertEqual(versioning.parse_version("v2.0"), ((2,), ""))
        self.assertEqual(versioning.parse_version(" 1.9.1rc2 "), ((1, 9, 1), "rc2"))
        self.assertEqual(versioning.parse_version("2026.09.14"), ((2026, 9, 14), ""))

    def test_parse_version_odd_segments(self):
        self.assertEqual(versioning.parse_version("1.x.3"), ((1, 0, 3), ""))
        self.assertEqual(versioning.parse_version("1.9"), ((1, 9), ""))
        self.assertEqual(versioning.parse_version("1.9.0"), ((1, 9), ""))
        self.assertEqual(versioning.parse_version(""), ((0,), ""))

    def test_compare_equal_after_zero_trim(self):
        self.assertEqual(versioning.compare_versions("1.9", "1.9.0"), 0)
        self.assertEqual(versioning.compare_versions("v1.9.1", "1.9.1"), 0)

    def test_compare_ordering(self):
        self.assertGreater(versioning.compare_versions("1.9.2", "1.9.1"), 0)
        self.assertLess(versioning.compare_versions("1.9.1", "1.9.2"), 0)
        self.assertGreater(versioning.compare_versions("2.0", "1.9.9"), 0)

    def test_prerelease_is_older(self):
        self.assertLess(versioning.compare_versions("1.9.1rc2", "1.9.1"), 0)
        self.assertGreater(versioning.compare_versions("1.9.1", "1.9.1rc2"), 0)

    def test_is_newer(self):
        self.assertTrue(versioning.is_newer("1.9.2", "1.9.1"))
        self.assertTrue(versioning.is_newer("2.0", "1.9.9"))
        self.assertFalse(versioning.is_newer("1.9.0", "1.9"))
        self.assertFalse(versioning.is_newer("1.9.1rc1", "1.9.1"))


class FileIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sp-fi-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "payload"
        self.root.mkdir()
        (self.root / "a").mkdir()
        (self.root / "a" / "b.txt").write_bytes(b"bee")
        (self.root / "c.txt").write_bytes(b"see")

    def test_snapshot_dir_hashes_files(self):
        snaps = file_integrity.snapshot_dir(self.root)
        self.assertEqual(set(snaps.keys()), {"a/b.txt", "c.txt"})
        self.assertEqual(snaps["a/b.txt"], hashlib.sha256(b"bee").hexdigest())

    def test_manifest_roundtrip_ok(self):
        manifest_path = self.root / "manifest.json"
        file_integrity.write_manifest(self.root, manifest_path)
        result = file_integrity.verify_manifest(self.root, manifest_path)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tampered"], [])
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["added"], [])
        self.assertTrue(all(c["status"] == "ok" for c in result["checks"]))

    def test_tampered_detected(self):
        manifest_path = self.root / "manifest.json"
        file_integrity.write_manifest(self.root, manifest_path)
        (self.root / "a" / "b.txt").write_bytes(b"evil")
        result = file_integrity.verify_manifest(self.root, manifest_path)
        self.assertFalse(result["ok"])
        self.assertIn("a/b.txt", result["tampered"])

    def test_missing_detected(self):
        manifest_path = self.root / "manifest.json"
        file_integrity.write_manifest(self.root, manifest_path)
        (self.root / "c.txt").unlink()
        result = file_integrity.verify_manifest(self.root, manifest_path)
        self.assertFalse(result["ok"])
        self.assertIn("c.txt", result["missing"])

    def test_added_detected(self):
        manifest_path = self.root / "manifest.json"
        file_integrity.write_manifest(self.root, manifest_path)
        (self.root / "extra.bin").write_bytes(b"new")
        result = file_integrity.verify_manifest(self.root, manifest_path)
        self.assertFalse(result["ok"])
        self.assertIn("extra.bin", result["added"])
        self.assertNotIn("manifest.json", result["added"])

    def test_fingerprint_engine_counts_known_files(self):
        engine = self.tmp / "engine"
        engine.mkdir()
        (engine / "winws.exe").write_bytes(b"exe-bytes")
        (engine / "WinDivert.dll").write_bytes(b"div")
        fp = file_integrity.fingerprint_engine(str(engine))
        names = [f["name"] for f in fp["files"]]
        self.assertEqual(len(fp["files"]), len(file_integrity.ENGINE_FINGERPRINT_FILES))
        self.assertEqual(names, list(file_integrity.ENGINE_FINGERPRINT_FILES))
        exe = next(f for f in fp["files"] if f["name"] == "winws.exe")
        self.assertTrue(exe["exists"])
        self.assertEqual(exe["sha256"], hashlib.sha256(b"exe-bytes").hexdigest())
        divert64 = next(f for f in fp["files"] if f["name"] == "WinDivert64.sys")
        self.assertFalse(divert64["exists"])
        self.assertIsNone(divert64["sha256"])
        self.assertEqual(
            fp["aggregate_hash"],
            file_integrity.fingerprint_engine(str(engine))["aggregate_hash"],
        )


class ManifestUpdateApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sp-upd-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.patch_app = patch("config.paths.app_dir", return_value=self.tmp / "app")
        self.patch_store_cfg = patch("config.store.config_file", return_value=self.tmp / "cfg" / "config.json")
        self.patch_paths_cfg = patch("config.paths.config_file", return_value=self.tmp / "cfg" / "config.json")
        self.patch_app.start()
        self.patch_store_cfg.start()
        self.patch_paths_cfg.start()
        self.addCleanup(self.patch_app.stop)
        self.addCleanup(self.patch_store_cfg.stop)
        self.addCleanup(self.patch_paths_cfg.stop)
        reset_cache()
        self.addCleanup(reset_cache)
        from ui.api import SwiftAPI

        self.api = SwiftAPI()

    def _await_status(self, deadline=10.0):
        t0 = time.monotonic()
        while time.monotonic() - t0 < deadline:
            st = self.api.get_updates_check_status()
            if st and st.get("status") != "running":
                return st
            time.sleep(0.02)
        return self.api.get_updates_check_status()

    def test_store_exposes_updates_and_integrity_sections(self):
        store = get_store()
        snapshot = store.snapshot()
        self.assertIn("updates", snapshot)
        self.assertIn("integrity", snapshot)
        self.assertEqual(store.get_updates()["source_url"], "")
        self.assertFalse(store.get_updates()["auto_check"])
        self.assertIsNone(store.get_updates()["last_check"])
        self.assertIsNone(store.get_integrity()["engine_baseline"])

    def test_set_update_source_validation(self):
        self.assertTrue(self.api.set_update_source("https://example.com/m.json")["ok"])
        self.assertTrue(self.api.set_update_source("http://example.com/m.json")["ok"])
        file_uri = (self.tmp / "src" / "m.json").as_uri()
        self.assertTrue(self.api.set_update_source(file_uri)["ok"])
        self.assertFalse(self.api.set_update_source("::::")["ok"])
        self.assertFalse(self.api.set_update_source("http://")["ok"])
        self.assertEqual(get_store().get("updates", "source_url"), file_uri)

    def test_set_auto_check_persists(self):
        self.api.set_auto_check(True)
        self.assertTrue(get_store().get("updates", "auto_check"))
        self.api.set_auto_check(False)
        self.assertFalse(get_store().get("updates", "auto_check"))

    def test_run_updates_check_no_source(self):
        self.assertTrue(self.api.run_updates_check()["ok"])
        st = self._await_status()
        result = (st or {}).get("result") or {}
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "no_source")

    def test_run_updates_check_with_manifest_applies(self):
        src = self.tmp / "src"
        src.mkdir()
        payload = b"swift-engine-binary" * 8
        (src / "winws2.bin").write_bytes(payload)
        manifest = {
            "version": "9.9.9",
            "files": [
                {
                    "path": "exe/winws2.bin",
                    "url": (src / "winws2.bin").as_uri(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            ],
        }
        (src / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.api.set_update_source((src / "manifest.json").as_uri())
        self.assertTrue(self.api.run_updates_check()["ok"])
        st = self._await_status()
        result = (st or {}).get("result") or {}
        self.assertTrue(result["ok"], result)
        self.assertIsNone(result["reason"])
        self.assertEqual(result["files_applied"], ["exe/winws2.bin"])
        dest = self.tmp / "app" / "updates" / "exe" / "winws2.bin"
        self.assertEqual(dest.read_bytes(), payload)
        self.assertIsNotNone(get_store().get("updates", "last_check"))

    def test_run_updates_check_rejects_escape_path(self):
        src = self.tmp / "src"
        src.mkdir()
        payload = b"evil"
        (src / "evil.bin").write_bytes(payload)
        manifest = {
            "version": "9.9.9",
            "files": [
                {
                    "path": "../escaped.bin",
                    "url": (src / "evil.bin").as_uri(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            ],
        }
        (src / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.api.set_update_source((src / "manifest.json").as_uri())
        self.assertTrue(self.api.run_updates_check()["ok"])
        st = self._await_status()
        result = (st or {}).get("result") or {}
        self.assertFalse(result["ok"])
        self.assertTrue(any(e.get("error") == "unsafe_path" for e in (result.get("errors") or [])))
        self.assertFalse((self.tmp / "escaped.bin").exists())

    def test_get_update_status_shape(self):
        st = self.api.get_update_status()
        self.assertIsInstance(st, dict)
        self.assertTrue(st.get("current"))
        self.assertIn("source_url", st)
        self.assertIn("last_check", st)
        self.assertIn("auto_check", st)
        self.assertIsInstance(st.get("engine_files_present"), bool)

    def test_engine_fingerprint_create_diff_reset(self):
        engine = self.tmp / "engine"
        engine.mkdir()
        (engine / "winws.exe").write_bytes(b"v1-exe")
        with patch("winws.paths.engine_dir", return_value=engine):
            created = self.api.engine_fingerprint(True)
            self.assertTrue(created.get("created"))
            self.assertIsNotNone(self.api._read_engine_baseline())
            ok_run = self.api.engine_fingerprint(True)
            self.assertTrue(ok_run.get("ok"), ok_run)
            self.assertEqual(ok_run.get("changed_files"), [])
            (engine / "winws.exe").write_bytes(b"tampered!")
            bad_run = self.api.engine_fingerprint(True)
            self.assertFalse(bad_run.get("ok"))
            self.assertIn("winws.exe", [f["name"] for f in (bad_run.get("changed_files") or [])])
            (engine / "WinDivert64.sys").write_bytes(b"n")
            added_run = self.api.engine_fingerprint(True)
            self.assertFalse(added_run.get("ok"))
            self.assertIn("WinDivert64.sys", [f["name"] for f in (added_run.get("added") or [])])
            self.api.reset_engine_baseline()
            self.assertIsNone(self.api._read_engine_baseline())
            no_baseline = self.api.engine_fingerprint(False)
            self.assertEqual(no_baseline.get("reason"), "no_baseline")
            again = self.api.engine_fingerprint(True)
            self.assertTrue(again.get("created"))


if __name__ == "__main__":
    unittest.main()