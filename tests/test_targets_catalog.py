import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hosts import catalog_repository as repo
from blockcheck.targets import (
    get_catalog_target_domains,
    get_default_https_targets_domains,
    get_default_scan_domains,
)

_SCHEMA = """
CREATE TABLE services (
    service_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('dns','hosts')),
    sort_order INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    icon_name TEXT NOT NULL,
    icon_color TEXT
);
CREATE TABLE domains (
    domain_id INTEGER PRIMARY KEY,
    service_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    sort_order INTEGER NOT NULL
);
CREATE TABLE hosts_entries (
    entry_id INTEGER PRIMARY KEY,
    service_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    priority INTEGER NOT NULL
);
"""


def _synthetic(path: Path) -> None:
    connection = sqlite3.connect(str(path))
    try:
        connection.executescript(_SCHEMA)
        connection.executemany(
            "INSERT INTO services VALUES (?,?,?,?,?,?,?,?)",
            [
                ("dns.one", "One", "other", "dns", 1, 1, "i", None),
                ("dns.off", "Off", "other", "dns", 2, 0, "i", None),
                ("hosts.two", "Two", "other", "hosts", 3, 1, "i", None),
            ],
        )
        connection.executemany(
            "INSERT INTO domains VALUES (?,?,?,?)",
            [
                (1, "dns.one", "a.example.com", 0),
                (2, "dns.one", "b.Example.COM", 1),
                (3, "dns.off", "hidden.example.org", 0),
            ],
        )
        connection.executemany(
            "INSERT INTO hosts_entries VALUES (?,?,?,?,?)",
            [
                (1, "hosts.two", "cdn.Two.example", "127.0.0.1", 0),
                (2, "hosts.two", "cdn.two.example", "127.0.0.1", 1),
                (3, "dns.off", "off.example.net", "127.0.0.1", 0),
            ],
        )
        connection.commit()
    finally:
        connection.close()


class TestCatalogDomainNames(unittest.TestCase):
    def test_returns_enabled_only_sorted_lowercase(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cat.sqlite3"
            _synthetic(path)
            names = repo.catalog_domain_names(path)
        self.assertEqual(
            names,
            ["a.example.com", "b.example.com", "cdn.two.example"],
        )

    def test_returns_all_when_disabled_included(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cat.sqlite3"
            _synthetic(path)
            names = repo.catalog_domain_names(path, enabled_only=False)
        self.assertIn("hidden.example.org", names)
        self.assertIn("off.example.net", names)

    def test_missing_file_returns_empty(self):
        self.assertEqual(repo.catalog_domain_names(Path("no_such_file.sqlite3")), [])


class TestCatalogTargetDomains(unittest.TestCase):
    def test_real_catalog_loads(self):
        domains = get_catalog_target_domains()
        self.assertGreater(len(domains), 100)
        self.assertEqual(domains, sorted(domains))
        self.assertTrue(all(d == d.lower() for d in domains))

    def test_limit_applies(self):
        domains = get_catalog_target_domains(limit=10)
        self.assertLessEqual(len(domains), 10)

    def test_limit_zero_means_all(self):
        full = get_catalog_target_domains(limit=0)
        self.assertGreaterEqual(len(full), 100)

    def test_catalog_failure_returns_empty(self):
        with mock.patch(
            "hosts.catalog_repository.catalog_domain_names",
            side_effect=RuntimeError("boom"),
        ):
            self.assertEqual(get_catalog_target_domains(), [])


class TestDefaultScanDomains(unittest.TestCase):
    def test_merges_builtin_catalog_user_dedup(self):
        builtin = get_default_https_targets_domains()
        self.assertGreater(len(builtin), 10)
        with mock.patch(
            "hosts.catalog_repository.catalog_domain_names",
            return_value=["z.extra.example", builtin[0]],
        ), mock.patch(
            "blockcheck.targets.load_user_domains",
            return_value=["user.example", "z.extra.example"],
        ):
            out = get_default_scan_domains()
        self.assertEqual(out[0], builtin[0])
        self.assertIn("z.extra.example", out)
        self.assertIn("user.example", out)
        self.assertEqual(len(out), len(set(out)))


if __name__ == "__main__":
    unittest.main()