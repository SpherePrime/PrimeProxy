import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hosts import catalog as hcatalog
from hosts import catalog_repository as repo

_SCHEMA = """
CREATE TABLE catalog_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE services (
    service_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('direct','ai','other')),
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
CREATE TABLE dns_profiles (
    profile_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    sort_order INTEGER NOT NULL,
    enabled INTEGER NOT NULL
);
CREATE TABLE dns_answers (
    domain_id INTEGER NOT NULL,
    profile_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    priority INTEGER NOT NULL,
    PRIMARY KEY (domain_id, profile_id, ip_address)
);
"""


def _build_synthetic_db(
    path: Path,
    application_id: int = repo.CATALOG_APPLICATION_ID,
    schema_version: int = repo.CATALOG_SCHEMA_VERSION,
    meta_sha: "str | None" = None,
    catalog_version: str = "2000.01.01.1",
) -> None:
    connection = sqlite3.connect(str(path))
    try:
        connection.executescript(_SCHEMA)
        connection.execute(
            "INSERT INTO services VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("hosts.discord", "Discord", "direct", "hosts", 1, 1, "discord", None),
        )
        connection.execute(
            "INSERT INTO services VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("dns.claude", "Claude", "ai", "dns", 2, 1, "fa5s.robot", "#B39DDB"),
        )
        connection.execute(
            "INSERT INTO domains VALUES (?, ?, ?, ?)",
            (1, "dns.claude", "claude.ai", 1),
        )
        connection.execute(
            "INSERT INTO domains VALUES (?, ?, ?, ?)",
            (2, "dns.claude", "claudeusercontent.com", 2),
        )
        connection.execute(
            "INSERT INTO hosts_entries VALUES (?, ?, ?, ?, ?)",
            (1, "hosts.discord", "discord.com", "104.16.24.10", 1),
        )
        connection.execute(
            "INSERT INTO hosts_entries VALUES (?, ?, ?, ?, ?)",
            (2, "hosts.discord", "discord.gg", "104.16.24.11", 2),
        )
        content_sha = meta_sha if meta_sha is not None else repo.compute_content_sha256(connection)
        connection.executemany(
            "INSERT INTO catalog_meta (key, value) VALUES (?, ?)",
            [
                ("schema_version", str(schema_version)),
                ("catalog_version", catalog_version),
                ("content_sha256", content_sha),
            ],
        )
        connection.execute(f"PRAGMA application_id = {application_id}")
        connection.execute(f"PRAGMA user_version = {schema_version}")
        connection.commit()
    finally:
        connection.close()


class BundledCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = repo.catalog_path()
        try:
            cls.path.stat()
        except OSError:
            raise unittest.SkipTest("shipped catalog is not bundled in this checkout")

    def test_loads_real_catalog(self):
        catalog = repo.load_catalog(self.path)
        self.assertGreaterEqual(len(catalog.services), 50)
        self.assertEqual(len(catalog.service_order), len(catalog.services))
        self.assertTrue(catalog.catalog_version)
        self.assertEqual(len(catalog.content_sha256), 64)

    def test_hosts_service_uses_concrete_ips(self):
        catalog = repo.load_catalog(self.path)
        service = next(
            s for s in catalog.services.values() if s.kind == "hosts" and s.host_entries
        )
        connection = repo._connect_read_only(self.path)
        try:
            mapping = repo.get_service_domains(connection, service.service_id)
        finally:
            connection.close()
        self.assertEqual(mapping, dict(service.host_entries))

    def test_dns_service_uses_loopback(self):
        catalog = repo.load_catalog(self.path)
        service = next(
            s for s in catalog.services.values() if s.kind == "dns" and s.domains
        )
        connection = repo._connect_read_only(self.path)
        try:
            mapping = repo.get_service_domains(connection, service.service_id)
        finally:
            connection.close()
        self.assertEqual(set(mapping), set(service.domains))
        self.assertEqual(set(mapping.values()), {repo.DEFAULT_BLOCK_IP})

    def test_counter_tables(self):
        catalog = repo.load_catalog(self.path)
        connection = repo._connect_read_only(self.path)
        try:
            self.assertGreaterEqual(repo.count_services(connection), 50)
            self.assertGreater(repo.count_domains(connection), 0)
            self.assertGreater(repo.count_host_entries(connection), 0)
        finally:
            connection.close()


class SyntheticCatalogTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "hosts_catalog.sqlite3"

    def test_loads_synthetic_catalog(self):
        _build_synthetic_db(self.path)
        catalog = repo.load_catalog(self.path)
        self.assertEqual(("hosts.discord", "dns.claude"), catalog.service_order)
        self.assertEqual(catalog.services["dns.claude"].kind, "dns")
        self.assertEqual(catalog.services["hosts.discord"].kind, "hosts")

    def test_missing_file_raises(self):
        with self.assertRaises(repo.HostsCatalogError):
            repo.load_catalog(Path(self._tmp.name) / "absent.sqlite3")

    def test_wrong_application_id_raises(self):
        _build_synthetic_db(self.path, application_id=0xDEADBEEF)
        with self.assertRaises(repo.HostsCatalogError):
            repo.load_catalog(self.path)

    def test_wrong_schema_version_raises(self):
        _build_synthetic_db(self.path, schema_version=99)
        with self.assertRaises(repo.HostsCatalogError):
            repo.load_catalog(self.path)

    def test_tampered_meta_hash_raises(self):
        _build_synthetic_db(self.path, meta_sha="0" * 64)
        with self.assertRaises(repo.HostsCatalogError):
            repo.load_catalog(self.path)

    def test_compute_sha_matches_meta(self):
        _build_synthetic_db(self.path)
        connection = repo._connect_read_only(self.path)
        try:
            self.assertEqual(
                repo.compute_content_sha256(connection),
                repo.catalog_meta(connection)["content_sha256"],
            )
        finally:
            connection.close()

    def test_get_service_domains_kind_specific(self):
        _build_synthetic_db(self.path)
        connection = repo._connect_read_only(self.path)
        try:
            self.assertEqual(
                repo.get_service_domains(connection, "hosts.discord"),
                {"discord.com": "104.16.24.10", "discord.gg": "104.16.24.11"},
            )
            self.assertEqual(
                repo.get_service_domains(connection, "dns.claude"),
                {"claude.ai": "127.0.0.1", "claudeusercontent.com": "127.0.0.1"},
            )
            self.assertEqual(repo.get_service_domains(connection, "missing"), {})
        finally:
            connection.close()


def _base_fake_catalog() -> repo.HostsCatalog:
    return repo.HostsCatalog(
        catalog_version="2000.01.01.1",
        content_sha256="a0" * 32,
        services={
            "hosts.discord": repo.CatalogService(
                service_id="hosts.discord",
                name="Discord",
                category="direct",
                kind="hosts",
                sort_order=1,
                enabled=True,
                icon_name="discord",
                icon_color=None,
                domains=("discord.com", "discord.gg"),
                host_entries=(("discord.com", "104.16.24.10"), ("discord.gg", "104.16.24.11")),
            ),
            "dns.chatgpt": repo.CatalogService(
                service_id="dns.chatgpt",
                name="ChatGPT",
                category="ai",
                kind="dns",
                sort_order=2,
                enabled=True,
                icon_name="fa5s.robot",
                icon_color="#7f7f7f",
                domains=("chatgpt.com", "openai.com"),
                host_entries=(),
            ),
            "dns.streaming": repo.CatalogService(
                service_id="dns.streaming",
                name="Streaming",
                category="other",
                kind="dns",
                sort_order=3,
                enabled=True,
                icon_name="",
                icon_color=None,
                domains=("stream.com",),
                host_entries=(),
            ),
        },
        service_order=("hosts.discord", "dns.chatgpt", "dns.streaming"),
    )


class CatalogApiTest(unittest.TestCase):
    def setUp(self):
        self._variant = 0
        self._load_patch = mock.patch.object(
            repo,
            "load_catalog",
            side_effect=lambda _path: self._variant_fake(),
        )
        self._load_patch.start()
        self.addCleanup(self._load_patch.stop)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        resource = Path(self._tmp.name) / "resource.sqlite3"
        resource.write_bytes(b"x")
        self._path_patch = mock.patch.object(repo, "catalog_path", return_value=resource)
        self._path_patch.start()
        self.addCleanup(self._path_patch.stop)
        hcatalog.invalidate_catalog_cache()
        self.addCleanup(hcatalog.invalidate_catalog_cache)

    def _variant_fake(self) -> repo.HostsCatalog:
        fake = _base_fake_catalog()
        if self._variant:
            fake.services["dns.jetbrains"] = repo.CatalogService(
                service_id="dns.jetbrains",
                name="JetBrains",
                category="other",
                kind="dns",
                sort_order=4,
                enabled=True,
                icon_name="",
                icon_color=None,
                domains=("jetbrains.com",),
                host_entries=(),
            )
            fake.service_order = tuple(list(fake.service_order) + ["dns.jetbrains"])
        return fake

    def test_snapshot_shape_and_custom_services(self):
        snapshot = hcatalog.services_snapshot()
        ids = [row["id"] for row in snapshot]
        self.assertIn("hosts.discord", ids)
        self.assertIn("adobe", ids)
        self.assertIn("windows-telemetry", ids)
        for row in snapshot:
            for key in ("id", "name", "mode", "type", "category", "icon", "domain_count", "domains"):
                self.assertIn(key, row)
        discord = next(row for row in snapshot if row["id"] == "hosts.discord")
        self.assertEqual(discord["category"], "direct")
        self.assertEqual(discord["type"], "hosts")
        self.assertEqual(discord["domain_count"], 2)
        self.assertEqual(sorted(discord["domains"]), ["discord.com", "discord.gg"])

    def test_service_domains_normalizes_legacy_ids(self):
        self.assertEqual(hcatalog.service_domains("discord")["discord.com"], "104.16.24.10")
        self.assertEqual(hcatalog.service_domains("youtube"), {})
        self.assertNotEqual(hcatalog.service_domains("dns.chatgpt"), {})

    def test_merge_plus_adobe(self):
        merged = hcatalog.merge_service_domains(["discord", "dns.chatgpt"], adobe=True)
        self.assertIn("discord.com", merged)
        self.assertIn("chatgpt.com", merged)
        self.assertIn("wip4.adobe.com", merged)
        without = hcatalog.merge_service_domains(["discord"], adobe=False)
        self.assertNotIn("wip4.adobe.com", without)

    def test_merge_ignores_unknown_and_empty(self):
        self.assertEqual(hcatalog.merge_service_domains([]), {})
        self.assertEqual(hcatalog.merge_service_domains([None, "steam", "  "]), {})

    def test_normalize_service_ids(self):
        self.assertEqual(
            hcatalog.normalize_service_ids(
                ["discord", "x", "instagram", "youtube", "notion", "xgboost", "twitch"]
            ),
            [
                "hosts.discord",
                "hosts.x_twitter",
                "hosts.instagram",
                "hosts.youtube",
                "dns.notion",
                "dns.microsoft_copilot_designer_xbox",
                "dns.twitch",
            ],
        )
        self.assertEqual(hcatalog.normalize_service_ids(None), [])
        self.assertEqual(hcatalog.normalize_service_ids([" ", 3, "discord", "discord"]), ["hosts.discord"])

    def test_catalog_signature_stable(self):
        first = hcatalog.catalog_signature()
        second = hcatalog.catalog_signature()
        self.assertEqual(first, second)
        self.assertGreater(first[1], 0)

    def test_catalog_signature_changes_with_content(self):
        before = hcatalog.catalog_signature()
        self._variant = 1
        hcatalog.invalidate_catalog_cache()
        after = hcatalog.catalog_signature()
        self.assertNotEqual(before, after)


class FallbackCatalogApiTest(unittest.TestCase):
    def setUp(self):
        self._path_patch = mock.patch.object(
            repo,
            "catalog_path",
            return_value=Path("Q:/nonexistent/hosts_catalog.sqlite3"),
        )
        self._path_patch.start()
        self.addCleanup(self._path_patch.stop)
        self._load_patch = mock.patch.object(
            repo,
            "load_catalog",
            side_effect=repo.HostsCatalogError("no catalog file"),
        )
        self._load_patch.start()
        self.addCleanup(self._load_patch.stop)
        hcatalog.invalidate_catalog_cache()
        self.addCleanup(hcatalog.invalidate_catalog_cache)

    def test_snapshot_from_static_fallback(self):
        snapshot = hcatalog.services_snapshot()
        ids = [row["id"] for row in snapshot]
        self.assertIn("discord", ids)
        self.assertIn("adobe", ids)
        self.assertIn("windows-telemetry", ids)
        self.assertGreaterEqual(len(snapshot), 14)

    def test_legacy_normalization_against_fallback(self):
        self.assertIn("discord.gg", hcatalog.service_domains("discord"))
        self.assertEqual(hcatalog.service_domains("youtube")["youtu.be"], "127.0.0.1")

    def test_merge_fallback(self):
        merged = hcatalog.merge_service_domains(["discord", "youtube"])
        self.assertIn("discord.com", merged)
        self.assertIn("youtube.com", merged)
        self.assertNotIn("lmlicenses.wip4.adobe.com", merged)
        with_adobe = hcatalog.merge_service_domains(["discord"], adobe=True)
        self.assertIn("wip4.adobe.com", with_adobe)

    def test_fallback_adobe_has_full_domain_list(self):
        adobe = hcatalog.service_domains("adobe")
        self.assertGreater(len(adobe), 100)


if __name__ == "__main__":
    unittest.main()