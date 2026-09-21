import unittest
from unittest import mock

import config.paths
from config.paths import _migrate_legacy_configs
from proxy.config import (
    CFPROXY_DEFAULT_DOMAINS,
    _is_valid_domain,
    _normalize_domain_pool,
    coerce_domain_list,
    parse_dc_ip_list,
)


class ParseDcIpListTest(unittest.TestCase):
    def test_parses_multiple_entries(self):
        self.assertEqual(
            parse_dc_ip_list(['2:149.154.167.220', '4:1.2.3.4']),
            {2: '149.154.167.220', 4: '1.2.3.4'},
        )

    def test_last_entry_wins_for_duplicate_dc(self):
        self.assertEqual(parse_dc_ip_list(['2:1.1.1.1', '2:2.2.2.2']), {2: '2.2.2.2'})

    def test_rejects_missing_separator(self):
        with self.assertRaises(ValueError) as ctx:
            parse_dc_ip_list(['2-1.2.3.4'])
        self.assertEqual(ctx.exception.kind, 'format')

    def test_rejects_short_form_ipv4(self):
        for entry in ('2:149.154', '2:1.2.3.4.5', '2:999.1.1.1', '2:abc'):
            with self.subTest(entry=entry), self.assertRaises(ValueError) as ctx:
                parse_dc_ip_list([entry])
            self.assertEqual(ctx.exception.kind, 'invalid')

    def test_rejects_non_numeric_dc(self):
        with self.assertRaises(ValueError):
            parse_dc_ip_list(['x:1.2.3.4'])


class CoerceDomainListTest(unittest.TestCase):
    def test_splits_on_common_separators(self):
        self.assertEqual(
            coerce_domain_list('a.com, b.com; c.com d.com'),
            ['a.com', 'b.com', 'c.com', 'd.com'],
        )

    def test_deduplicates_case_insensitively_keeping_first(self):
        self.assertEqual(coerce_domain_list(['A.com', 'a.com']), ['A.com'])

    def test_flattens_sequences_and_skips_non_strings(self):
        self.assertEqual(coerce_domain_list(['a.com b.com', 5, None]), ['a.com', 'b.com'])

    def test_returns_empty_for_unsupported_types(self):
        self.assertEqual(coerce_domain_list(None), [])
        self.assertEqual(coerce_domain_list(42), [])


class DomainValidationTest(unittest.TestCase):
    def test_accepts_ordinary_domains(self):
        for domain in ('example.com', 'a-b.co.uk', 'x.io'):
            self.assertTrue(_is_valid_domain(domain), domain)

    def test_rejects_malformed_domains(self):
        for domain in ('', 'nodot', '.leading.com', 'trailing.com.',
                       '-bad.com', 'bad-.com', 'a..com', 'a.1',
                       'a.' + 'b' * 64, 'a' * 250 + '.com'):
            self.assertFalse(_is_valid_domain(domain), domain)

    def test_normalize_lowercases_dedupes_and_drops_invalid(self):
        self.assertEqual(
            _normalize_domain_pool(['B.com ', 'b.com', 'nodot', 'a.com']),
            ['b.com', 'a.com'],
        )


class DefaultDomainsTest(unittest.TestCase):
    def test_decoded_defaults_are_valid_domains(self):
        self.assertTrue(CFPROXY_DEFAULT_DOMAINS)
        for domain in CFPROXY_DEFAULT_DOMAINS:
            self.assertTrue(_is_valid_domain(domain), domain)

    def test_decoded_defaults_are_unique(self):
        self.assertEqual(
            len(set(CFPROXY_DEFAULT_DOMAINS)), len(CFPROXY_DEFAULT_DOMAINS)
        )


class MigrateLegacyConfigsTest(unittest.TestCase):
    """Regression coverage for _migrate_legacy_configs.

    The documented behaviour: migration is **fill-only**. A legacy value is
    applied only when the target section field is absent, so values already
    saved in sectioned form (e.g. a MTProto port set in the new UI) survive a
    legacy config on disk. Flat legacy keys successfully moved into sections
    are dropped from the current config.
    """

    def tearDown(self):
        mock.patch.stopall()

    def _no_legacy_dirs(self):
        mock.patch.object(
            config.paths,
            "_legacy_app_dir",
            lambda name: mock.MagicMock(exists=lambda: False),
        ).start()

    def test_flat_legacy_keys_do_not_overwrite_sectioned_values(self):
        self._no_legacy_dirs()
        current = {
            "proxy": {"port": 19999, "secret": "7e83fd8bdd26be253b30961290edd638"},
            "port": 1443,
            "secret": "7aed2dd13a0c4362d218e71acb299394",
        }
        result = _migrate_legacy_configs(current)
        self.assertEqual(result["proxy"]["port"], 19999)
        self.assertEqual(result["proxy"]["secret"], "7e83fd8bdd26be253b30961290edd638")
        self.assertNotIn("port", result)
        self.assertNotIn("secret", result)

    def test_sectioned_values_win_over_legacy_appdir_values(self):
        current = {"proxy": {"port": 19999}}
        with mock.patch(
            "config.paths._legacy_app_dir",
            lambda name: mock.MagicMock(exists=lambda: True),
        ), mock.patch(
            "config.store.load_saved_json",
            return_value={"port": 1443, "secret": "f8f21362f1f535920d764d3f9cb7826c"},
        ):
            result = _migrate_legacy_configs(current)
        self.assertEqual(result["proxy"]["port"], 19999)
        self.assertEqual(result["proxy"]["secret"], "f8f21362f1f535920d764d3f9cb7826c")

    def test_fills_missing_fields_from_legacy_appdir(self):
        current = {}
        with mock.patch(
            "config.paths._legacy_app_dir",
            lambda name: mock.MagicMock(exists=lambda: True),
        ), mock.patch(
            "config.store.load_saved_json",
            return_value={"port": 1443, "secret": "f8f21362f1f535920d764d3f9cb7826c"},
        ):
            result = _migrate_legacy_configs(current)
        self.assertEqual(result["proxy"]["port"], 1443)
        self.assertEqual(result["proxy"]["secret"], "f8f21362f1f535920d764d3f9cb7826c")

    def test_flat_legacy_keys_move_into_section_when_field_missing(self):
        self._no_legacy_dirs()
        current = {"port": 1443, "secret": "f8f21362f1f535920d764d3f9cb7826c"}
        result = _migrate_legacy_configs(current)
        self.assertEqual(result["proxy"]["port"], 1443)
        self.assertEqual(result["proxy"]["secret"], "f8f21362f1f535920d764d3f9cb7826c")
        self.assertNotIn("port", result)
        self.assertNotIn("secret", result)


if __name__ == '__main__':
    unittest.main()
