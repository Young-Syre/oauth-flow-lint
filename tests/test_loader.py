"""Loading and validating a configuration."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from oauth_flow_lint.loader import ConfigError, load_file, load_text

MINIMAL = """
[client]
client_id = "c"
redirect_uris = ["https://app.example/cb"]

[provider]
name = "p"
issuer = "https://idp.example"
redirect_uri_matching = "exact"
"""


class Loading(unittest.TestCase):
    def test_minimal_configuration_loads(self):
        cfg = load_text(MINIMAL)
        self.assertEqual(cfg.client.client_id, "c")
        self.assertEqual(len(cfg.providers), 1)
        self.assertEqual(cfg.providers[0].name, "p")

    def test_defaults_are_conservative(self):
        cfg = load_text(MINIMAL)
        self.assertFalse(cfg.client.pkce.used)
        self.assertFalse(cfg.client.state.sent)
        self.assertEqual(cfg.client.state.source, "unknown")
        self.assertEqual(cfg.client.id_token_validation.jwks_source, "unknown")
        self.assertFalse(cfg.client.id_token_validation.signature_verified)

    def test_invalid_toml_is_exit_code_two_territory(self):
        with self.assertRaises(ConfigError) as ctx:
            load_text("[client\nbroken")
        self.assertIn("invalid TOML", str(ctx.exception))

    def test_a_missing_provider_is_an_error(self):
        with self.assertRaises(ConfigError) as ctx:
            load_text('[client]\nclient_id = "c"\n')
        self.assertIn("no provider configured", str(ctx.exception))

    def test_enumerations_are_validated_rather_than_defaulted(self):
        text = MINIMAL.replace('redirect_uri_matching = "exact"', 'redirect_uri_matching = "Exact"')
        with self.assertRaises(ConfigError) as ctx:
            load_text(text)
        self.assertIn("is not one of", str(ctx.exception))

    def test_wrong_type_is_reported_with_its_location(self):
        with self.assertRaises(ConfigError) as ctx:
            load_text(MINIMAL.replace('redirect_uris = ["https://app.example/cb"]', "redirect_uris = 3"))
        self.assertIn("client.redirect_uris", str(ctx.exception))

    def test_boolean_is_not_accepted_where_an_integer_is_expected(self):
        text = MINIMAL + "\n[client.state]\nentropy_bits = true\n"
        with self.assertRaises(ConfigError):
            load_text(text)

    def test_unknown_keys_are_reported_not_ignored(self):
        cfg = load_text(MINIMAL + '\n[client.pkce]\nusd = true\n')
        self.assertIn("client.pkce.usd", cfg.unknown_keys)

    def test_unknown_top_level_key_is_reported(self):
        cfg = load_text("nonsense = 1\n" + MINIMAL)
        self.assertIn("nonsense", cfg.unknown_keys)

    def test_unsupported_schema_version_is_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            load_text("schema = 99\n" + MINIMAL)
        self.assertIn("not supported", str(ctx.exception))

    def test_client_secret_literal_only_sets_presence(self):
        cfg = load_text(MINIMAL + '\n' )
        self.assertFalse(cfg.client.secret_present)
        cfg2 = load_text(MINIMAL.replace('client_id = "c"', 'client_id = "c"\nclient_secret = "REDACTED-TEST-VALUE"'))
        self.assertTrue(cfg2.client.secret_present)

    def test_several_providers_load_as_a_list(self):
        text = MINIMAL + """
[[providers]]
name = "q"
issuer = "https://other.example"
redirect_uri_matching = "prefix"
"""
        cfg = load_text(text)
        self.assertEqual([p.name for p in cfg.providers], ["p", "q"])
        self.assertTrue(cfg.multi_provider)
        self.assertEqual(cfg.loosest_matching, "prefix")

    def test_duplicate_provider_names_are_rejected(self):
        text = MINIMAL + '\n[[providers]]\nname = "p"\nissuer = "https://x.example"\n'
        with self.assertRaises(ConfigError) as ctx:
            load_text(text)
        self.assertIn("distinct", str(ctx.exception))


class DiscoveryDocument(unittest.TestCase):
    def test_a_url_is_refused_with_an_explanation(self):
        text = MINIMAL + '\ndiscovery_document = "https://idp.example/.well-known/openid-configuration"\n'
        with self.assertRaises(ConfigError) as ctx:
            load_text(text)
        message = str(ctx.exception)
        self.assertIn("looks like a URL", message)
        self.assertIn("never performs network requests", message)

    def test_a_relative_path_resolves_against_the_configuration_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "d.json").write_text(json.dumps({"issuer": "https://idp.example"}))
            (root / "c.toml").write_text(MINIMAL + '\ndiscovery_document = "./d.json"\n')
            cfg = load_file(root / "c.toml")
            self.assertEqual(cfg.providers[0].discovery["issuer"], "https://idp.example")

    def test_a_missing_file_is_reported_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "c.toml").write_text(MINIMAL + '\ndiscovery_document = "./absent.json"\n')
            with self.assertRaises(ConfigError) as ctx:
                load_file(root / "c.toml")
            self.assertIn("cannot read", str(ctx.exception))

    def test_malformed_json_is_reported_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "d.json").write_text("{not json")
            (root / "c.toml").write_text(MINIMAL + '\ndiscovery_document = "./d.json"\n')
            with self.assertRaises(ConfigError) as ctx:
                load_file(root / "c.toml")
            self.assertIn("not valid JSON", str(ctx.exception))

    def test_a_json_array_is_not_a_metadata_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "d.json").write_text("[]")
            (root / "c.toml").write_text(MINIMAL + '\ndiscovery_document = "./d.json"\n')
            with self.assertRaises(ConfigError):
                load_file(root / "c.toml")

    def test_an_unreadable_configuration_file_is_an_error(self):
        with self.assertRaises(ConfigError) as ctx:
            load_file("/nonexistent/path/to/config.toml")
        self.assertIn("cannot read", str(ctx.exception))


class DerivedProperties(unittest.TestCase):
    def test_an_spa_is_public_however_it_is_registered(self):
        cfg = load_text(MINIMAL.replace('client_id = "c"', 'client_id = "c"\nclient_type = "confidential"\napplication_type = "spa"'))
        self.assertTrue(cfg.client.is_public)

    def test_a_native_client_is_public_however_it_is_registered(self):
        cfg = load_text(MINIMAL.replace('client_id = "c"', 'client_id = "c"\nclient_type = "confidential"\napplication_type = "native"'))
        self.assertTrue(cfg.client.is_public)

    def test_a_server_side_web_client_can_be_confidential(self):
        cfg = load_text(MINIMAL.replace('client_id = "c"', 'client_id = "c"\nclient_type = "confidential"\napplication_type = "web"'))
        self.assertFalse(cfg.client.is_public)

    def test_openid_scope_implies_an_id_token(self):
        cfg = load_text(MINIMAL.replace('client_id = "c"', 'client_id = "c"\nscopes = ["openid"]'))
        self.assertTrue(cfg.client.requests_id_token)

    def test_hybrid_response_types_are_identified(self):
        cfg = load_text(MINIMAL.replace('client_id = "c"', 'client_id = "c"\nresponse_types = ["code id_token"]'))
        self.assertEqual(cfg.client.hybrid_response_types, ["code id_token"])
        self.assertTrue(cfg.client.uses_code)
        self.assertFalse(cfg.client.uses_implicit)

    def test_token_in_a_compound_response_type_is_implicit(self):
        cfg = load_text(MINIMAL.replace('client_id = "c"', 'client_id = "c"\nresponse_types = ["id_token token"]'))
        self.assertTrue(cfg.client.uses_implicit)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
