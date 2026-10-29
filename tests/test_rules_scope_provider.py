"""Scope rules (SC001 - SC003) and provider/discovery rules (PV001 - PV010)."""

from __future__ import annotations

import unittest

from oauth_flow_lint.findings import Severity
from tests.helpers import config, detail_of, fired, hardened_client, hardened_provider, severity_of

GOOD_METADATA = {
    "issuer": "https://idp.example",
    "authorization_endpoint": "https://idp.example/authorize",
    "token_endpoint": "https://idp.example/token",
    "jwks_uri": "https://idp.example/jwks",
    "response_types_supported": ["code"],
    "response_modes_supported": ["query", "form_post"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    "code_challenge_methods_supported": ["S256"],
    "request_uri_parameter_supported": False,
}


def with_metadata(**overrides):
    doc = dict(GOOD_METADATA)
    doc.update(overrides)
    return config(providers=[hardened_provider(discovery=doc, discovery_path="<test>.json")])


class Scope(unittest.TestCase):
    def test_offline_access_outside_the_stated_purpose_fires_sc001(self):
        cfg = config(
            client=hardened_client(
                scopes=["openid", "offline_access"], stated_purpose_scopes=["openid"]
            )
        )
        self.assertIn("SC001", fired(cfg))

    def test_offline_access_inside_the_stated_purpose_is_accepted(self):
        cfg = config(
            client=hardened_client(
                scopes=["openid", "offline_access"],
                stated_purpose_scopes=["openid", "offline_access"],
            )
        )
        self.assertNotIn("SC001", fired(cfg))

    def test_a_provider_granting_offline_access_unasked_fires_sc001(self):
        cfg = config(providers=[hardened_provider(grants_offline_access_without_request=True)])
        self.assertIn("SC001", fired(cfg))

    def test_a_scope_beyond_the_stated_purpose_fires_sc002(self):
        cfg = config(
            client=hardened_client(
                scopes=["openid", "profile", "mail:read"],
                stated_purpose_scopes=["openid", "profile"],
            )
        )
        self.assertIn("SC002", fired(cfg))
        self.assertIn("mail:read", detail_of(cfg, "SC002"))

    def test_no_stated_purpose_means_no_sc002(self):
        cfg = config(
            client=hardened_client(scopes=["openid", "mail:read"], stated_purpose_scopes=[])
        )
        self.assertNotIn("SC002", fired(cfg))

    def test_missing_reconsent_fires_sc003(self):
        cfg = config(client=hardened_client(scope_change_reconsent=False))
        self.assertIn("SC003", fired(cfg))

    def test_reconsent_enabled_is_clean(self):
        self.assertNotIn("SC003", fired(config()))


class ProviderDeclarations(unittest.TestCase):
    def test_open_registration_fires_pv006(self):
        cfg = config(providers=[hardened_provider(dynamic_client_registration="open")])
        self.assertIn("PV006", fired(cfg))
        self.assertEqual(severity_of(cfg, "PV006"), Severity.HIGH)

    def test_protected_registration_does_not_fire_pv006(self):
        cfg = config(providers=[hardened_provider(dynamic_client_registration="protected")])
        self.assertNotIn("PV006", fired(cfg))

    def test_request_uri_support_fires_pv007(self):
        cfg = config(providers=[hardened_provider(supports_request_uri=True)])
        self.assertIn("PV007", fired(cfg))
        self.assertIn("does not exercise it", detail_of(cfg, "PV007"))

    def test_an_http_issuer_fires_pv001(self):
        cfg = config(providers=[hardened_provider(issuer="http://idp.example")])
        self.assertIn("PV001", fired(cfg))


class MetadataDocument(unittest.TestCase):
    def test_a_clean_document_adds_nothing(self):
        self.assertEqual(fired(with_metadata()), set())

    def test_an_http_endpoint_fires_pv001_and_names_it(self):
        cfg = with_metadata(token_endpoint="http://internal.idp.example/token")
        self.assertIn("PV001", fired(cfg))
        self.assertIn("token_endpoint=http://internal.idp.example/token", detail_of(cfg, "PV001"))

    def test_a_loopback_endpoint_in_metadata_is_not_flagged_as_insecure(self):
        cfg = with_metadata(introspection_endpoint="http://127.0.0.1:9000/introspect")
        self.assertNotIn("PV001", fired(cfg))

    def test_an_issuer_mismatch_fires_pv008(self):
        cfg = with_metadata(issuer="https://other.example")
        self.assertIn("PV008", fired(cfg))
        self.assertIn("https://other.example", detail_of(cfg, "PV008"))

    def test_a_foreign_jwks_host_fires_pv002(self):
        cfg = with_metadata(jwks_uri="https://keys.cdn.example/jwks")
        self.assertIn("PV002", fired(cfg))
        self.assertIn("keys.cdn.example", detail_of(cfg, "PV002"))

    def test_a_jwks_uri_on_the_issuer_host_is_clean(self):
        self.assertNotIn("PV002", fired(with_metadata(jwks_uri="https://idp.example/keys/jwks")))

    def test_auth_method_none_with_a_confidential_client_is_medium(self):
        cfg = with_metadata(token_endpoint_auth_methods_supported=["client_secret_basic", "none"])
        self.assertEqual(severity_of(cfg, "PV003"), Severity.MEDIUM)

    def test_auth_method_none_with_no_confidential_client_is_only_low(self):
        doc = dict(GOOD_METADATA)
        doc["token_endpoint_auth_methods_supported"] = ["none"]
        cfg = config(
            client=hardened_client(client_type="public", application_type="spa", secret_present=False),
            providers=[hardened_provider(discovery=doc)],
        )
        self.assertEqual(severity_of(cfg, "PV003"), Severity.LOW)

    def test_absent_pkce_methods_fires_pv005(self):
        doc = dict(GOOD_METADATA)
        del doc["code_challenge_methods_supported"]
        cfg = config(providers=[hardened_provider(discovery=doc)])
        self.assertIn("PV005", fired(cfg))

    def test_pkce_methods_without_s256_fires_pv010(self):
        cfg = with_metadata(code_challenge_methods_supported=["plain"])
        self.assertIn("PV010", fired(cfg))

    def test_plain_in_the_metadata_fires_fl011(self):
        cfg = with_metadata(code_challenge_methods_supported=["S256", "plain"])
        self.assertIn("FL011", fired(cfg))

    def test_fragment_response_mode_offered_but_unused_fires_pv004(self):
        cfg = with_metadata(response_modes_supported=["query", "fragment"])
        self.assertIn("PV004", fired(cfg))
        self.assertEqual(severity_of(cfg, "PV004"), Severity.INFO)

    def test_fragment_response_mode_is_not_reported_when_a_client_uses_implicit(self):
        doc = dict(GOOD_METADATA)
        doc["response_modes_supported"] = ["query", "fragment"]
        cfg = config(
            client=hardened_client(response_types=["token"], response_mode="fragment"),
            providers=[hardened_provider(discovery=doc)],
        )
        self.assertNotIn("PV004", fired(cfg))

    def test_token_bearing_response_types_fire_pv009(self):
        cfg = with_metadata(response_types_supported=["code", "id_token token"])
        self.assertIn("PV009", fired(cfg))

    def test_a_registration_endpoint_contradicting_the_configuration_fires_pv006(self):
        cfg = with_metadata(registration_endpoint="https://idp.example/register")
        self.assertIn("PV006", fired(cfg))
        self.assertEqual(severity_of(cfg, "PV006"), Severity.MEDIUM)

    def test_metadata_contradicting_request_uri_support_fires_pv007(self):
        cfg = with_metadata(request_uri_parameter_supported=True)
        self.assertIn("PV007", fired(cfg))
        self.assertIn("server's own statement", detail_of(cfg, "PV007"))

    def test_unexpected_metadata_types_do_not_crash_the_checks(self):
        cfg = with_metadata(
            response_modes_supported="query",
            token_endpoint_auth_methods_supported=None,
            code_challenge_methods_supported={"S256": True},
            jwks_uri=42,
        )
        fired(cfg)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
