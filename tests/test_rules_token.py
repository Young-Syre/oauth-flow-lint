"""Token and ID token validation rules: TK001 - TK014."""

from __future__ import annotations

import unittest

from oauth_flow_lint.findings import Severity
from oauth_flow_lint.model import IdTokenValidation, TokenHandling
from tests.helpers import config, detail_of, fired, hardened_client, hardened_provider, severity_of


def with_validation(**kw):
    base = {
        "signature_verified": True,
        "alg_pinned": True,
        "accepted_algs": ["RS256"],
        "accepts_none_alg": False,
        "aud_checked": True,
        "iss_checked": True,
        "exp_checked": True,
        "azp_checked": True,
        "jwks_source": "pinned",
        "jwks_host_pinned": True,
        "expected_audiences": ["test-client"],
    }
    base.update(kw)
    return config(client=hardened_client(id_token_validation=IdTokenValidation(**base)))


def with_tokens(**kw):
    base = {
        "access_token_transport": "header",
        "refresh_token_issued": True,
        "refresh_token_rotation": True,
        "access_token_lifetime_seconds": 600,
        "refresh_token_lifetime_seconds": 2592000,
        "browser_storage": "server",
    }
    base.update(kw)
    return config(client=hardened_client(tokens=TokenHandling(**base)))


class IdTokenValidationRules(unittest.TestCase):
    def test_unverified_signature_is_critical(self):
        cfg = with_validation(signature_verified=False)
        self.assertEqual(severity_of(cfg, "TK001"), Severity.CRITICAL)

    def test_tk001_names_the_subject_claim(self):
        self.assertIn("sub", detail_of(with_validation(signature_verified=False), "TK001"))

    def test_unpinned_algorithm_fires_tk002(self):
        cfg = with_validation(alg_pinned=False)
        self.assertIn("TK002", fired(cfg))
        self.assertIn("HMAC-SHA256", detail_of(cfg, "TK002"))

    def test_pinned_without_a_recorded_algorithm_is_only_low(self):
        cfg = with_validation(alg_pinned=True, accepted_algs=[])
        self.assertEqual(severity_of(cfg, "TK002"), Severity.LOW)

    def test_accepting_none_is_critical(self):
        cfg = with_validation(accepts_none_alg=True)
        self.assertEqual(severity_of(cfg, "TK003"), Severity.CRITICAL)

    def test_none_on_the_allow_list_is_also_tk003(self):
        cfg = with_validation(accepted_algs=["RS256", "none"])
        self.assertIn("TK003", fired(cfg))

    def test_none_is_matched_case_insensitively(self):
        self.assertIn("TK003", fired(with_validation(accepted_algs=["None"])))

    def test_unchecked_audience_fires_tk004(self):
        cfg = with_validation(aud_checked=False)
        self.assertIn("TK004", fired(cfg))
        self.assertIn("different client", detail_of(cfg, "TK004"))

    def test_checked_audience_with_nothing_recorded_is_low(self):
        cfg = with_validation(aud_checked=True, expected_audiences=[])
        self.assertEqual(severity_of(cfg, "TK004"), Severity.LOW)

    def test_an_audience_list_without_the_client_id_is_reported(self):
        cfg = with_validation(expected_audiences=["someone-else"])
        self.assertIn("TK004", fired(cfg))
        self.assertIn("test-client", detail_of(cfg, "TK004"))

    def test_unchecked_issuer_fires_tk005(self):
        self.assertIn("TK005", fired(with_validation(iss_checked=False)))

    def test_unchecked_expiry_fires_tk014(self):
        cfg = with_validation(exp_checked=False)
        self.assertIn("TK014", fired(cfg))
        self.assertEqual(severity_of(cfg, "TK014"), Severity.HIGH)

    def test_multiple_audiences_without_azp_fires_tk006(self):
        cfg = with_validation(expected_audiences=["test-client", "sibling"], azp_checked=False)
        self.assertIn("TK006", fired(cfg))

    def test_a_single_audience_does_not_need_azp(self):
        cfg = with_validation(expected_audiences=["test-client"], azp_checked=False)
        self.assertNotIn("TK006", fired(cfg))

    def test_a_client_with_no_id_token_skips_these_rules(self):
        cfg = config(
            client=hardened_client(
                scopes=["profile"],
                stated_purpose_scopes=["profile"],
                id_token_validation=IdTokenValidation(),
            )
        )
        f = fired(cfg)
        for rule in ("TK001", "TK002", "TK003", "TK004", "TK005", "TK014"):
            self.assertNotIn(rule, f, rule)


class KeyResolution(unittest.TestCase):
    def test_keys_from_the_token_header_is_critical(self):
        cfg = with_validation(jwks_source="token_header")
        self.assertEqual(severity_of(cfg, "TK007"), Severity.CRITICAL)
        self.assertIn("jku", detail_of(cfg, "TK007"))

    def test_discovery_without_a_pinned_host_fires_tk008(self):
        cfg = with_validation(jwks_source="discovery", jwks_host_pinned=False)
        self.assertEqual(severity_of(cfg, "TK008"), Severity.MEDIUM)

    def test_discovery_with_a_pinned_host_is_accepted(self):
        cfg = with_validation(jwks_source="discovery", jwks_host_pinned=True)
        self.assertNotIn("TK008", fired(cfg))

    def test_an_unestablished_key_source_is_raised_to_high(self):
        cfg = with_validation(jwks_source="unknown")
        self.assertEqual(severity_of(cfg, "TK008"), Severity.HIGH)
        self.assertIn("most load-bearing fact", detail_of(cfg, "TK008"))


class Transport(unittest.TestCase):
    def test_token_in_the_query_fires_tk009(self):
        cfg = with_tokens(access_token_transport="query")
        self.assertEqual(severity_of(cfg, "TK009"), Severity.HIGH)

    def test_an_unestablished_transport_is_only_low(self):
        cfg = with_tokens(access_token_transport="unknown")
        self.assertEqual(severity_of(cfg, "TK009"), Severity.LOW)

    def test_the_header_is_clean(self):
        self.assertNotIn("TK009", fired(config()))


class RefreshTokens(unittest.TestCase):
    def test_public_client_without_rotation_fires_tk010(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="spa",
                secret_present=False,
                tokens=TokenHandling(refresh_token_issued=True, refresh_token_rotation=False, refresh_token_lifetime_seconds=3600, access_token_lifetime_seconds=600),
            )
        )
        self.assertIn("TK010", fired(cfg))

    def test_a_confidential_client_without_rotation_does_not_fire_tk010(self):
        cfg = with_tokens(refresh_token_rotation=False)
        self.assertNotIn("TK010", fired(cfg))

    def test_a_public_client_with_rotation_does_not_fire_tk010(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="spa",
                secret_present=False,
                tokens=TokenHandling(refresh_token_issued=True, refresh_token_rotation=True, refresh_token_lifetime_seconds=3600, access_token_lifetime_seconds=600),
            )
        )
        self.assertNotIn("TK010", fired(cfg))

    def test_unbounded_refresh_lifetime_fires_tk012(self):
        self.assertIn("TK012", fired(with_tokens(refresh_token_lifetime_seconds=0)))

    def test_no_refresh_token_means_no_refresh_rules(self):
        cfg = with_tokens(refresh_token_issued=False, refresh_token_lifetime_seconds=0)
        f = fired(cfg)
        self.assertNotIn("TK010", f)
        self.assertNotIn("TK012", f)


class AccessTokenLifetime(unittest.TestCase):
    def test_unset_lifetime_on_a_browser_client_fires_tk011(self):
        self.assertIn("TK011", fired(with_tokens(access_token_lifetime_seconds=0)))

    def test_an_excessive_lifetime_fires_tk011(self):
        cfg = with_tokens(access_token_lifetime_seconds=86400)
        self.assertIn("TK011", fired(cfg))
        self.assertIn("86400", detail_of(cfg, "TK011"))

    def test_a_short_lifetime_is_clean(self):
        self.assertNotIn("TK011", fired(with_tokens(access_token_lifetime_seconds=300)))

    def test_the_ceiling_does_not_apply_to_a_native_client(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="native",
                secret_present=False,
                tokens=TokenHandling(access_token_lifetime_seconds=86400, refresh_token_issued=False),
            )
        )
        self.assertNotIn("TK011", fired(cfg))


class Storage(unittest.TestCase):
    def test_localstorage_fires_tk013(self):
        cfg = with_tokens(browser_storage="localstorage")
        self.assertIn("TK013", fired(cfg))
        self.assertIn("cross-site scripting", detail_of(cfg, "TK013"))

    def test_sessionstorage_fires_tk013(self):
        self.assertIn("TK013", fired(with_tokens(browser_storage="sessionstorage")))

    def test_memory_and_server_storage_are_clean(self):
        self.assertNotIn("TK013", fired(with_tokens(browser_storage="memory")))
        self.assertNotIn("TK013", fired(with_tokens(browser_storage="server")))


class IssuerScheme(unittest.TestCase):
    def test_an_http_issuer_is_reported_against_the_issuer_comparison(self):
        cfg = config(providers=[hardened_provider(issuer="http://idp.example")])
        f = fired(cfg)
        self.assertIn("TK005", f)
        self.assertIn("PV001", f)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
