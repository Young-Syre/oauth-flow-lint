"""Flow and grant rules: FL001 - FL011."""

from __future__ import annotations

import unittest

from oauth_flow_lint.findings import Severity
from oauth_flow_lint.model import PKCE
from tests.helpers import config, detail_of, fired, hardened_client, hardened_provider, severity_of


def client(**kw):
    return config(client=hardened_client(**kw))


class ImplicitAndHybrid(unittest.TestCase):
    def test_response_type_token_fires_fl001(self):
        self.assertIn("FL001", fired(client(response_types=["token"])))

    def test_id_token_token_fires_fl001(self):
        cfg = client(response_types=["id_token token"], nonce=hardened_client().nonce)
        self.assertIn("FL001", fired(cfg))

    def test_id_token_alone_is_not_implicit_for_this_rule(self):
        self.assertNotIn("FL001", fired(client(response_types=["id_token"])))

    def test_code_alone_does_not_fire_fl001(self):
        self.assertNotIn("FL001", fired(config()))

    def test_implicit_on_a_native_client_also_fires_fl007(self):
        cfg = client(
            response_types=["token"], client_type="public", application_type="native"
        )
        f = fired(cfg)
        self.assertIn("FL007", f)
        self.assertIn("FL001", f)

    def test_implicit_on_a_web_client_does_not_fire_fl007(self):
        self.assertNotIn("FL007", fired(client(response_types=["token"])))

    def test_hybrid_code_id_token_fires_fl002_at_medium(self):
        cfg = client(response_types=["code id_token"])
        self.assertEqual(severity_of(cfg, "FL002"), Severity.MEDIUM)
        self.assertIn("replayable identity assertion", detail_of(cfg, "FL002"))

    def test_hybrid_carrying_a_token_is_raised_to_high(self):
        cfg = client(response_types=["code token"])
        self.assertEqual(severity_of(cfg, "FL002"), Severity.HIGH)
        self.assertIn("leaks exactly as it does in the implicit flow", detail_of(cfg, "FL002"))

    def test_hybrid_is_not_reported_for_a_pure_code_flow(self):
        self.assertNotIn("FL002", fired(config()))


class Pkce(unittest.TestCase):
    def test_public_client_without_pkce_is_high(self):
        cfg = config(
            client=hardened_client(
                client_type="public", application_type="spa", secret_present=False, pkce=PKCE(used=False)
            )
        )
        self.assertEqual(severity_of(cfg, "FL003"), Severity.HIGH)

    def test_confidential_client_without_pkce_is_graded_lower(self):
        cfg = client(pkce=PKCE(used=False))
        self.assertEqual(severity_of(cfg, "FL003"), Severity.LOW)
        self.assertIn("client secret still stands", detail_of(cfg, "FL003"))

    def test_plain_method_fires_fl004(self):
        cfg = config(
            client=hardened_client(pkce=PKCE(used=True, method="plain")),
            providers=[hardened_provider(pkce_methods=["S256", "plain"])],
        )
        self.assertIn("FL004", fired(cfg))

    def test_s256_does_not_fire_fl004(self):
        self.assertNotIn("FL004", fired(config()))

    def test_provider_not_enforcing_pkce_fires_fl005(self):
        cfg = config(providers=[hardened_provider(enforces_pkce=False)])
        self.assertIn("FL005", fired(cfg))

    def test_fl005_is_raised_to_high_for_a_public_client(self):
        cfg = config(
            client=hardened_client(client_type="public", application_type="spa", secret_present=False),
            providers=[hardened_provider(enforces_pkce=False)],
        )
        self.assertEqual(severity_of(cfg, "FL005"), Severity.HIGH)

    def test_fl005_says_the_client_side_control_is_not_in_the_attack_path(self):
        cfg = config(providers=[hardened_provider(enforces_pkce=False)])
        self.assertIn("not a control an attacker has to defeat", detail_of(cfg, "FL005"))

    def test_a_method_the_provider_does_not_advertise_fires_fl010(self):
        cfg = config(providers=[hardened_provider(pkce_methods=["plain"])])
        f = fired(cfg)
        self.assertIn("FL010", f)
        self.assertIn("FL011", f)

    def test_provider_advertising_plain_fires_fl011(self):
        cfg = config(providers=[hardened_provider(pkce_methods=["S256", "plain"])])
        self.assertIn("FL011", fired(cfg))

    def test_pkce_rules_do_not_apply_to_a_client_with_no_code_flow(self):
        cfg = config(
            client=hardened_client(
                response_types=["token"], grant_types=["implicit"], pkce=PKCE(used=False)
            ),
            providers=[hardened_provider(enforces_pkce=False, pkce_methods=["plain"])],
        )
        f = fired(cfg)
        for rule in ("FL003", "FL004", "FL005", "FL010", "FL011"):
            self.assertNotIn(rule, f, rule)


class Grants(unittest.TestCase):
    def test_password_grant_fires_fl006(self):
        cfg = client(grant_types=["authorization_code", "password"])
        self.assertIn("FL006", fired(cfg))
        self.assertIn("second factor", detail_of(cfg, "FL006"))

    def test_no_password_grant_does_not_fire_fl006(self):
        self.assertNotIn("FL006", fired(config()))


class ClientAuthentication(unittest.TestCase):
    def test_secret_in_an_spa_is_high(self):
        cfg = client(client_type="public", application_type="spa", secret_present=True)
        self.assertEqual(severity_of(cfg, "FL008"), Severity.HIGH)

    def test_secret_in_a_native_app_is_high(self):
        cfg = client(client_type="public", application_type="native", secret_present=True)
        self.assertEqual(severity_of(cfg, "FL008"), Severity.HIGH)

    def test_secret_on_a_client_registered_public_is_a_contradiction_at_medium(self):
        cfg = client(client_type="public", application_type="web", secret_present=True)
        self.assertEqual(severity_of(cfg, "FL008"), Severity.MEDIUM)

    def test_secret_on_a_confidential_web_client_is_correct(self):
        self.assertNotIn("FL008", fired(config()))


class ResponseMode(unittest.TestCase):
    def test_fragment_mode_on_a_code_flow_fires_fl009(self):
        self.assertIn("FL009", fired(client(response_mode="fragment")))

    def test_fragment_mode_is_not_reported_when_the_flow_needs_it(self):
        cfg = client(response_types=["token"], response_mode="fragment")
        self.assertNotIn("FL009", fired(cfg))

    def test_query_mode_does_not_fire_fl009(self):
        self.assertNotIn("FL009", fired(config()))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class IdTokenOnlyImplicit(unittest.TestCase):
    """`response_type=id_token` is an implicit flow under OIDC Core 3.2.

    `uses_implicit` tested for the bare word `token`, and `"token"` is not in
    `["id_token"]`, so this configuration was read as neither implicit nor hybrid
    and fell through every front-channel rule: FL009 fired saying the fragment
    was unnecessary -- on the flow whose default and correct response mode *is*
    the fragment -- while no rule reported the front-channel credential at all,
    so the escalation chain never saw one.
    """

    def test_id_token_alone_is_implicit(self):
        self.assertTrue(client(response_types=["id_token"]).client.uses_implicit)

    def test_hybrid_is_not_implicit(self):
        for rt in ("code id_token", "code token", "code id_token token"):
            with self.subTest(response_type=rt):
                cfg = client(response_types=[rt])
                self.assertFalse(cfg.client.uses_implicit, rt)
                self.assertTrue(cfg.client.hybrid_response_types, rt)
                self.assertTrue(cfg.client.returns_front_channel_credential, rt)

    def test_code_alone_returns_no_front_channel_credential(self):
        self.assertFalse(client(response_types=["code"]).client.returns_front_channel_credential)

    def test_id_token_alone_fires_fl012_and_not_fl001(self):
        # FL001 stays scoped to an access token on purpose: a replayable identity
        # assertion and a bearer key to an API are not the same risk, which is
        # why FL012 carries its own severity.
        f = fired(client(response_types=["id_token"]))
        self.assertIn("FL012", f)
        self.assertNotIn("FL001", f)

    def test_id_token_with_an_access_token_fires_fl001_and_not_fl012(self):
        cfg = client(response_types=["id_token token"], nonce=hardened_client().nonce)
        f = fired(cfg)
        self.assertIn("FL001", f)
        self.assertNotIn("FL012", f)

    def test_hybrid_fires_fl002_and_not_fl012(self):
        f = fired(client(response_types=["code id_token"]))
        self.assertIn("FL002", f)
        self.assertNotIn("FL012", f)

    def test_fragment_is_not_reported_as_unnecessary_for_an_id_token_flow(self):
        self.assertNotIn("FL009", fired(client(response_types=["id_token"], response_mode="fragment")))

    def test_fragment_is_still_reported_as_unnecessary_for_a_code_flow(self):
        self.assertIn("FL009", fired(client(response_types=["code"], response_mode="fragment")))

    def test_fragment_is_not_reported_as_unnecessary_for_a_hybrid_flow(self):
        self.assertNotIn("FL009", fired(client(response_types=["code id_token"], response_mode="fragment")))
