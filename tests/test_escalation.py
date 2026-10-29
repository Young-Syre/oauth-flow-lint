"""The escalation matrix: ESC001 - ESC014.

Each test builds the minimum configuration that produces one combination, and
asserts that the combination fires, that the components are annotated with it,
and - for the cases where it is the point - that removing either half of the
combination stops it. The negative half matters more than the positive half: a
matrix that fires on everything is a matrix that tells a reviewer nothing.
"""

from __future__ import annotations

import unittest

from oauth_flow_lint.escalation import MATRIX, apply
from oauth_flow_lint.findings import RULES, Finding, Severity
from oauth_flow_lint.model import (
    PKCE,
    Capture,
    IdTokenValidation,
    NonceHandling,
    StateHandling,
    TokenHandling,
)
from tests.helpers import config, fired, hardened_client, hardened_provider, run


def loose_provider(**kw):
    return hardened_provider(redirect_uri_matching="prefix", **kw)


class MatrixShape(unittest.TestCase):
    def test_every_escalation_is_registered_as_a_rule(self):
        for esc in MATRIX:
            self.assertIn(esc.id, RULES)
            self.assertEqual(RULES[esc.id].category, "escalation")

    def test_every_escalation_references_only_real_rules(self):
        for esc in MATRIX:
            for rule_id in esc.left + esc.right:
                self.assertIn(rule_id, RULES, f"{esc.id} references {rule_id}")

    def test_no_escalation_references_another_escalation(self):
        for esc in MATRIX:
            for rule_id in esc.left + esc.right:
                self.assertNotEqual(RULES[rule_id].category, "escalation", esc.id)

    def test_every_escalation_outranks_or_matches_its_components(self):
        for esc in MATRIX:
            components = [RULES[r].severity for r in esc.left + esc.right]
            self.assertGreaterEqual(esc.severity, max(components), esc.id)

    def test_escalation_ids_are_unique_and_sequential(self):
        ids = [e.id for e in MATRIX]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids))

    def test_left_and_right_do_not_overlap(self):
        for esc in MATRIX:
            self.assertEqual(set(esc.left) & set(esc.right), set(), esc.id)

    def test_every_escalation_has_a_mechanism_and_a_narrative(self):
        for esc in MATRIX:
            self.assertTrue(esc.mechanism.strip(), esc.id)
            self.assertGreater(len(esc.narrative), 200, esc.id)
            self.assertTrue(esc.remediation.strip(), esc.id)

    def test_a_single_rule_from_one_side_fires_nothing(self):
        for esc in MATRIX:
            produced = apply([Finding(rule_id=esc.left[0], locus="x", detail="d")])
            self.assertEqual([f.rule_id for f in produced], [], esc.id)

    def test_both_sides_together_fire_exactly_that_escalation(self):
        for esc in MATRIX:
            findings = [
                Finding(rule_id=esc.left[0], locus="x", detail="d"),
                Finding(rule_id=esc.right[0], locus="y", detail="d"),
            ]
            produced = apply(findings)
            self.assertIn(esc.id, [f.rule_id for f in produced], esc.id)

    def test_contributing_findings_are_annotated_in_both_directions(self):
        esc = MATRIX[0]
        findings = [
            Finding(rule_id=esc.left[0], locus="x", detail="d"),
            Finding(rule_id=esc.right[0], locus="y", detail="d"),
        ]
        apply(findings)
        for f in findings:
            self.assertIn(esc.id, f.escalated_into)

    def test_an_escalation_records_the_rules_it_was_built_from(self):
        esc = MATRIX[0]
        produced = apply(
            [
                Finding(rule_id=esc.left[0], locus="x", detail="d"),
                Finding(rule_id=esc.right[0], locus="y", detail="d"),
            ]
        )
        match = next(f for f in produced if f.rule_id == esc.id)
        self.assertIn(esc.left[0], match.evidence["contributing_rules"])
        self.assertIn(esc.right[0], match.evidence["contributing_rules"])
        self.assertIn("Built from:", match.detail)

    def test_components_are_not_removed_from_the_report(self):
        cfg = config(
            client=hardened_client(response_types=["token"], grant_types=["implicit"]),
            providers=[loose_provider()],
        )
        f = fired(cfg)
        self.assertIn("ESC001", f)
        self.assertIn("FL001", f)
        self.assertIn("RU002", f)

    def test_many_loci_are_summarised_rather_than_concatenated(self):
        findings = [Finding(rule_id="FL001", locus="client", detail="d")] + [
            Finding(rule_id="RU003", locus=f"uri-{i}", detail="d") for i in range(6)
        ]
        produced = apply(findings)
        match = next(f for f in produced if f.rule_id == "ESC001")
        self.assertIn("more)", match.locus)
        self.assertLess(len(match.locus), 120)


class Esc001ImplicitPlusLooseRedirect(unittest.TestCase):
    """The case the tool exists for."""

    def base(self, **provider_kw):
        return config(
            client=hardened_client(
                client_type="public",
                application_type="spa",
                secret_present=False,
                response_types=["token"],
                grant_types=["implicit"],
                pkce=PKCE(used=False),
                tokens=TokenHandling(access_token_lifetime_seconds=600),
            ),
            providers=[hardened_provider(**provider_kw)],
        )

    def test_implicit_plus_prefix_matching_is_critical(self):
        report = run(self.base(redirect_uri_matching="prefix"))
        esc = [f for f in report.findings if f.rule_id == "ESC001"]
        self.assertEqual(len(esc), 1)
        self.assertEqual(esc[0].severity, Severity.CRITICAL)

    def test_the_narrative_states_the_mechanism_in_one_sentence(self):
        self.assertIn(
            "attacker-controlled path on a registered origin receives the access token",
            RULES["ESC001"].mechanism,
        )

    def test_implicit_with_exact_matching_and_a_complete_uri_does_not_escalate(self):
        self.assertNotIn("ESC001", fired(self.base(redirect_uri_matching="exact")))

    def test_a_loose_redirect_without_front_channel_credentials_does_not_escalate(self):
        cfg = config(providers=[loose_provider()])
        self.assertNotIn("ESC001", fired(cfg))

    def test_an_open_path_suffix_is_enough_on_the_redirect_side(self):
        cfg = config(
            client=hardened_client(
                response_types=["token"],
                grant_types=["implicit"],
                redirect_uris=["https://app.example/"],
            ),
            providers=[loose_provider()],
        )
        self.assertIn("ESC001", fired(cfg))

    def test_a_shared_platform_host_is_enough_on_the_redirect_side(self):
        cfg = config(
            client=hardened_client(
                response_types=["token"],
                grant_types=["implicit"],
                redirect_uris=["https://preview.pages.dev/auth/callback"],
            )
        )
        self.assertIn("ESC001", fired(cfg))

    def test_a_hybrid_flow_returning_a_token_also_escalates(self):
        cfg = config(
            client=hardened_client(response_types=["code token"]),
            providers=[loose_provider()],
        )
        self.assertIn("ESC001", fired(cfg))


class Esc002CodeInterception(unittest.TestCase):
    def test_public_client_without_pkce_plus_loose_redirect(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="spa",
                secret_present=False,
                pkce=PKCE(used=False),
            ),
            providers=[loose_provider()],
        )
        self.assertIn("ESC002", fired(cfg))

    def test_pkce_removes_it(self):
        cfg = config(
            client=hardened_client(
                client_type="public", application_type="spa", secret_present=False
            ),
            providers=[loose_provider()],
        )
        self.assertNotIn("ESC002", fired(cfg))

    def test_exact_matching_removes_it(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="spa",
                secret_present=False,
                pkce=PKCE(used=False),
            )
        )
        self.assertNotIn("ESC002", fired(cfg))


class Esc003PkceDowngrade(unittest.TestCase):
    def test_provider_not_enforcing_pkce_plus_loose_redirect(self):
        cfg = config(providers=[loose_provider(enforces_pkce=False)])
        self.assertIn("ESC003", fired(cfg))

    def test_enforced_pkce_removes_it(self):
        self.assertNotIn("ESC003", fired(config(providers=[loose_provider()])))

    def test_the_mechanism_names_the_provider_as_the_place_the_control_fails(self):
        self.assertIn("omits code_challenge", RULES["ESC003"].mechanism)


class Esc004MixUp(unittest.TestCase):
    def two_providers(self):
        return [
            hardened_provider(name="a", returns_iss_parameter=True),
            hardened_provider(name="b", returns_iss_parameter=False),
        ]

    def test_missing_iss_plus_unbound_state_is_critical(self):
        cfg = config(
            client=hardened_client(
                state=StateHandling(sent=True, bound_to_session=False, entropy_bits=256, source="csprng")
            ),
            providers=self.two_providers(),
        )
        report = run(cfg)
        esc = [f for f in report.findings if f.rule_id == "ESC004"]
        self.assertEqual(len(esc), 1)
        self.assertEqual(esc[0].severity, Severity.CRITICAL)

    def test_a_session_bound_state_removes_it(self):
        self.assertNotIn("ESC004", fired(config(providers=self.two_providers())))

    def test_one_provider_cannot_produce_it(self):
        cfg = config(
            client=hardened_client(
                state=StateHandling(sent=True, bound_to_session=False, entropy_bits=256, source="csprng")
            ),
            providers=[hardened_provider(returns_iss_parameter=False)],
        )
        self.assertNotIn("ESC004", fired(cfg))

    def test_an_unchecked_issuer_also_completes_it(self):
        cfg = config(
            client=hardened_client(
                id_token_validation=IdTokenValidation(
                    signature_verified=True,
                    alg_pinned=True,
                    accepted_algs=["RS256"],
                    aud_checked=True,
                    iss_checked=False,
                    exp_checked=True,
                    azp_checked=True,
                    jwks_source="pinned",
                    jwks_host_pinned=True,
                    expected_audiences=["test-client"],
                )
            ),
            providers=self.two_providers(),
        )
        self.assertIn("ESC004", fired(cfg))


class Esc005TokenForgery(unittest.TestCase):
    def validation(self, **kw):
        base = {
            "signature_verified": True,
            "alg_pinned": True,
            "accepted_algs": ["RS256"],
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

    def test_unpinned_alg_plus_unpinned_keys_is_critical(self):
        cfg = self.validation(alg_pinned=False, jwks_source="discovery", jwks_host_pinned=False)
        self.assertIn("ESC005", fired(cfg))

    def test_keys_from_the_token_header_completes_it(self):
        cfg = self.validation(alg_pinned=False, jwks_source="token_header")
        self.assertIn("ESC005", fired(cfg))

    def test_pinned_keys_remove_it(self):
        self.assertNotIn("ESC005", fired(self.validation(alg_pinned=False)))

    def test_a_pinned_algorithm_removes_it(self):
        cfg = self.validation(jwks_source="discovery", jwks_host_pinned=False)
        self.assertNotIn("ESC005", fired(cfg))


class Esc006CrossClientReplay(unittest.TestCase):
    def test_unchecked_audience_plus_open_registration(self):
        cfg = config(
            client=hardened_client(
                id_token_validation=IdTokenValidation(
                    signature_verified=True,
                    alg_pinned=True,
                    accepted_algs=["RS256"],
                    aud_checked=False,
                    iss_checked=True,
                    exp_checked=True,
                    azp_checked=True,
                    jwks_source="pinned",
                    jwks_host_pinned=True,
                )
            ),
            providers=[hardened_provider(dynamic_client_registration="open")],
        )
        self.assertIn("ESC006", fired(cfg))

    def test_unchecked_audience_plus_ignored_azp(self):
        cfg = config(
            client=hardened_client(
                id_token_validation=IdTokenValidation(
                    signature_verified=True,
                    alg_pinned=True,
                    accepted_algs=["RS256"],
                    aud_checked=False,
                    iss_checked=True,
                    exp_checked=True,
                    azp_checked=False,
                    jwks_source="pinned",
                    jwks_host_pinned=True,
                    expected_audiences=["test-client", "sibling"],
                )
            )
        )
        self.assertIn("ESC006", fired(cfg))

    def test_a_checked_audience_removes_it(self):
        self.assertNotIn(
            "ESC006", fired(config(providers=[hardened_provider(dynamic_client_registration="open")]))
        )


class Esc007OnwardForwarding(unittest.TestCase):
    def test_front_channel_credential_plus_confirmed_open_redirector(self):
        cfg = config(
            client=hardened_client(
                response_types=["token"],
                grant_types=["implicit"],
                redirect_uris=["https://app.example/redirect"],
                confirmed_open_redirect_uris=["https://app.example/redirect"],
            )
        )
        self.assertIn("ESC007", fired(cfg))

    def test_a_suspected_forwarder_is_enough_to_raise_it(self):
        cfg = config(
            client=hardened_client(
                response_types=["token"],
                grant_types=["implicit"],
                redirect_uris=["https://app.example/goto"],
            )
        )
        self.assertIn("ESC007", fired(cfg))

    def test_esc001_and_esc007_are_distinguished_by_mechanism(self):
        """One delivers to a path on the origin; the other leaves the origin."""
        cfg = config(
            client=hardened_client(
                response_types=["token"],
                grant_types=["implicit"],
                redirect_uris=["https://app.example/goto"],
            )
        )
        f = fired(cfg)
        self.assertIn("ESC007", f)
        self.assertNotIn("ESC001", f)

    def test_a_code_flow_to_a_forwarder_does_not_fire_esc007(self):
        cfg = config(client=hardened_client(redirect_uris=["https://app.example/goto"]))
        self.assertNotIn("ESC007", fired(cfg))


class Esc008PersistentAccess(unittest.TestCase):
    def test_unrotated_refresh_token_plus_web_storage(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="spa",
                secret_present=False,
                tokens=TokenHandling(
                    refresh_token_issued=True,
                    refresh_token_rotation=False,
                    refresh_token_lifetime_seconds=3600,
                    access_token_lifetime_seconds=600,
                    browser_storage="localstorage",
                ),
            )
        )
        self.assertIn("ESC008", fired(cfg))

    def test_rotation_removes_it(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="spa",
                secret_present=False,
                tokens=TokenHandling(
                    refresh_token_issued=True,
                    refresh_token_rotation=True,
                    refresh_token_lifetime_seconds=3600,
                    access_token_lifetime_seconds=600,
                    browser_storage="localstorage",
                ),
            )
        )
        self.assertNotIn("ESC008", fired(cfg))


class Esc009CodeInjection(unittest.TestCase):
    def test_absent_state_plus_no_pkce(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="spa",
                secret_present=False,
                state=StateHandling(sent=False),
                pkce=PKCE(used=False),
            )
        )
        self.assertIn("ESC009", fired(cfg))

    def test_unbound_state_plus_unenforced_pkce(self):
        cfg = config(
            client=hardened_client(
                state=StateHandling(sent=True, bound_to_session=False, entropy_bits=256, source="csprng")
            ),
            providers=[hardened_provider(enforces_pkce=False)],
        )
        self.assertIn("ESC009", fired(cfg))

    def test_a_bound_state_removes_it(self):
        cfg = config(providers=[hardened_provider(enforces_pkce=False)])
        self.assertNotIn("ESC009", fired(cfg))


class Esc010ScopeWidening(unittest.TestCase):
    def test_no_reconsent_plus_default_offline_access(self):
        cfg = config(
            client=hardened_client(
                scope_change_reconsent=False,
                scopes=["openid", "offline_access"],
                stated_purpose_scopes=["openid"],
            )
        )
        self.assertIn("ESC010", fired(cfg))

    def test_no_reconsent_plus_unbounded_refresh_token(self):
        cfg = config(
            client=hardened_client(
                scope_change_reconsent=False,
                tokens=TokenHandling(
                    refresh_token_issued=True,
                    refresh_token_rotation=True,
                    refresh_token_lifetime_seconds=0,
                    access_token_lifetime_seconds=600,
                ),
            )
        )
        self.assertIn("ESC010", fired(cfg))

    def test_reconsent_removes_it(self):
        cfg = config(
            client=hardened_client(scopes=["openid", "offline_access"], stated_purpose_scopes=["openid"])
        )
        self.assertNotIn("ESC010", fired(cfg))


class Esc011OpenRegistration(unittest.TestCase):
    def test_open_registration_plus_request_uri(self):
        cfg = config(
            providers=[
                hardened_provider(dynamic_client_registration="open", supports_request_uri=True)
            ]
        )
        self.assertIn("ESC011", fired(cfg))

    def test_open_registration_plus_auth_method_none(self):
        doc = {
            "issuer": "https://idp.example",
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
        }
        cfg = config(
            providers=[hardened_provider(dynamic_client_registration="open", discovery=doc)]
        )
        self.assertIn("ESC011", fired(cfg))

    def test_closed_registration_removes_it(self):
        cfg = config(providers=[hardened_provider(supports_request_uri=True)])
        self.assertNotIn("ESC011", fired(cfg))


class Esc012MetadataKeys(unittest.TestCase):
    def test_http_endpoint_plus_unpinned_keys(self):
        doc = {
            "issuer": "https://idp.example",
            "token_endpoint": "http://idp.example/token",
            "jwks_uri": "https://idp.example/jwks",
            "code_challenge_methods_supported": ["S256"],
        }
        cfg = config(
            client=hardened_client(
                id_token_validation=IdTokenValidation(
                    signature_verified=True,
                    alg_pinned=True,
                    accepted_algs=["RS256"],
                    aud_checked=True,
                    iss_checked=True,
                    exp_checked=True,
                    azp_checked=True,
                    jwks_source="discovery",
                    jwks_host_pinned=False,
                    expected_audiences=["test-client"],
                )
            ),
            providers=[hardened_provider(discovery=doc)],
        )
        self.assertIn("ESC012", fired(cfg))

    def test_https_endpoints_remove_it(self):
        doc = {
            "issuer": "https://idp.example",
            "token_endpoint": "https://idp.example/token",
            "jwks_uri": "https://keys.other.example/jwks",
            "code_challenge_methods_supported": ["S256"],
        }
        cfg = config(providers=[hardened_provider(discovery=doc)])
        self.assertNotIn("ESC012", fired(cfg))


class Esc013NativeHijack(unittest.TestCase):
    def test_unclaimable_scheme_plus_no_pkce(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="native",
                secret_present=False,
                redirect_uris=["myapp://callback"],
                pkce=PKCE(used=False),
                tokens=TokenHandling(access_token_lifetime_seconds=600),
            )
        )
        self.assertIn("ESC013", fired(cfg))

    def test_a_reverse_dns_scheme_removes_it(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="native",
                secret_present=False,
                redirect_uris=["com.example.app:/oauth2redirect"],
                pkce=PKCE(used=False),
            )
        )
        self.assertNotIn("ESC013", fired(cfg))

    def test_pkce_with_an_enforcing_provider_removes_it(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="native",
                secret_present=False,
                redirect_uris=["myapp://callback"],
            )
        )
        self.assertNotIn("ESC013", fired(cfg))


class Esc014TokenInUrlForwarded(unittest.TestCase):
    def test_token_in_query_plus_forwarding_callback(self):
        cfg = config(
            client=hardened_client(
                redirect_uris=["https://app.example/redirect"],
                confirmed_open_redirect_uris=["https://app.example/redirect"],
                tokens=TokenHandling(access_token_transport="query", access_token_lifetime_seconds=600),
            )
        )
        self.assertIn("ESC014", fired(cfg))

    def test_a_header_transport_removes_it(self):
        cfg = config(
            client=hardened_client(
                redirect_uris=["https://app.example/redirect"],
                confirmed_open_redirect_uris=["https://app.example/redirect"],
            )
        )
        self.assertNotIn("ESC014", fired(cfg))

    def test_an_observed_token_in_a_query_also_completes_it(self):
        cfg = config(
            client=hardened_client(redirect_uris=["https://app.example/redirect"]),
            captures=[
                Capture(
                    label="t",
                    authorization_response="https://app.example/redirect?access_token=REDACTED-TEST-VALUE&iss=https%3A%2F%2Fidp.example",
                )
            ],
        )
        self.assertIn("ESC014", fired(cfg))


class HardenedConfigurationsEscalateNothing(unittest.TestCase):
    def test_the_hardened_baseline_fires_no_escalation(self):
        self.assertEqual(run(config()).escalations, [])

    def test_a_hardened_native_client_fires_no_escalation(self):
        cfg = config(
            client=hardened_client(
                client_type="public",
                application_type="native",
                secret_present=False,
                redirect_uris=["com.example.app:/oauth2redirect", "http://127.0.0.1/cb"],
                tokens=TokenHandling(
                    refresh_token_issued=True,
                    refresh_token_rotation=True,
                    refresh_token_lifetime_seconds=7776000,
                    access_token_lifetime_seconds=900,
                ),
                nonce=NonceHandling(sent=True, bound_to_session=True),
            )
        )
        self.assertEqual(run(cfg).escalations, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
