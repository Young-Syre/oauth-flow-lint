"""State, nonce and issuer rules: SN001 - SN008."""

from __future__ import annotations

import unittest

from oauth_flow_lint.findings import Severity
from oauth_flow_lint.model import NonceHandling, StateHandling
from tests.helpers import config, detail_of, fired, hardened_client, hardened_provider, severity_of


def with_state(**kw):
    base = {
        "sent": True,
        "bound_to_session": True,
        "single_use": True,
        "entropy_bits": 256,
        "source": "csprng",
    }
    base.update(kw)
    return config(client=hardened_client(state=StateHandling(**base)))


class State(unittest.TestCase):
    def test_absent_state_fires_sn001(self):
        cfg = with_state(sent=False)
        self.assertIn("SN001", fired(cfg))
        self.assertEqual(severity_of(cfg, "SN001"), Severity.HIGH)

    def test_absent_state_suppresses_the_quality_rules(self):
        f = fired(with_state(sent=False, bound_to_session=False, single_use=False, source="static"))
        self.assertEqual({r for r in f if r.startswith("SN00")} & {"SN002", "SN003", "SN004"}, set())

    def test_unbound_state_fires_sn002(self):
        self.assertIn("SN002", fired(with_state(bound_to_session=False)))

    def test_sn002_explains_that_the_attacker_supplies_their_own_state(self):
        self.assertIn("starts their own flow", detail_of(with_state(bound_to_session=False), "SN002"))

    def test_reusable_state_fires_sn003(self):
        self.assertIn("SN003", fired(with_state(single_use=False)))

    def test_timestamp_source_fires_sn004_at_high(self):
        cfg = with_state(source="timestamp")
        self.assertEqual(severity_of(cfg, "SN004"), Severity.HIGH)

    def test_counter_source_fires_sn004(self):
        self.assertIn("SN004", fired(with_state(source="counter")))

    def test_static_source_fires_sn004(self):
        self.assertIn("SN004", fired(with_state(source="static")))

    def test_an_unestablished_source_is_graded_medium(self):
        cfg = with_state(source="unknown")
        self.assertEqual(severity_of(cfg, "SN004"), Severity.MEDIUM)
        self.assertIn("must be treated as predictable", detail_of(cfg, "SN004"))

    def test_low_entropy_from_a_good_source_is_medium(self):
        cfg = with_state(source="csprng", entropy_bits=48)
        self.assertEqual(severity_of(cfg, "SN004"), Severity.MEDIUM)

    def test_sufficient_entropy_from_a_good_source_is_clean(self):
        self.assertNotIn("SN004", fired(with_state(source="csprng", entropy_bits=128)))


class Nonce(unittest.TestCase):
    def test_absent_nonce_with_openid_scope_fires_sn005(self):
        cfg = config(client=hardened_client(nonce=NonceHandling(sent=False)))
        self.assertIn("SN005", fired(cfg))
        self.assertIn("openid scope", detail_of(cfg, "SN005"))

    def test_absent_nonce_with_an_id_token_response_type_names_that_reason(self):
        cfg = config(
            client=hardened_client(
                response_types=["code id_token"], scopes=[], stated_purpose_scopes=[], nonce=NonceHandling(sent=False)
            )
        )
        self.assertIn("response_types requests an id_token", detail_of(cfg, "SN005"))

    def test_unbound_nonce_fires_sn006(self):
        cfg = config(client=hardened_client(nonce=NonceHandling(sent=True, bound_to_session=False)))
        f = fired(cfg)
        self.assertIn("SN006", f)
        self.assertNotIn("SN005", f)

    def test_no_id_token_means_no_nonce_rules(self):
        cfg = config(
            client=hardened_client(
                scopes=["profile"], stated_purpose_scopes=["profile"], nonce=NonceHandling(sent=False)
            )
        )
        f = fired(cfg)
        self.assertNotIn("SN005", f)
        self.assertNotIn("SN006", f)

    def test_a_bound_nonce_is_clean(self):
        self.assertNotIn("SN005", fired(config()))
        self.assertNotIn("SN006", fired(config()))


class IssuerIdentification(unittest.TestCase):
    def test_single_provider_without_iss_is_sn008_at_low(self):
        cfg = config(providers=[hardened_provider(returns_iss_parameter=False)])
        self.assertEqual(severity_of(cfg, "SN008"), Severity.LOW)
        self.assertNotIn("SN007", fired(cfg))

    def test_sn008_explains_why_it_is_reported_at_all(self):
        cfg = config(providers=[hardened_provider(returns_iss_parameter=False)])
        self.assertIn("adding a second issuer", detail_of(cfg, "SN008"))

    def test_two_providers_one_without_iss_fires_sn007(self):
        cfg = config(
            providers=[
                hardened_provider(name="a", returns_iss_parameter=True),
                hardened_provider(name="b", returns_iss_parameter=False),
            ]
        )
        self.assertIn("SN007", fired(cfg))
        self.assertEqual(severity_of(cfg, "SN007"), Severity.HIGH)
        self.assertNotIn("SN008", fired(cfg))

    def test_sn007_names_the_mix_up_condition_explicitly(self):
        cfg = config(
            providers=[
                hardened_provider(name="a", returns_iss_parameter=True),
                hardened_provider(name="b", returns_iss_parameter=False),
            ]
        )
        self.assertIn("mix-up condition", detail_of(cfg, "SN007"))

    def test_sn007_names_the_providers_at_fault(self):
        cfg = config(
            providers=[
                hardened_provider(name="good", returns_iss_parameter=True),
                hardened_provider(name="bad-one", returns_iss_parameter=False),
                hardened_provider(name="bad-two", returns_iss_parameter=False),
            ]
        )
        detail = detail_of(cfg, "SN007")
        self.assertIn("bad-one", detail)
        self.assertIn("bad-two", detail)
        self.assertNotIn("good", detail.replace("bad-one", "").replace("bad-two", ""))

    def test_several_providers_all_returning_iss_are_clean(self):
        cfg = config(
            providers=[
                hardened_provider(name="a", returns_iss_parameter=True),
                hardened_provider(name="b", returns_iss_parameter=True),
            ]
        )
        f = fired(cfg)
        self.assertNotIn("SN007", f)
        self.assertNotIn("SN008", f)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
