"""Captured request/response cross-checks: CP001 - CP008.

The captured URLs here are fabricated, and every credential value in them is
the literal placeholder ``REDACTED-TEST-VALUE``. The tool only ever asks
whether a parameter is present and in which URL component, never what it
contains, so a test fixture never needs a real-shaped token.
"""

from __future__ import annotations

import unittest

from oauth_flow_lint.findings import Severity
from oauth_flow_lint.model import Capture
from tests.helpers import config, detail_of, fired, hardened_client, hardened_provider, severity_of

GOOD_REQUEST = (
    "https://idp.example/authorize"
    "?response_type=code"
    "&client_id=test-client"
    "&redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback"
    "&scope=openid+profile"
    "&state=REDACTED-TEST-VALUE"
    "&nonce=REDACTED-TEST-VALUE"
    "&code_challenge=REDACTED-TEST-VALUE"
    "&code_challenge_method=S256"
)
GOOD_RESPONSE = (
    "https://app.example/auth/callback"
    "?code=REDACTED-TEST-VALUE"
    "&state=REDACTED-TEST-VALUE"
    "&iss=https%3A%2F%2Fidp.example"
)


def captured(request=GOOD_REQUEST, response=GOOD_RESPONSE, resource="", client=None):
    return config(
        client=client,
        captures=[
            Capture(
                label="t",
                authorization_request=request,
                authorization_response=response,
                resource_request=resource,
            )
        ],
    )


def drop(url: str, param: str) -> str:
    parts = [p for p in url.split("&") if not p.startswith(param + "=")]
    return "&".join(parts)


class CleanCapture(unittest.TestCase):
    def test_a_correct_capture_adds_nothing(self):
        self.assertEqual(fired(captured()), set())

    def test_no_capture_means_no_capture_rules(self):
        self.assertEqual({r for r in fired(config()) if r.startswith("CP")}, set())

    def test_an_unparseable_capture_does_not_crash(self):
        fired(captured(request="https://idp.example:bad/authorize?response_type=code"))


class RequestCrossChecks(unittest.TestCase):
    def test_an_undeclared_response_type_fires_cp001(self):
        cfg = captured(request=GOOD_REQUEST.replace("response_type=code", "response_type=token"))
        self.assertIn("CP001", fired(cfg))
        self.assertIn("not pinned", detail_of(cfg, "CP001"))

    def test_a_missing_state_fires_cp002(self):
        cfg = captured(request=drop(GOOD_REQUEST, "state"))
        self.assertIn("CP002", fired(cfg))
        self.assertIn("describing a different code path", detail_of(cfg, "CP002"))

    def test_a_missing_code_challenge_fires_cp003(self):
        cfg = captured(request=drop(drop(GOOD_REQUEST, "code_challenge"), "code_challenge_method"))
        self.assertIn("CP003", fired(cfg))

    def test_cp003_is_high_for_a_public_client_and_medium_for_a_confidential_one(self):
        request = drop(drop(GOOD_REQUEST, "code_challenge"), "code_challenge_method")
        confidential = captured(request=request)
        self.assertEqual(severity_of(confidential, "CP003"), Severity.MEDIUM)
        public = captured(
            request=request,
            client=hardened_client(
                client_type="public", application_type="spa", secret_present=False
            ),
        )
        self.assertEqual(severity_of(public, "CP003"), Severity.HIGH)

    def test_a_method_mismatch_fires_cp003(self):
        cfg = captured(request=GOOD_REQUEST.replace("code_challenge_method=S256", "code_challenge_method=plain"))
        self.assertIn("CP003", fired(cfg))
        self.assertIn("'plain'", detail_of(cfg, "CP003"))

    def test_an_omitted_method_defaults_to_plain_and_is_reported(self):
        cfg = captured(request=drop(GOOD_REQUEST, "code_challenge_method"))
        self.assertIn("CP003", fired(cfg))
        self.assertIn("default is 'plain'", detail_of(cfg, "CP003"))

    def test_a_missing_nonce_on_an_id_token_request_fires_cp004(self):
        request = drop(GOOD_REQUEST, "nonce").replace("response_type=code", "response_type=code%20id_token")
        cfg = captured(
            request=request,
            client=hardened_client(response_types=["code id_token", "code"]),
        )
        self.assertIn("CP004", fired(cfg))

    def test_an_unregistered_redirect_uri_fires_cp006(self):
        cfg = captured(
            request=GOOD_REQUEST.replace(
                "redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback",
                "redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback%2F",
            )
        )
        self.assertIn("CP006", fired(cfg))
        self.assertIn("looser than a string comparison", detail_of(cfg, "CP006"))

    def test_the_registered_redirect_uri_passes_exact_comparison(self):
        self.assertNotIn("CP006", fired(captured()))


class ResponseCrossChecks(unittest.TestCase):
    def test_an_access_token_in_the_query_fires_cp005(self):
        cfg = captured(response=GOOD_RESPONSE + "&access_token=REDACTED-TEST-VALUE")
        self.assertIn("CP005", fired(cfg))
        self.assertEqual(severity_of(cfg, "CP005"), Severity.HIGH)

    def test_a_code_in_the_query_is_the_specified_behaviour_and_is_not_reported(self):
        self.assertNotIn("CP005", fired(captured()))

    def test_a_code_in_the_fragment_is_reported_at_medium(self):
        cfg = captured(
            response="https://app.example/auth/callback#code=REDACTED-TEST-VALUE&iss=https%3A%2F%2Fidp.example"
        )
        self.assertEqual(severity_of(cfg, "CP008"), Severity.MEDIUM)
        self.assertIn("response mode", detail_of(cfg, "CP008"))

    def test_a_token_in_the_fragment_fires_cp008(self):
        cfg = captured(
            response="https://app.example/auth/callback#access_token=REDACTED-TEST-VALUE&iss=https%3A%2F%2Fidp.example"
        )
        self.assertIn("CP008", fired(cfg))
        self.assertIn("observed behaviour", detail_of(cfg, "CP008"))

    def test_an_id_token_in_the_fragment_fires_cp008(self):
        cfg = captured(
            response="https://app.example/auth/callback#id_token=REDACTED-TEST-VALUE&iss=https%3A%2F%2Fidp.example"
        )
        self.assertIn("CP008", fired(cfg))

    def test_a_missing_iss_fires_cp007(self):
        cfg = captured(response=drop(GOOD_RESPONSE, "iss"))
        self.assertIn("CP007", fired(cfg))
        self.assertEqual(severity_of(cfg, "CP007"), Severity.MEDIUM)

    def test_a_missing_iss_is_raised_to_high_with_several_providers(self):
        cfg = config(
            providers=[
                hardened_provider(name="a"),
                hardened_provider(name="b"),
            ],
            captures=[
                Capture(
                    label="t",
                    authorization_request=GOOD_REQUEST,
                    authorization_response=drop(GOOD_RESPONSE, "iss"),
                )
            ],
        )
        self.assertEqual(severity_of(cfg, "CP007"), Severity.HIGH)

    def test_a_token_in_a_resource_request_query_fires_cp005(self):
        cfg = captured(resource="https://api.example/v1/me?access_token=REDACTED-TEST-VALUE")
        self.assertIn("CP005", fired(cfg))
        self.assertIn("resource request", detail_of(cfg, "CP005"))

    def test_several_captures_are_each_checked(self):
        cfg = config(
            captures=[
                Capture(label="one", authorization_request=drop(GOOD_REQUEST, "state"), authorization_response=GOOD_RESPONSE),
                Capture(label="two", authorization_request=GOOD_REQUEST, authorization_response=drop(GOOD_RESPONSE, "iss")),
            ]
        )
        loci = {f.locus for f in __import__("tests.helpers", fromlist=["run"]).run(cfg).findings}
        self.assertTrue(any("one" in loc for loc in loci))
        self.assertTrue(any("two" in loc for loc in loci))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
