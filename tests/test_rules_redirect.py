"""Redirect URI rules: RU001 - RU018."""

from __future__ import annotations

import unittest

from oauth_flow_lint.findings import Severity
from tests.helpers import (
    config,
    detail_of,
    fired,
    hardened_client,
    hardened_provider,
    run,
    severity_of,
)


def with_uris(*uris: str, **client_overrides: object):
    return config(client=hardened_client(redirect_uris=list(uris), **client_overrides))


def loose(*uris: str, **client_overrides: object):
    return config(
        client=hardened_client(redirect_uris=list(uris), **client_overrides),
        providers=[hardened_provider(redirect_uri_matching="prefix")],
    )


class Baseline(unittest.TestCase):
    def test_the_hardened_baseline_reports_nothing(self):
        self.assertEqual(fired(config()), set())


class Wildcards(unittest.TestCase):
    def test_wildcard_host_fires_ru001(self):
        self.assertIn("RU001", fired(with_uris("https://*.app.example/cb")))

    def test_wildcard_path_fires_ru001(self):
        self.assertIn("RU001", fired(with_uris("https://app.example/cb/*")))

    def test_ru001_names_the_component(self):
        self.assertIn("host", detail_of(with_uris("https://*.app.example/cb"), "RU001"))


class Matching(unittest.TestCase):
    def test_prefix_matching_fires_ru002_at_high(self):
        cfg = config(providers=[hardened_provider(redirect_uri_matching="prefix")])
        self.assertIn("RU002", fired(cfg))
        self.assertEqual(severity_of(cfg, "RU002"), Severity.HIGH)

    def test_wildcard_matching_fires_ru002(self):
        cfg = config(providers=[hardened_provider(redirect_uri_matching="wildcard")])
        self.assertEqual(severity_of(cfg, "RU002"), Severity.HIGH)

    def test_unknown_matching_is_graded_lower_than_a_known_loose_rule(self):
        cfg = config(providers=[hardened_provider(redirect_uri_matching="unknown")])
        self.assertEqual(severity_of(cfg, "RU002"), Severity.MEDIUM)
        self.assertIn("plan subcommand", detail_of(cfg, "RU002"))

    def test_exact_matching_does_not_fire_ru002(self):
        self.assertNotIn("RU002", fired(config()))


class OpenPath(unittest.TestCase):
    def test_bare_origin_under_prefix_matching_is_medium(self):
        cfg = loose("https://app.example")
        self.assertEqual(severity_of(cfg, "RU003"), Severity.MEDIUM)
        self.assertIn("any path under this origin", detail_of(cfg, "RU003"))

    def test_trailing_slash_under_prefix_matching_fires(self):
        self.assertIn("RU003", fired(loose("https://app.example/cb/")))

    def test_open_path_under_exact_matching_is_only_low(self):
        cfg = with_uris("https://app.example/cb/")
        self.assertEqual(severity_of(cfg, "RU003"), Severity.LOW)
        self.assertIn("currently contained", detail_of(cfg, "RU003"))

    def test_a_complete_path_does_not_fire_ru003(self):
        self.assertNotIn("RU003", fired(loose("https://app.example/auth/callback")))


class Schemes(unittest.TestCase):
    def test_http_on_a_routable_host_fires_ru004(self):
        self.assertIn("RU004", fired(with_uris("http://app.example/cb")))

    def test_loopback_on_a_native_client_is_informational_only(self):
        cfg = with_uris(
            "http://127.0.0.1:8400/cb", client_type="public", application_type="native"
        )
        f = fired(cfg)
        self.assertIn("RU006", f)
        self.assertNotIn("RU004", f)
        self.assertNotIn("RU005", f)
        self.assertEqual(severity_of(cfg, "RU006"), Severity.INFO)

    def test_localhost_on_a_native_client_is_also_accepted(self):
        cfg = with_uris("http://localhost:8400/cb", client_type="public", application_type="native")
        self.assertIn("RU006", fired(cfg))
        self.assertNotIn("RU004", fired(cfg))

    def test_loopback_on_a_web_client_fires_ru005_not_ru004(self):
        cfg = with_uris("http://localhost:3000/cb")
        f = fired(cfg)
        self.assertIn("RU005", f)
        self.assertNotIn("RU004", f)
        self.assertNotIn("RU006", f)

    def test_loopback_on_an_spa_fires_ru005(self):
        cfg = with_uris("http://127.0.0.1:3000/cb", client_type="public", application_type="spa")
        self.assertIn("RU005", fired(cfg))

    def test_the_native_info_finding_explains_the_port_requirement(self):
        cfg = with_uris("http://127.0.0.1/cb", client_type="public", application_type="native")
        self.assertIn("any port", detail_of(cfg, "RU006"))


class PrivateUseSchemes(unittest.TestCase):
    def test_bare_scheme_fires_ru007(self):
        cfg = with_uris("myapp://callback", client_type="public", application_type="native")
        self.assertIn("RU007", fired(cfg))

    def test_reverse_dns_scheme_does_not_fire_ru007(self):
        cfg = with_uris(
            "com.example.fieldapp:/oauth2redirect", client_type="public", application_type="native"
        )
        self.assertNotIn("RU007", fired(cfg))


class HostReachability(unittest.TestCase):
    def test_subdomain_of_a_wildcard_domain_is_high(self):
        cfg = with_uris("https://a.app.example/cb", wildcard_dns_hosts=["app.example"])
        self.assertEqual(severity_of(cfg, "RU008"), Severity.HIGH)
        match = next(f for f in run(cfg).findings if f.rule_id == "RU008")
        self.assertEqual(match.evidence["match"], "subdomain")

    def test_the_wildcard_apex_itself_is_graded_lower(self):
        cfg = with_uris("https://app.example/cb", wildcard_dns_hosts=["app.example"])
        self.assertEqual(severity_of(cfg, "RU008"), Severity.MEDIUM)
        match = next(f for f in run(cfg).findings if f.rule_id == "RU008")
        self.assertEqual(match.evidence["match"], "apex")
        self.assertIn("sibling", match.detail)

    def test_an_unrelated_host_does_not_fire_ru008(self):
        cfg = with_uris("https://other.example/cb", wildcard_dns_hosts=["app.example"])
        self.assertNotIn("RU008", fired(cfg))

    def test_platform_host_fires_ru009(self):
        cfg = with_uris("https://preview.pages.dev/cb")
        self.assertIn("RU009", fired(cfg))
        self.assertIn("pages.dev", detail_of(cfg, "RU009"))

    def test_several_platform_suffixes_are_recognised(self):
        for host in ("x.vercel.app", "y.netlify.app", "z.github.io", "w.herokuapp.com"):
            self.assertIn("RU009", fired(with_uris(f"https://{host}/cb")), host)


class Forwarding(unittest.TestCase):
    def test_a_forwarder_shaped_path_fires_ru010(self):
        self.assertIn("RU010", fired(with_uris("https://app.example/redirect")))

    def test_a_destination_shaped_query_fires_ru010(self):
        self.assertIn("RU010", fired(with_uris("https://app.example/login?next=/home")))

    def test_a_confirmed_open_redirector_fires_ru011_instead(self):
        cfg = with_uris(
            "https://app.example/redirect",
            confirmed_open_redirect_uris=["https://app.example/redirect"],
        )
        f = fired(cfg)
        self.assertIn("RU011", f)
        self.assertNotIn("RU010", f)

    def test_ru010_tells_the_reader_how_to_promote_it(self):
        self.assertIn(
            "confirmed_open_redirect_uris", detail_of(with_uris("https://app.example/goto"), "RU010")
        )


class Components(unittest.TestCase):
    def test_fragment_fires_ru012(self):
        cfg = with_uris("https://app.example/cb#x")
        self.assertIn("RU012", fired(cfg))
        self.assertEqual(severity_of(cfg, "RU012"), Severity.HIGH)

    def test_a_plain_query_fires_only_ru013(self):
        cfg = with_uris("https://app.example/cb?tenant=acme")
        f = fired(cfg)
        self.assertIn("RU013", f)
        self.assertNotIn("RU010", f)
        self.assertEqual(severity_of(cfg, "RU013"), Severity.LOW)

    def test_userinfo_fires_ru015_and_names_the_real_host(self):
        cfg = with_uris("https://app.example@evil.example/cb")
        self.assertIn("RU015", fired(cfg))
        self.assertIn("evil.example", detail_of(cfg, "RU015"))


class Normalisation(unittest.TestCase):
    def test_a_backslash_that_changes_the_host_is_high(self):
        cfg = with_uris("https://app.example\\@evil.example/cb")
        self.assertEqual(severity_of(cfg, "RU016"), Severity.HIGH)
        detail = detail_of(cfg, "RU016")
        self.assertIn("evil.example", detail)
        self.assertIn("app.example", detail)

    def test_a_default_port_fires_ru016(self):
        self.assertIn("RU016", fired(with_uris("https://app.example:443/cb")))

    def test_percent_encoding_fires_ru016(self):
        self.assertIn("RU016", fired(with_uris("https://app.example/cb%2Fsub")))

    def test_a_dot_segment_fires_ru016(self):
        self.assertIn("RU016", fired(with_uris("https://app.example/a/../cb")))

    def test_a_double_slash_fires_ru016(self):
        self.assertIn("RU016", fired(with_uris("https://app.example//cb")))

    def test_an_uppercase_host_fires_ru016(self):
        self.assertIn("RU016", fired(with_uris("https://APP.example/cb")))

    def test_a_trailing_dot_host_fires_ru016(self):
        self.assertIn("RU016", fired(with_uris("https://app.example./cb")))

    def test_a_trailing_slash_alone_is_only_low(self):
        cfg = with_uris("https://app.example/cb/")
        self.assertEqual(severity_of(cfg, "RU016"), Severity.LOW)

    def test_ru016_reports_the_canonical_form(self):
        self.assertIn(
            "https://app.example/cb", detail_of(with_uris("https://app.example:443/cb"), "RU016")
        )

    def test_an_unparseable_registration_fires_ru016_rather_than_crashing(self):
        cfg = with_uris("https://app.example:notaport/cb")
        self.assertIn("RU016", fired(cfg))

    def test_one_bad_registration_does_not_stop_the_others(self):
        cfg = with_uris("not-a-uri", "https://app.example/cb#frag")
        f = fired(cfg)
        self.assertIn("RU016", f)
        self.assertIn("RU012", f)


class InternationalisedHosts(unittest.TestCase):
    def test_punycode_fires_ru017(self):
        self.assertIn("RU017", fired(with_uris("https://xn--80ak6aa92e.example/cb")))

    def test_unicode_fires_ru017(self):
        self.assertIn("RU017", fired(with_uris("https://аpp.example/cb")))

    def test_an_ascii_host_does_not_fire_ru017(self):
        self.assertNotIn("RU017", fired(config()))


class RegistrationSet(unittest.TestCase):
    def test_no_registrations_at_all_fires_ru018(self):
        cfg = config(client=hardened_client(redirect_uris=[]))
        self.assertIn("RU018", fired(cfg))

    def test_no_registrations_short_circuits_the_other_redirect_rules(self):
        f = fired(config(client=hardened_client(redirect_uris=[])))
        self.assertEqual({r for r in f if r.startswith("RU")}, {"RU018"})

    def test_mixed_strictness_fires_ru014_and_names_the_weakest(self):
        cfg = with_uris("https://app.example/auth/callback", "https://app.example/")
        self.assertIn("RU014", fired(cfg))
        detail = detail_of(cfg, "RU014")
        self.assertIn("security of 'https://app.example/'", detail)

    def test_two_equally_strict_registrations_do_not_fire_ru014(self):
        cfg = with_uris("https://app.example/cb-one", "https://app.example/cb-two")
        self.assertNotIn("RU014", fired(cfg))

    def test_a_single_registration_cannot_fire_ru014(self):
        self.assertNotIn("RU014", fired(config()))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
