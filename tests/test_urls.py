"""URL parsing and the normalisation traps.

Every trap named in the project's own requirements has a test here, because a
redirect-URI linter that decides on substrings rather than on a parsed URL is
worse than no linter: it produces confident output that is wrong in exactly the
cases that matter.
"""

from __future__ import annotations

import unittest

from oauth_flow_lint.urls import (
    collapse_empty_segments,
    equivalent,
    exact_match,
    host_in_domain,
    is_shared_platform_host,
    looseness_score,
    parse_redirect_uri,
    reflecting_path_segment,
    resolve_dot_segments,
)


class ParseBasics(unittest.TestCase):
    def test_simple_https_uri(self):
        u = parse_redirect_uri("https://app.example/auth/callback")
        self.assertTrue(u.valid)
        self.assertEqual(u.scheme, "https")
        self.assertEqual(u.host, "app.example")
        self.assertIsNone(u.port)
        self.assertEqual(u.path, "/auth/callback")
        self.assertEqual(u.hazards, ())
        self.assertFalse(u.path_is_open)

    def test_missing_scheme_is_an_error_not_a_guess(self):
        u = parse_redirect_uri("app.example/callback")
        self.assertFalse(u.valid)
        self.assertIn("absolute URI", u.error or "")

    def test_empty_value_is_an_error(self):
        self.assertFalse(parse_redirect_uri("").valid)
        self.assertFalse(parse_redirect_uri("   ").valid)

    def test_invalid_port_does_not_raise(self):
        u = parse_redirect_uri("https://app.example:notaport/cb")
        self.assertFalse(u.valid)
        self.assertIn("port", (u.error or "").lower())

    def test_control_character_is_rejected(self):
        u = parse_redirect_uri("https://app.example/cb\nX")
        self.assertFalse(u.valid)
        self.assertIn("control character", u.error or "")

    def test_explicit_non_default_port_is_kept(self):
        u = parse_redirect_uri("https://app.example:8443/cb")
        self.assertEqual(u.port, 8443)
        self.assertNotIn("default-port-written", u.hazards)
        self.assertEqual(u.authority, "app.example:8443")


class NormalisationTraps(unittest.TestCase):
    """One test per trap. These are the cases exact matching gets wrong."""

    def test_trailing_slash(self):
        u = parse_redirect_uri("https://app.example/cb/")
        self.assertIn("trailing-slash", u.hazards)
        self.assertTrue(u.path_is_open)

    def test_bare_origin_has_empty_path_hazard(self):
        u = parse_redirect_uri("https://app.example")
        self.assertIn("empty-path", u.hazards)
        self.assertTrue(u.path_is_open)

    def test_root_path_is_also_open(self):
        u = parse_redirect_uri("https://app.example/")
        self.assertIn("empty-path", u.hazards)
        self.assertTrue(u.path_is_open)

    def test_default_port_written_explicitly(self):
        https = parse_redirect_uri("https://app.example:443/cb")
        self.assertIn("default-port-written", https.hazards)
        http = parse_redirect_uri("http://app.example:80/cb")
        self.assertIn("default-port-written", http.hazards)

    def test_percent_encoded_separator(self):
        u = parse_redirect_uri("https://app.example/cb%2Fsub")
        self.assertIn("percent-encoded-reserved", u.hazards)

    def test_percent_encoding_case_is_a_distinct_hazard(self):
        lower = parse_redirect_uri("https://app.example/cb%2fsub")
        self.assertIn("percent-encoding-case", lower.hazards)
        upper = parse_redirect_uri("https://app.example/cb%2Fsub")
        self.assertNotIn("percent-encoding-case", upper.hazards)

    def test_userinfo_component_changes_the_host(self):
        u = parse_redirect_uri("https://app.example@evil.example/cb")
        self.assertIn("userinfo", u.hazards)
        self.assertEqual(u.host, "evil.example")
        self.assertEqual(u.userinfo, "app.example")

    def test_punycode_host(self):
        u = parse_redirect_uri("https://xn--80ak6aa92e.example/cb")
        self.assertIn("punycode-host", u.hazards)

    def test_unicode_host(self):
        u = parse_redirect_uri("https://аpp.example/cb")
        self.assertIn("idn-unicode-host", u.hazards)

    def test_backslash_gives_two_hosts(self):
        u = parse_redirect_uri("https://app.example\\@evil.example/cb")
        self.assertIn("backslash", u.hazards)
        self.assertTrue(u.host_is_ambiguous)
        self.assertEqual(u.host, "evil.example")
        self.assertEqual(u.browser_host, "app.example")

    def test_backslash_without_authority_confusion_is_still_flagged(self):
        u = parse_redirect_uri("https://app.example/cb\\sub")
        self.assertIn("backslash", u.hazards)
        self.assertFalse(u.host_is_ambiguous)

    def test_double_slash_in_path(self):
        u = parse_redirect_uri("https://app.example//cb")
        self.assertIn("double-slash", u.hazards)

    def test_dot_segment(self):
        self.assertIn("dot-segment", parse_redirect_uri("https://app.example/a/../cb").hazards)
        self.assertIn("dot-segment", parse_redirect_uri("https://app.example/./cb").hazards)

    def test_uppercase_host_is_lowercased_and_recorded(self):
        u = parse_redirect_uri("https://APP.Example/cb")
        self.assertEqual(u.host, "app.example")
        self.assertIn("uppercase-host", u.hazards)

    def test_trailing_dot_host(self):
        u = parse_redirect_uri("https://app.example./cb")
        self.assertIn("trailing-dot-host", u.hazards)

    def test_destination_shaped_query(self):
        u = parse_redirect_uri("https://app.example/login?next=/home")
        self.assertIn("credential-shaped-query", u.hazards)

    def test_hazards_are_deduplicated_and_ordered(self):
        u = parse_redirect_uri("https://app.example/a/./b/../c%2fd/")
        self.assertEqual(len(u.hazards), len(set(u.hazards)))


class Canonicalisation(unittest.TestCase):
    def test_dot_segments_resolve(self):
        self.assertEqual(resolve_dot_segments("/a/../cb"), "/cb")
        self.assertEqual(resolve_dot_segments("/a/./cb"), "/a/cb")
        self.assertEqual(resolve_dot_segments("/a/b/../../cb"), "/cb")
        self.assertEqual(resolve_dot_segments("/a/.."), "/")

    def test_empty_segments_collapse(self):
        self.assertEqual(collapse_empty_segments("//cb"), "/cb")
        self.assertEqual(collapse_empty_segments("/a//b"), "/a/b")
        self.assertEqual(collapse_empty_segments("/a/b"), "/a/b")

    def test_default_port_is_equivalent_to_no_port(self):
        self.assertTrue(
            equivalent(
                parse_redirect_uri("https://app.example/cb"),
                parse_redirect_uri("https://app.example:443/cb"),
            )
        )

    def test_case_of_host_does_not_change_equivalence(self):
        self.assertTrue(
            equivalent(
                parse_redirect_uri("https://app.example/cb"),
                parse_redirect_uri("https://APP.EXAMPLE/cb"),
            )
        )

    def test_trailing_slash_is_not_equivalent(self):
        """The paths genuinely differ, and a router may treat them differently."""
        self.assertFalse(
            equivalent(
                parse_redirect_uri("https://app.example/cb"),
                parse_redirect_uri("https://app.example/cb/"),
            )
        )

    def test_dot_segment_escape_is_equivalent_to_its_target(self):
        self.assertTrue(
            equivalent(
                parse_redirect_uri("https://app.example/cb/../other"),
                parse_redirect_uri("https://app.example/other"),
            )
        )

    def test_exact_match_is_string_equality(self):
        self.assertTrue(exact_match("https://app.example/cb", "https://app.example/cb"))
        self.assertFalse(exact_match("https://app.example/cb", "https://app.example/cb/"))
        self.assertFalse(exact_match("https://app.example/cb", "https://APP.example/cb"))


class SchemeClassification(unittest.TestCase):
    def test_loopback_hosts(self):
        for host in ("localhost", "127.0.0.1"):
            self.assertTrue(parse_redirect_uri(f"http://{host}:1234/cb").is_loopback, host)
        self.assertTrue(parse_redirect_uri("http://[::1]:1234/cb").is_loopback)
        self.assertFalse(parse_redirect_uri("http://app.example/cb").is_loopback)

    def test_reverse_dns_private_use_scheme(self):
        u = parse_redirect_uri("com.example.app:/oauth2redirect")
        self.assertTrue(u.is_private_use_scheme)
        self.assertTrue(u.is_reverse_dns_scheme)
        self.assertFalse(u.is_http)

    def test_bare_private_use_scheme_is_not_reverse_dns(self):
        u = parse_redirect_uri("myapp://callback")
        self.assertTrue(u.is_private_use_scheme)
        self.assertFalse(u.is_reverse_dns_scheme)

    def test_wildcards_survive_parsing_in_the_right_component(self):
        host = parse_redirect_uri("https://*.app.example/cb")
        self.assertTrue(host.has_wildcard)
        self.assertEqual(host.host, "*.app.example")
        self.assertEqual(host.path, "/cb")
        path = parse_redirect_uri("https://app.example/cb/*")
        self.assertTrue(path.has_wildcard)
        self.assertEqual(path.host, "app.example")


class HostHelpers(unittest.TestCase):
    def test_shared_platform_suffixes(self):
        self.assertEqual(is_shared_platform_host("preview.pages.dev"), "pages.dev")
        self.assertEqual(is_shared_platform_host("thing.vercel.app"), "vercel.app")
        self.assertIsNone(is_shared_platform_host("app.example"))

    def test_suffix_match_requires_a_label_boundary(self):
        self.assertIsNone(is_shared_platform_host("notpages.dev"))

    def test_host_in_domain(self):
        self.assertTrue(host_in_domain("a.b.example", "b.example"))
        self.assertTrue(host_in_domain("b.example", "b.example"))
        self.assertTrue(host_in_domain("a.b.example", "*.b.example"))
        self.assertFalse(host_in_domain("ab.example", "b.example"))

    def test_reflecting_path_segments(self):
        self.assertEqual(reflecting_path_segment("/redirect"), "redirect")
        self.assertEqual(reflecting_path_segment("/a/goto/b"), "goto")
        self.assertIsNone(reflecting_path_segment("/auth/callback"))

    def test_looseness_orders_registrations(self):
        strict = parse_redirect_uri("https://app.example/auth/callback")
        open_path = parse_redirect_uri("https://app.example/")
        wildcard = parse_redirect_uri("https://*.app.example/cb")
        self.assertLess(looseness_score(strict), looseness_score(open_path))
        self.assertLess(looseness_score(open_path), looseness_score(wildcard))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
