"""The shipped examples, and the invariants the catalogue itself must hold.

The examples are part of the documentation, so they are tested as
documentation: each one must say what it demonstrates, must produce what the
README says it produces, and must contain nothing that looks like a real
tenant's configuration.
"""

from __future__ import annotations

import re
import tomllib
import unittest

from oauth_flow_lint.escalation import MATRIX
from oauth_flow_lint.findings import CATEGORIES, RULES, Severity
from oauth_flow_lint.loader import load_file
from oauth_flow_lint.probes import build
from tests.helpers import EXAMPLES, REPO_ROOT, run

HARDENED = EXAMPLES / "hardened-web-confidential.toml"
NATIVE = EXAMPLES / "hardened-native-pkce.toml"
VULNERABLE = EXAMPLES / "vulnerable-spa-implicit.toml"
MULTI_IDP = EXAMPLES / "multi-idp-missing-iss.toml"

ALL_EXAMPLES = (HARDENED, NATIVE, VULNERABLE, MULTI_IDP)

#: Only reserved, unresolvable names belong in a fixture. RFC 2606 reserves
#: .example, .invalid and .test; RFC 6761 reserves .localhost.
PERMITTED_TLDS = ("example", "invalid", "test", "localhost")

#: Two deliberate exceptions, both needed to demonstrate a rule that can only
#: fire on a real-world shape, and both written so that no reader could mistake
#: them for someone's tenant.
#:
#: * the loopback literals, which RU006 is about;
#: * one placeholder label on a real multi-tenant platform suffix, which is the
#:   only way to demonstrate RU009 - the rule matches the suffix, so a reserved
#:   domain cannot exercise it.
PERMITTED_HOSTS = (
    "127.0.0.1",
    "localhost",
    "::1",
    "oauth-flow-lint-placeholder.pages.dev",
)


class ExamplesExist(unittest.TestCase):
    def test_there_are_at_least_four(self):
        found = sorted(p.name for p in EXAMPLES.glob("*.toml"))
        self.assertGreaterEqual(len(found), 4)
        for path in ALL_EXAMPLES:
            self.assertTrue(path.exists(), path.name)

    def test_each_one_loads(self):
        for path in ALL_EXAMPLES:
            cfg = load_file(path)
            self.assertTrue(cfg.providers, path.name)

    def test_none_has_an_unrecognised_key(self):
        for path in ALL_EXAMPLES:
            self.assertEqual(load_file(path).unknown_keys, [], path.name)

    def test_each_one_opens_with_a_comment_explaining_itself(self):
        for path in ALL_EXAMPLES:
            first = path.read_text(encoding="utf-8").lstrip().splitlines()[0]
            self.assertTrue(first.startswith("#"), path.name)
            self.assertGreater(len(path.read_text(encoding="utf-8").split("schema")[0]), 200, path.name)


class HardenedExamples(unittest.TestCase):
    def test_the_confidential_web_client_is_completely_clean(self):
        report = run(load_file(HARDENED))
        self.assertEqual(report.findings, [])

    def test_the_native_client_reports_only_the_informational_loopback_note(self):
        report = run(load_file(NATIVE))
        self.assertEqual([f.rule_id for f in report.findings], ["RU006"])
        self.assertEqual(report.findings[0].severity, Severity.INFO)

    def test_the_native_client_is_clean_at_the_default_threshold(self):
        report = run(load_file(NATIVE))
        self.assertEqual(report.at_or_above(Severity.MEDIUM), [])

    def test_the_native_example_registers_both_specified_mechanisms(self):
        cfg = load_file(NATIVE)
        schemes = {u.scheme for u in cfg.client.parsed_redirect_uris}
        self.assertIn("http", schemes)
        self.assertIn("com.example.fieldapp", schemes)


class EscalationExample(unittest.TestCase):
    def setUp(self):
        self.report = run(load_file(VULNERABLE))
        self.ids = {f.rule_id for f in self.report.findings}

    def test_it_produces_the_headline_escalation(self):
        self.assertIn("ESC001", self.ids)

    def test_the_headline_escalation_is_critical(self):
        esc = next(f for f in self.report.findings if f.rule_id == "ESC001")
        self.assertEqual(esc.severity, Severity.CRITICAL)

    def test_it_also_produces_the_forgery_and_replay_combinations(self):
        for rule_id in ("ESC005", "ESC006", "ESC007", "ESC008", "ESC010", "ESC011", "ESC012", "ESC014"):
            self.assertIn(rule_id, self.ids, rule_id)

    def test_it_produces_findings_in_every_category(self):
        categories = {f.rule.category for f in self.report.findings}
        for category in CATEGORIES:
            self.assertIn(category, categories, category)

    def test_the_components_of_esc001_are_present_and_annotated(self):
        esc = next(f for f in self.report.findings if f.rule_id == "ESC001")
        for rule_id in esc.evidence["contributing_rules"]:
            contributors = [f for f in self.report.findings if f.rule_id == rule_id]
            self.assertTrue(contributors, rule_id)
            self.assertTrue(
                any("ESC001" in f.escalated_into for f in contributors), rule_id
            )

    def test_the_capture_contradicts_the_declared_registration(self):
        self.assertIn("CP006", self.ids)


class MultiIdpExample(unittest.TestCase):
    def setUp(self):
        self.report = run(load_file(MULTI_IDP))
        self.ids = {f.rule_id for f in self.report.findings}

    def test_it_produces_the_mix_up_escalation(self):
        self.assertIn("ESC004", self.ids)

    def test_the_mix_up_escalation_is_critical(self):
        esc = next(f for f in self.report.findings if f.rule_id == "ESC004")
        self.assertEqual(esc.severity, Severity.CRITICAL)

    def test_it_is_otherwise_a_competent_client(self):
        """Nothing in the token validation or redirect URI rules fires."""
        for rule_id in self.ids:
            self.assertFalse(rule_id.startswith("TK"), rule_id)
            self.assertFalse(rule_id.startswith("RU"), rule_id)

    def test_three_providers_are_configured(self):
        self.assertEqual(len(load_file(MULTI_IDP).providers), 3)


class PlansBuildForEveryExample(unittest.TestCase):
    def test_every_example_produces_probes(self):
        for path in ALL_EXAMPLES:
            probes = build(load_file(path))
            self.assertGreater(len(probes), 20, path.name)

    def test_probe_ids_are_unique_within_a_plan(self):
        for path in ALL_EXAMPLES:
            ids = [p.id for p in build(load_file(path))]
            self.assertEqual(len(ids), len(set(ids)), path.name)

    def test_every_probe_states_both_outcomes(self):
        for path in ALL_EXAMPLES:
            for probe in build(load_file(path)):
                self.assertTrue(probe.vulnerable_response, f"{path.name}:{probe.id}")
                self.assertTrue(probe.correct_response, f"{path.name}:{probe.id}")
                self.assertTrue(probe.group, f"{path.name}:{probe.id}")


class FixtureHygiene(unittest.TestCase):
    """The examples must not look like anybody's real configuration."""

    def example_text(self):
        for path in sorted(EXAMPLES.iterdir()):
            if path.is_file():
                yield path, path.read_text(encoding="utf-8")

    def test_every_host_is_a_reserved_or_placeholder_name(self):
        host_pattern = re.compile(r"https?://([A-Za-z0-9*.\-]+)")
        for path, text in self.example_text():
            for host in host_pattern.findall(text):
                bare = host.rstrip(".").lower()
                if bare in PERMITTED_HOSTS:
                    continue
                tld = bare.rsplit(".", 1)[-1]
                self.assertIn(tld, PERMITTED_TLDS, f"{path.name}: {host}")

    def test_no_fixture_contains_a_token_shaped_literal(self):
        jwt_shape = re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")
        for path, text in self.example_text():
            self.assertIsNone(jwt_shape.search(text), path.name)

    def test_secret_and_credential_values_are_the_placeholder(self):
        for path, text in self.example_text():
            for match in re.findall(r"(?:access_token|id_token|code|state|nonce|client_secret)=([^&\"'\s]+)", text):
                self.assertIn(
                    match,
                    ("REDACTED-TEST-VALUE", "REDACTED", "code", "1762000000"),
                    f"{path.name}: {match}",
                )

    def test_no_private_key_block_anywhere_in_the_repository(self):
        needle = "-----BEGIN " + "PRIVATE KEY-----"
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            self.assertNotIn(needle, text, str(path.relative_to(REPO_ROOT)))


class CatalogueInvariants(unittest.TestCase):
    def test_every_rule_has_a_mechanism_sentence(self):
        for rule in RULES.values():
            self.assertGreater(len(rule.mechanism), 60, rule.id)
            self.assertTrue(rule.mechanism[0].isupper() or rule.mechanism.startswith("`"), rule.id)

    def test_every_rule_has_a_remediation(self):
        for rule in RULES.values():
            self.assertTrue(rule.remediation.strip(), rule.id)

    def test_every_non_escalation_rule_belongs_to_a_known_category(self):
        for rule in RULES.values():
            self.assertIn(rule.category, CATEGORIES, rule.id)

    def test_rule_names_are_unique(self):
        names = [r.name for r in RULES.values()]
        self.assertEqual(len(names), len(set(names)))

    def test_rule_names_are_kebab_case(self):
        for rule in RULES.values():
            self.assertRegex(rule.name, r"^[a-z0-9]+(-[a-z0-9]+)*$", rule.id)

    def test_rule_ids_follow_the_category_prefix(self):
        prefixes = {
            "redirect": "RU",
            "flow": "FL",
            "state": "SN",
            "token": "TK",
            "scope": "SC",
            "provider": "PV",
            "capture": "CP",
            "escalation": "ESC",
        }
        for rule in RULES.values():
            self.assertTrue(rule.id.startswith(prefixes[rule.category]), rule.id)

    def test_every_catalogued_rule_can_actually_fire(self):
        """A rule nobody can trigger is documentation pretending to be code."""
        emitted = set()
        for path in ALL_EXAMPLES:
            emitted |= {f.rule_id for f in run(load_file(path)).findings}
        for module_test in (
            "tests.test_rules_redirect",
            "tests.test_rules_flow",
            "tests.test_rules_state",
            "tests.test_rules_token",
            "tests.test_rules_scope_provider",
            "tests.test_rules_capture",
            "tests.test_escalation",
        ):
            __import__(module_test)
        # Every rule ID must appear in the test suite's source, which is how we
        # know it has a test, and every escalation must appear in the matrix.
        suite_source = "".join(
            p.read_text(encoding="utf-8") for p in sorted((REPO_ROOT / "tests").glob("*.py"))
        )
        for rule_id in RULES:
            self.assertIn(rule_id, suite_source, f"{rule_id} has no test")

    def test_the_escalation_count_matches_the_matrix(self):
        self.assertEqual(
            len([r for r in RULES.values() if r.category == "escalation"]), len(MATRIX)
        )

    def test_severity_ordering_is_usable_as_a_threshold(self):
        self.assertGreater(Severity.CRITICAL, Severity.HIGH)
        self.assertGreater(Severity.HIGH, Severity.MEDIUM)
        self.assertGreater(Severity.MEDIUM, Severity.LOW)
        self.assertGreater(Severity.LOW, Severity.INFO)

    def test_the_scaffold_shipped_in_the_package_is_valid_toml(self):
        from oauth_flow_lint.scaffold import scaffold_text

        tomllib.loads(scaffold_text())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
