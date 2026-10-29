"""The command line interface, its output formats, and its exit codes."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from oauth_flow_lint.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from oauth_flow_lint.findings import RULES
from tests.helpers import EXAMPLES

HARDENED = EXAMPLES / "hardened-web-confidential.toml"
VULNERABLE = EXAMPLES / "vulnerable-spa-implicit.toml"
MULTI_IDP = EXAMPLES / "multi-idp-missing-iss.toml"
NATIVE = EXAMPLES / "hardened-native-pkce.toml"


def invoke(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


class ExitCodes(unittest.TestCase):
    def test_a_clean_configuration_exits_zero(self):
        code, _, _ = invoke("lint", str(HARDENED))
        self.assertEqual(code, EXIT_OK)

    def test_a_configuration_with_findings_exits_one(self):
        code, _, _ = invoke("lint", str(VULNERABLE))
        self.assertEqual(code, EXIT_FINDINGS)

    def test_an_unreadable_configuration_exits_two(self):
        code, _, err = invoke("lint", "/nonexistent/config.toml")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("cannot read", err)

    def test_an_invalid_enumeration_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.toml"
            path.write_text(
                '[client]\nclient_id="c"\nclient_type="semi"\n[provider]\nname="p"\n',
                encoding="utf-8",
            )
            code, _, err = invoke("lint", str(path))
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("is not one of", err)

    def test_no_subcommand_prints_help_and_exits_two(self):
        code, out, _ = invoke()
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("usage: oauth-flow-lint", out)

    def test_the_threshold_changes_the_exit_code(self):
        low, _, _ = invoke("lint", str(NATIVE), "--fail-on", "info")
        self.assertEqual(low, EXIT_FINDINGS)
        high, _, _ = invoke("lint", str(NATIVE), "--fail-on", "medium")
        self.assertEqual(high, EXIT_OK)

    def test_a_critical_threshold_still_catches_the_escalation_case(self):
        code, _, _ = invoke("lint", str(VULNERABLE), "--fail-on", "critical")
        self.assertEqual(code, EXIT_FINDINGS)

    def test_the_multi_idp_example_exits_one(self):
        code, _, _ = invoke("lint", str(MULTI_IDP))
        self.assertEqual(code, EXIT_FINDINGS)


class TextOutput(unittest.TestCase):
    def test_the_header_names_the_client_and_the_providers(self):
        _, out, _ = invoke("lint", str(MULTI_IDP))
        self.assertIn("workspace-federated-login", out)
        self.assertIn("primary-idp", out)
        self.assertIn("customer-b-idp", out)

    def test_escalations_are_printed_before_the_component_findings(self):
        _, out, _ = invoke("lint", str(VULNERABLE))
        self.assertLess(out.index("ESCALATED COMBINATIONS"), out.index("FINDINGS\n"))

    def test_the_escalation_case_reports_esc001(self):
        _, out, _ = invoke("lint", str(VULNERABLE))
        self.assertIn("ESC001", out)
        self.assertIn("front-channel-token-to-attacker-controlled-path", out)

    def test_component_findings_point_at_the_escalation(self):
        _, out, _ = invoke("lint", str(VULNERABLE))
        self.assertIn("escalates into:", out)

    def test_a_clean_configuration_says_so(self):
        _, out, _ = invoke("lint", str(HARDENED))
        self.assertIn("No findings", out)

    def test_the_all_flag_shows_the_informational_native_finding(self):
        _, without, _ = invoke("lint", str(NATIVE))
        _, with_all, _ = invoke("lint", str(NATIVE), "--all")
        self.assertNotIn("RU006", without)
        self.assertIn("RU006", with_all)

    def test_an_adjusted_severity_is_marked_as_such(self):
        _, out, _ = invoke("lint", str(VULNERABLE), "--all")
        self.assertIn("[adjusted from", out)

    def test_the_summary_line_counts_every_severity(self):
        _, out, _ = invoke("lint", str(VULNERABLE))
        self.assertIn("total:", out)
        for label in ("critical", "high", "medium", "low", "info"):
            self.assertIn(label, out)


class JsonOutput(unittest.TestCase):
    def payload(self, *argv: str) -> dict:
        _, out, _ = invoke(*argv)
        return json.loads(out)

    def test_the_document_is_valid_json(self):
        data = self.payload("lint", str(VULNERABLE), "--format", "json")
        self.assertEqual(data["tool"], "oauth-flow-lint")

    def test_each_finding_carries_its_mechanism_and_severity(self):
        data = self.payload("lint", str(VULNERABLE), "--format", "json")
        for f in data["findings"]:
            self.assertIn(f["id"], RULES)
            self.assertTrue(f["mechanism"])
            self.assertIn(f["severity"], ("critical", "high", "medium", "low", "info"))

    def test_the_escalations_that_fired_are_listed_separately(self):
        data = self.payload("lint", str(VULNERABLE), "--format", "json")
        self.assertIn("ESC001", data["escalations_fired"])

    def test_the_client_block_records_that_an_spa_is_effectively_public(self):
        data = self.payload("lint", str(VULNERABLE), "--format", "json")
        self.assertTrue(data["client"]["effectively_public"])

    def test_the_provider_block_records_the_metadata_path_that_was_read(self):
        data = self.payload("lint", str(VULNERABLE), "--format", "json")
        self.assertTrue(data["providers"][0]["discovery_document"].endswith(".json"))

    def test_a_clean_configuration_produces_an_empty_findings_list(self):
        data = self.payload("lint", str(HARDENED), "--format", "json")
        self.assertEqual(data["findings"], [])
        self.assertIsNone(data["highest_severity"])

    def test_the_threshold_is_recorded_in_the_document(self):
        data = self.payload("lint", str(VULNERABLE), "--format", "json", "--fail-on", "high")
        self.assertEqual(data["threshold"], "high")
        for f in data["findings"]:
            self.assertIn(f["severity"], ("critical", "high"))


class MarkdownOutput(unittest.TestCase):
    def test_the_report_has_a_findings_table(self):
        _, out, _ = invoke("lint", str(VULNERABLE), "--format", "markdown")
        self.assertIn("| Severity | ID | Name | Locus | Escalates into |", out)

    def test_escalations_get_their_own_section(self):
        _, out, _ = invoke("lint", str(VULNERABLE), "--format", "markdown")
        self.assertIn("## Escalated combinations", out)
        self.assertIn("### ESC001", out)

    def test_a_clean_configuration_produces_a_short_report(self):
        _, out, _ = invoke("lint", str(HARDENED), "--format", "markdown")
        self.assertIn("No findings at or above medium.", out)


class PlanCommand(unittest.TestCase):
    def test_the_plan_exits_zero_even_for_a_vulnerable_configuration(self):
        code, _, _ = invoke("plan", str(VULNERABLE))
        self.assertEqual(code, EXIT_OK)

    def test_the_plan_states_that_nothing_is_sent(self):
        _, out, _ = invoke("plan", str(HARDENED))
        self.assertIn("contains no networking code", out)

    def test_the_plan_includes_the_normalisation_probes(self):
        _, out, _ = invoke("plan", str(HARDENED))
        for label in (
            "appended-path-segment",
            "trailing-slash",
            "dot-segment-escape",
            "double-slash",
            "backslash-authority",
            "userinfo-authority",
            "default-port-written",
            "uppercase-host",
            "sibling-subdomain",
            "scheme-downgrade",
        ):
            self.assertIn(label, out, label)

    def test_the_plan_includes_every_response_type_permutation(self):
        _, out, _ = invoke("plan", str(HARDENED))
        for rt in ("'code'", "'token'", "'id_token'", "'id_token token'", "'code id_token token'"):
            self.assertIn(rt, out, rt)

    def test_the_plan_includes_the_pkce_enforcement_probes(self):
        _, out, _ = invoke("plan", str(HARDENED))
        self.assertIn("omit code_challenge entirely", out)
        self.assertIn("redeem the code with a different verifier", out)
        self.assertIn("redeem the code with no code_verifier at all", out)

    def test_the_plan_includes_the_state_probes(self):
        _, out, _ = invoke("plan", str(HARDENED))
        self.assertIn("omit state", out)
        self.assertIn("replay the full callback URL", out)
        self.assertIn("ten state values", out)

    def test_a_multi_provider_configuration_gets_a_mix_up_probe(self):
        _, out, _ = invoke("plan", str(MULTI_IDP))
        self.assertIn("cross-deliver", out)

    def test_a_single_provider_configuration_gets_no_mix_up_probe(self):
        _, out, _ = invoke("plan", str(HARDENED))
        self.assertNotIn("cross-deliver", out)

    def test_the_request_uri_probe_carries_an_authorisation_caveat(self):
        _, out, _ = invoke("plan", str(VULNERABLE))
        self.assertIn("only against a host you control", out.lower())

    def test_the_plan_renders_as_json(self):
        _, out, _ = invoke("plan", str(HARDENED), "--format", "json")
        data = json.loads(out)
        self.assertEqual(data["command"], "plan")
        self.assertEqual(data["probe_count"], len(data["probes"]))
        self.assertGreater(data["probe_count"], 30)
        for probe in data["probes"]:
            self.assertTrue(probe["intent"])
            self.assertTrue(probe["vulnerable_response"])
            self.assertTrue(probe["correct_response"])

    def test_the_plan_renders_as_markdown(self):
        _, out, _ = invoke("plan", str(HARDENED), "--format", "markdown")
        self.assertIn("# oauth-flow-lint probe plan", out)
        self.assertIn("**Vulnerable:**", out)

    def test_every_probe_id_is_unique(self):
        _, out, _ = invoke("plan", str(VULNERABLE), "--format", "json")
        ids = [p["id"] for p in json.loads(out)["probes"]]
        self.assertEqual(len(ids), len(set(ids)))


class InitCommand(unittest.TestCase):
    def test_init_writes_to_standard_output_by_default(self):
        code, out, _ = invoke("init")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("[client]", out)
        self.assertIn("schema = 1", out)

    def test_the_scaffold_is_commented(self):
        _, out, _ = invoke("init")
        self.assertIn("# oauth-flow-lint configuration.", out)
        self.assertIn("never performs network requests", out)

    def test_the_scaffold_lints_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scaffold.toml"
            code, _, _ = invoke("init", str(path))
            self.assertEqual(code, EXIT_OK)
            lint_code, out, _ = invoke("lint", str(path), "--all")
            self.assertEqual(lint_code, EXIT_OK, out)
            self.assertIn("No findings", out)

    def test_the_scaffold_has_no_unknown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scaffold.toml"
            invoke("init", str(path))
            _, out, _ = invoke("lint", str(path), "--format", "json")
            self.assertEqual(json.loads(out)["unknown_configuration_keys"], [])

    def test_init_refuses_to_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scaffold.toml"
            invoke("init", str(path))
            code, _, err = invoke("init", str(path))
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("--force", err)

    def test_force_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scaffold.toml"
            invoke("init", str(path))
            path.write_text("clobbered", encoding="utf-8")
            code, _, _ = invoke("init", str(path), "--force")
            self.assertEqual(code, EXIT_OK)
            self.assertIn("[client]", path.read_text(encoding="utf-8"))

    def test_an_unwritable_destination_exits_two(self):
        code, _, err = invoke("init", "/nonexistent-directory/scaffold.toml")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("cannot write", err)


class RulesCommand(unittest.TestCase):
    def test_the_catalogue_lists_every_rule(self):
        _, out, _ = invoke("rules")
        for rule_id in RULES:
            self.assertIn(rule_id, out, rule_id)

    def test_the_matrix_flag_omits_the_catalogue(self):
        """The matrix still names rule IDs; what it drops is their entries."""
        _, out, _ = invoke("rules", "--matrix")
        self.assertIn("ESCALATION MATRIX", out)
        self.assertNotIn("RULES\n", out)
        self.assertNotIn("redirect-uri-wildcard", out)

    def test_the_catalogue_renders_as_json(self):
        _, out, _ = invoke("rules", "--format", "json")
        data = json.loads(out)
        self.assertEqual(
            len(data["rules"]), len([r for r in RULES.values() if r.category != "escalation"])
        )
        self.assertEqual(len(data["escalations"]), 14)

    def test_the_catalogue_renders_as_markdown_tables(self):
        _, out, _ = invoke("rules", "--format", "markdown")
        self.assertIn("| ID | Name | Severity | Mechanism |", out)
        self.assertIn("| ID | Severity | Any of | Combined with any of | Result |", out)

    def test_the_counts_line_is_accurate(self):
        _, out, _ = invoke("rules")
        base = len([r for r in RULES.values() if r.category != "escalation"])
        self.assertIn(f"{base} rules, 14 escalations.", out)


class Warnings(unittest.TestCase):
    def test_an_unrecognised_key_is_reported_in_text_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.toml"
            path.write_text(
                '[client]\nclient_id="c"\nredirect_uris=["https://app.example/cb"]\n'
                'typoed_key=1\n[provider]\nname="p"\nredirect_uri_matching="exact"\n',
                encoding="utf-8",
            )
            _, out, _ = invoke("lint", str(path))
            self.assertIn("client.typoed_key", out)
            self.assertIn("checks that did not run", out)

    def test_an_unrecognised_key_is_reported_on_stderr_for_machine_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.toml"
            path.write_text(
                '[client]\nclient_id="c"\nredirect_uris=["https://app.example/cb"]\n'
                'typoed_key=1\n[provider]\nname="p"\nredirect_uri_matching="exact"\n',
                encoding="utf-8",
            )
            _, _, err = invoke("lint", str(path), "--format", "json")
            self.assertIn("typoed_key", err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
