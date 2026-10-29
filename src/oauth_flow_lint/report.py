"""Rendering: text for a terminal, JSON for a pipeline, Markdown for a report."""

from __future__ import annotations

import json
import textwrap
from collections.abc import Iterable

from .engine import Report
from .escalation import BY_ID, matrix_rows
from .findings import CATEGORIES, RULES, Finding, Severity
from .probes import Probe

SEVERITY_MARK = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
    Severity.INFO: "INFO",
}


def _wrap(text: str, indent: str = "        ", width: int = 96) -> str:
    out = []
    for para in text.split("\n"):
        if not para.strip():
            out.append("")
            continue
        out.extend(
            textwrap.wrap(
                para,
                width=width,
                initial_indent=indent,
                subsequent_indent=indent,
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
    return "\n".join(out)


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------
def render_text(report: Report, threshold: Severity, show_all: bool) -> str:
    lines: list[str] = []
    cfg = report.config
    lines.append(f"oauth-flow-lint  {cfg.source_path}")
    lines.append(
        f"client {cfg.client.client_id!r} "
        f"({cfg.client.client_type}/{cfg.client.application_type}), "
        f"{len(cfg.providers)} provider(s): {', '.join(p.name for p in cfg.providers)}"
    )
    lines.append("")

    if cfg.unknown_keys:
        lines.append("configuration keys this build does not understand (checks that did not run):")
        for key in cfg.unknown_keys:
            lines.append(f"  ? {key}")
        lines.append("")

    shown = report.findings if show_all else report.at_or_above(threshold)
    escalations = [f for f in shown if f.rule.category == "escalation"]
    base = [f for f in shown if f.rule.category != "escalation"]

    if escalations:
        lines.append("=" * 100)
        lines.append("ESCALATED COMBINATIONS")
        lines.append("=" * 100)
        for f in escalations:
            lines.extend(_render_finding(f, escalation=True))
        lines.append("")

    if base:
        lines.append("=" * 100)
        lines.append("FINDINGS")
        lines.append("=" * 100)
        last_category = None
        for f in base:
            if f.rule.category != last_category:
                last_category = f.rule.category
                lines.append("")
                lines.append(f"-- {CATEGORIES[last_category]} " + "-" * (94 - len(CATEGORIES[last_category])))
            lines.extend(_render_finding(f, escalation=False))

    if not shown:
        lines.append(
            "No findings."
            if show_all
            else f"No findings at or above {threshold.label}."
            + (
                f" ({len(report.findings)} below it; pass --all to see them.)"
                if report.findings
                else ""
            )
        )

    lines.append("")
    lines.append("-" * 100)
    counts = report.counts()
    lines.append(
        "total: "
        + ", ".join(f"{counts[s.label]} {s.label}" for s in reversed(Severity))
        + f"  (threshold: {threshold.label}"
        + ("; showing all severities" if show_all else "")
        + ")"
    )
    if report.escalations:
        lines.append(
            "escalations: " + ", ".join(sorted({f.rule_id for f in report.escalations}))
        )
    return "\n".join(lines) + "\n"


def _render_finding(f: Finding, escalation: bool) -> list[str]:
    lines = [""]
    mark = SEVERITY_MARK[f.severity]
    suffix = ""
    if f.severity != f.rule.severity and not escalation:
        suffix = f" [adjusted from {f.rule.severity.label}]"
    lines.append(f"[{mark}] {f.rule_id}  {f.rule.name}{suffix}")
    lines.append(f"        at: {f.locus}")
    lines.append(_wrap(f.detail))
    if escalation:
        lines.append(_wrap(f"mechanism: {f.rule.mechanism}"))
    if f.escalated_into:
        lines.append(_wrap("escalates into: " + ", ".join(f.escalated_into)))
    if f.rule.reference:
        lines.append(_wrap(f"reference: {f.rule.reference}"))
    if f.rule.remediation:
        lines.append(_wrap(f"fix: {f.rule.remediation}"))
    return lines


def render_json(report: Report, threshold: Severity, show_all: bool) -> str:
    cfg = report.config
    shown = report.findings if show_all else report.at_or_above(threshold)
    payload = {
        "tool": "oauth-flow-lint",
        "source": cfg.source_path,
        "client": {
            "client_id": cfg.client.client_id,
            "client_type": cfg.client.client_type,
            "application_type": cfg.client.application_type,
            "effectively_public": cfg.client.is_public,
        },
        "providers": [
            {
                "name": p.name,
                "issuer": p.issuer,
                "redirect_uri_matching": p.redirect_uri_matching,
                "discovery_document": p.discovery_path,
            }
            for p in cfg.providers
        ],
        "threshold": threshold.label,
        "counts": report.counts(),
        "highest_severity": report.highest().label if report.highest() else None,
        "unknown_configuration_keys": cfg.unknown_keys,
        "findings": [f.to_dict() for f in shown],
        "escalations_fired": sorted({f.rule_id for f in report.escalations}),
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


def render_markdown(report: Report, threshold: Severity, show_all: bool) -> str:
    cfg = report.config
    shown = report.findings if show_all else report.at_or_above(threshold)
    out: list[str] = []
    out.append(f"# oauth-flow-lint report: `{cfg.client.client_id}`")
    out.append("")
    out.append(f"- Source: `{cfg.source_path}`")
    out.append(f"- Client: `{cfg.client.client_type}` / `{cfg.client.application_type}`" + (" (effectively public)" if cfg.client.is_public else ""))
    out.append(f"- Providers: {', '.join('`' + p.name + '`' for p in cfg.providers)}")
    counts = report.counts()
    out.append("- Findings: " + ", ".join(f"{counts[s.label]} {s.label}" for s in reversed(Severity)))
    out.append("")

    escalations = [f for f in shown if f.rule.category == "escalation"]
    if escalations:
        out.append("## Escalated combinations")
        out.append("")
        for f in escalations:
            out.append(f"### {f.rule_id} — {f.rule.name} ({f.severity.label})")
            out.append("")
            out.append(f"**{f.rule.mechanism}**")
            out.append("")
            out.append(f.detail)
            out.append("")
            if f.rule.remediation:
                out.append(f"*Fix:* {f.rule.remediation}")
                out.append("")

    base = [f for f in shown if f.rule.category != "escalation"]
    if base:
        out.append("## Findings")
        out.append("")
        out.append("| Severity | ID | Name | Locus | Escalates into |")
        out.append("| --- | --- | --- | --- | --- |")
        for f in base:
            out.append(
                f"| {f.severity.label} | {f.rule_id} | {f.rule.name} | `{f.locus}` | "
                + (", ".join(f.escalated_into) or "—")
                + " |"
            )
        out.append("")
        for f in base:
            out.append(f"### {f.rule_id} — {f.rule.name} ({f.severity.label})")
            out.append("")
            out.append(f"*At:* `{f.locus}`")
            out.append("")
            out.append(f.detail)
            out.append("")
            out.append(f"*Mechanism:* {f.rule.mechanism}")
            out.append("")
            if f.rule.reference:
                out.append(f"*Reference:* {f.rule.reference}")
                out.append("")
            if f.rule.remediation:
                out.append(f"*Fix:* {f.rule.remediation}")
                out.append("")

    if not shown:
        out.append("No findings." if show_all else f"No findings at or above {threshold.label}.")
        out.append("")

    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------
PLAN_PREAMBLE = (
    "These are requests for a tester to send by hand, against a system they are authorised to test. "
    "oauth-flow-lint does not send them: this package contains no networking code. Each probe says what a "
    "vulnerable provider does and what a correct one does, because 'it returned an error' and 'it returned an "
    "error to the URI I asked it to' are different results."
)


def render_plan_text(probes: Iterable[Probe], source: str) -> str:
    probes = list(probes)
    lines = [f"oauth-flow-lint plan  {source}", ""]
    lines.append(_wrap(PLAN_PREAMBLE, indent=""))
    lines.append("")
    group = None
    for p in probes:
        if p.group != group:
            group = p.group
            lines.append("")
            lines.append(f"== {group} " + "=" * (96 - len(group)))
        lines.append("")
        lines.append(f"  {p.id}  {p.intent}")
        if p.parameters:
            for key, value in p.parameters.items():
                if key == "_":
                    lines.append(f"        action: {value}")
                else:
                    lines.append(f"        {key} = {value}")
        lines.append(_wrap(f"vulnerable: {p.vulnerable_response}"))
        lines.append(_wrap(f"correct:    {p.correct_response}"))
        if p.note:
            lines.append(_wrap(f"note:       {p.note}"))
    lines.append("")
    lines.append(f"{len(probes)} probes.")
    return "\n".join(lines) + "\n"


def render_plan_json(probes: Iterable[Probe], source: str) -> str:
    probes = list(probes)
    return (
        json.dumps(
            {
                "tool": "oauth-flow-lint",
                "command": "plan",
                "source": source,
                "notice": PLAN_PREAMBLE,
                "probe_count": len(probes),
                "probes": [p.to_dict() for p in probes],
            },
            indent=2,
        )
        + "\n"
    )


def render_plan_markdown(probes: Iterable[Probe], source: str) -> str:
    probes = list(probes)
    out = [f"# oauth-flow-lint probe plan: `{source}`", "", PLAN_PREAMBLE, ""]
    group = None
    for p in probes:
        if p.group != group:
            group = p.group
            out.append(f"## {group}")
            out.append("")
        out.append(f"### {p.id} — {p.intent}")
        out.append("")
        if p.parameters:
            out.append("```")
            for key, value in p.parameters.items():
                out.append(f"{key} = {value}" if key != "_" else f"(action) {value}")
            out.append("```")
            out.append("")
        out.append(f"- **Vulnerable:** {p.vulnerable_response}")
        out.append(f"- **Correct:** {p.correct_response}")
        if p.note:
            out.append(f"- **Note:** {p.note}")
        out.append("")
    out.append(f"{len(probes)} probes.")
    out.append("")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------
def render_rules_text(matrix_only: bool) -> str:
    lines: list[str] = []
    if not matrix_only:
        lines.append("RULES")
        lines.append("=" * 100)
        for category, title in CATEGORIES.items():
            if category == "escalation":
                continue
            lines.append("")
            lines.append(f"-- {title}")
            for rule in RULES.values():
                if rule.category != category:
                    continue
                lines.append(f"  {rule.id}  {rule.severity.label:8} {rule.name}")
                lines.append(_wrap(rule.mechanism, indent="           "))
                if rule.reference:
                    lines.append(_wrap(f"ref: {rule.reference}", indent="           "))
        lines.append("")
    lines.append("ESCALATION MATRIX")
    lines.append("=" * 100)
    for row in matrix_rows():
        esc = BY_ID[str(row["id"])]
        lines.append("")
        lines.append(f"  {esc.id}  {esc.severity.label:8} {esc.name}")
        lines.append(f"           any of {list(esc.left)}")
        lines.append(f"         + any of {list(esc.right)}")
        lines.append(_wrap(esc.mechanism, indent="           "))
    lines.append("")
    base = len([r for r in RULES.values() if r.category != "escalation"])
    lines.append(f"{base} rules, {len(matrix_rows())} escalations.")
    return "\n".join(lines) + "\n"


def render_rules_json(matrix_only: bool) -> str:
    payload: dict[str, object] = {"tool": "oauth-flow-lint"}
    if not matrix_only:
        payload["rules"] = [
            {
                "id": r.id,
                "name": r.name,
                "category": r.category,
                "severity": r.severity.label,
                "mechanism": r.mechanism,
                "reference": r.reference,
                "remediation": r.remediation,
            }
            for r in RULES.values()
            if r.category != "escalation"
        ]
    payload["escalations"] = matrix_rows()
    return json.dumps(payload, indent=2) + "\n"


def render_rules_markdown(matrix_only: bool) -> str:
    out: list[str] = []
    if not matrix_only:
        out.append("## Findings")
        out.append("")
        out.append("| ID | Name | Severity | Mechanism |")
        out.append("| --- | --- | --- | --- |")
        for r in RULES.values():
            if r.category == "escalation":
                continue
            out.append(f"| `{r.id}` | {r.name} | {r.severity.label} | {r.mechanism} |")
        out.append("")
    out.append("## Escalation matrix")
    out.append("")
    out.append("| ID | Severity | Any of | Combined with any of | Result |")
    out.append("| --- | --- | --- | --- | --- |")
    for esc in BY_ID.values():
        left = ", ".join(f"`{x}`" for x in esc.left)
        right = ", ".join(f"`{x}`" for x in esc.right)
        out.append(f"| `{esc.id}` | {esc.severity.label} | {left} | {right} | {esc.mechanism} |")
    out.append("")
    return "\n".join(out) + "\n"
