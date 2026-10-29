"""Run every rule over a configuration, then apply the escalation matrix."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import (
    rules_capture,
    rules_flow,
    rules_provider,
    rules_redirect,
    rules_scope,
    rules_state,
    rules_token,
)
from .findings import Finding, Severity, sort_key
from .model import Configuration

#: In the order the output reads most naturally: where a response can be
#: delivered, what the response contains, whether it can be tied to a request,
#: what is done with what it contained, then the provider's own posture.
CHECK_MODULES = (
    rules_redirect,
    rules_flow,
    rules_state,
    rules_token,
    rules_scope,
    rules_provider,
    rules_capture,
)


@dataclass
class Report:
    config: Configuration
    findings: list[Finding] = field(default_factory=list)

    def at_or_above(self, threshold: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= threshold]

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in reversed(Severity)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def highest(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


def run(config: Configuration) -> Report:
    findings: list[Finding] = []
    for module in CHECK_MODULES:
        findings.extend(module.check(config))
    findings.sort(key=sort_key)
    return Report(config=config, findings=findings)
