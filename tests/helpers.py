"""Builders for test configurations.

The baseline is a hardened client that produces no findings, so every test can
state exactly one deviation and assert exactly what it causes. A test that has
to describe a whole configuration to make its point is a test whose point is
not clear.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from oauth_flow_lint import engine
from oauth_flow_lint.findings import Finding, Severity
from oauth_flow_lint.model import (
    PKCE,
    Capture,
    Client,
    Configuration,
    IdTokenValidation,
    NonceHandling,
    Provider,
    StateHandling,
    TokenHandling,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"


def hardened_client(**overrides: object) -> Client:
    client = Client(
        client_id="test-client",
        client_type="confidential",
        application_type="web",
        secret_present=True,
        redirect_uris=["https://app.example/auth/callback"],
        response_types=["code"],
        response_mode="query",
        grant_types=["authorization_code", "refresh_token"],
        scopes=["openid", "profile"],
        stated_purpose_scopes=["openid", "profile"],
        scope_change_reconsent=True,
        pkce=PKCE(used=True, method="S256"),
        state=StateHandling(
            sent=True, bound_to_session=True, single_use=True, entropy_bits=256, source="csprng"
        ),
        nonce=NonceHandling(sent=True, bound_to_session=True),
        id_token_validation=IdTokenValidation(
            signature_verified=True,
            alg_pinned=True,
            accepted_algs=["RS256"],
            accepts_none_alg=False,
            aud_checked=True,
            iss_checked=True,
            exp_checked=True,
            azp_checked=True,
            jwks_source="pinned",
            jwks_host_pinned=True,
            expected_audiences=["test-client"],
        ),
        tokens=TokenHandling(
            access_token_transport="header",
            refresh_token_issued=True,
            refresh_token_rotation=True,
            access_token_lifetime_seconds=600,
            refresh_token_lifetime_seconds=2592000,
            browser_storage="server",
        ),
    )
    return replace(client, **overrides) if overrides else client


def hardened_provider(**overrides: object) -> Provider:
    provider = Provider(
        name="test-idp",
        issuer="https://idp.example",
        redirect_uri_matching="exact",
        enforces_pkce=True,
        pkce_methods=["S256"],
        returns_iss_parameter=True,
        dynamic_client_registration="closed",
        supports_request_uri=False,
        grants_offline_access_without_request=False,
    )
    return replace(provider, **overrides) if overrides else provider


def config(
    client: Client | None = None,
    providers: list[Provider] | None = None,
    captures: list[Capture] | None = None,
) -> Configuration:
    return Configuration(
        client=client if client is not None else hardened_client(),
        providers=providers if providers is not None else [hardened_provider()],
        captures=captures or [],
        source_path="<test>",
    )


def run(cfg: Configuration):
    return engine.run(cfg)


def ids(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings}


def fired(cfg: Configuration) -> set[str]:
    return ids(run(cfg).findings)


def severity_of(cfg: Configuration, rule_id: str) -> Severity:
    matches = [f for f in run(cfg).findings if f.rule_id == rule_id]
    if not matches:
        raise AssertionError(f"{rule_id} did not fire")
    return max(f.severity for f in matches)


def detail_of(cfg: Configuration, rule_id: str) -> str:
    return " ".join(f.detail for f in run(cfg).findings if f.rule_id == rule_id)
