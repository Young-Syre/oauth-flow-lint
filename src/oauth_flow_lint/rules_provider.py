"""Provider and discovery metadata checks.

The discovery document is read from a local file. The tool has no code that
can fetch one, which is a constraint, not an omission: a linter that reaches
out to an authorisation server is a linter you cannot run against a production
tenant during review, and the document is one curl away in any case.
"""

from __future__ import annotations

from .findings import Finding, Severity, finding
from .model import Configuration, Provider
from .urls import parse_redirect_uri

#: Metadata members that name an endpoint, per RFC 8414 and OIDC Discovery.
ENDPOINT_KEYS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "end_session_endpoint",
    "device_authorization_endpoint",
    "pushed_authorization_request_endpoint",
)


def check(config: Configuration) -> list[Finding]:
    out: list[Finding] = []
    for provider in config.providers:
        out.extend(_check_declared(config, provider))
        if provider.discovery:
            out.extend(_check_discovery(config, provider))
    return out


def _check_declared(config: Configuration, provider: Provider) -> list[Finding]:
    out: list[Finding] = []
    locus = f"provider {provider.name}"

    if provider.dynamic_client_registration == "open":
        out.append(
            finding(
                "PV006",
                locus=locus,
                detail=(
                    "dynamic_client_registration is 'open', so anyone can create a client inside this issuer. That is the "
                    "precondition for every attack whose first step is 'the attacker needs a client the provider considers legitimate'."
                ),
                evidence={"dynamic_client_registration": "open"},
            )
        )

    if provider.supports_request_uri:
        out.append(
            finding(
                "PV007",
                locus=locus,
                detail=(
                    "The provider accepts a request object by reference, so an authorisation request can name a URL for the "
                    "authorisation server to fetch. That is a server-side request forgery primitive inside the component that "
                    "issues credentials. This tool reports the capability and does not exercise it."
                ),
                evidence={"supports_request_uri": True},
            )
        )

    if provider.issuer:
        parsed = parse_redirect_uri(provider.issuer)
        if parsed.valid and parsed.scheme == "http":
            out.append(
                finding(
                    "PV001",
                    locus=f"{locus} issuer",
                    detail=f"The configured issuer {provider.issuer!r} uses http.",
                    evidence={"issuer": provider.issuer},
                )
            )

    return out


def _check_discovery(config: Configuration, provider: Provider) -> list[Finding]:
    doc = provider.discovery
    locus = f"provider {provider.name} metadata"
    out: list[Finding] = []

    # -- endpoint schemes --------------------------------------------------
    insecure: list[str] = []
    for key in ENDPOINT_KEYS:
        value = doc.get(key)
        if not isinstance(value, str) or not value:
            continue
        parsed = parse_redirect_uri(value)
        if parsed.valid and parsed.scheme == "http" and not parsed.is_loopback:
            insecure.append(f"{key}={value}")
    if insecure:
        out.append(
            finding(
                "PV001",
                locus=locus,
                detail="The metadata publishes endpoint(s) over http: " + "; ".join(insecure) + ". Anyone on the network path can answer them, and they are where codes are exchanged and keys are published.",
                evidence={"endpoints": insecure},
            )
        )

    # -- issuer agreement --------------------------------------------------
    doc_issuer = doc.get("issuer")
    if isinstance(doc_issuer, str) and provider.issuer and doc_issuer != provider.issuer:
        out.append(
            finding(
                "PV008",
                locus=locus,
                detail=(
                    f"The metadata issuer is {doc_issuer!r} and the configuration expects {provider.issuer!r}. These are compared "
                    "as strings, so the client either rejects every token from this server or is pointed at a different one than "
                    "the configuration describes."
                ),
                evidence={"metadata_issuer": doc_issuer, "configured_issuer": provider.issuer},
            )
        )

    # -- key set host ------------------------------------------------------
    jwks = doc.get("jwks_uri")
    issuer_ref = doc_issuer if isinstance(doc_issuer, str) else provider.issuer
    if isinstance(jwks, str) and jwks and issuer_ref:
        jwks_parsed = parse_redirect_uri(jwks)
        issuer_parsed = parse_redirect_uri(issuer_ref)
        if (
            jwks_parsed.valid
            and issuer_parsed.valid
            and jwks_parsed.host
            and issuer_parsed.host
            and jwks_parsed.host != issuer_parsed.host
        ):
            out.append(
                finding(
                    "PV002",
                    locus=locus,
                    detail=(
                        f"jwks_uri is served from {jwks_parsed.host!r} while the issuer is {issuer_parsed.host!r}. "
                        "Whoever controls the key host can mint tokens this issuer's clients accept, so that host is part of "
                        "the trust boundary and is probably not documented as such."
                    ),
                    evidence={"jwks_host": jwks_parsed.host, "issuer_host": issuer_parsed.host},
                )
            )

    # -- client authentication methods ------------------------------------
    methods = doc.get("token_endpoint_auth_methods_supported")
    if isinstance(methods, list) and "none" in methods:
        confidential = [
            config.client.client_id
        ] if config.client.client_type == "confidential" else []
        out.append(
            finding(
                "PV003",
                locus=locus,
                detail=(
                    "token_endpoint_auth_methods_supported includes 'none'. "
                    + (
                        f"The configured client {confidential[0]!r} is registered as confidential, so unless the provider pins the "
                        "method per client, its secret is not required to exchange a code."
                        if confidential
                        else "No confidential client is configured here, so this is a property of the server to note rather than an exposure of this client."
                    )
                ),
                severity_override=None if confidential else Severity.LOW,
                evidence={"methods": methods, "confidential_client": bool(confidential)},
            )
        )

    # -- PKCE advertisement ------------------------------------------------
    pkce_methods = doc.get("code_challenge_methods_supported")
    if pkce_methods is None:
        out.append(
            finding(
                "PV005",
                locus=locus,
                detail="code_challenge_methods_supported is absent from the metadata, so a client has no way to discover whether PKCE is available, and a client that assumes it is cannot be told otherwise.",
            )
        )
    elif isinstance(pkce_methods, list):
        if "S256" not in pkce_methods:
            out.append(
                finding(
                    "PV010",
                    locus=locus,
                    detail=f"code_challenge_methods_supported is {pkce_methods} and does not include 'S256'.",
                    evidence={"methods": pkce_methods},
                )
            )
        if "plain" in pkce_methods:
            out.append(
                finding(
                    "FL011",
                    locus=locus,
                    detail=f"The metadata advertises 'plain' among {pkce_methods}, so the downgrade is available at the protocol level regardless of what any client chooses.",
                    evidence={"methods": pkce_methods},
                )
            )

    # -- response modes and types -----------------------------------------
    modes = doc.get("response_modes_supported")
    if isinstance(modes, list) and "fragment" in modes and not config.client.uses_implicit:
        out.append(
            finding(
                "PV004",
                locus=locus,
                detail=f"response_modes_supported is {modes}; 'fragment' is offered and no configured client needs it. It stays available to anyone shaping an authorisation request for this client.",
                evidence={"modes": modes},
            )
        )

    types = doc.get("response_types_supported")
    if isinstance(types, list):
        token_types = [t for t in types if isinstance(t, str) and "token" in t.split()]
        if token_types:
            out.append(
                finding(
                    "PV009",
                    locus=locus,
                    detail=f"response_types_supported includes {token_types}, so front-channel token delivery remains reachable at this issuer.",
                    evidence={"response_types": token_types},
                )
            )

    # -- registration endpoint --------------------------------------------
    if doc.get("registration_endpoint") and provider.dynamic_client_registration == "closed":
        out.append(
            finding(
                "PV006",
                locus=locus,
                detail=(
                    "The metadata publishes a registration_endpoint while the configuration declares dynamic client registration "
                    "'closed'. One of the two is wrong, and the one that matters is the endpoint."
                ),
                severity_override=Severity.MEDIUM,
                evidence={"registration_endpoint": doc.get("registration_endpoint")},
            )
        )

    if doc.get("request_uri_parameter_supported") is True and not provider.supports_request_uri:
        out.append(
            finding(
                "PV007",
                locus=locus,
                detail="The metadata says request_uri_parameter_supported is true while the configuration declares otherwise. The server's own statement is the one an attacker will rely on.",
                evidence={"request_uri_parameter_supported": True},
            )
        )

    return out
