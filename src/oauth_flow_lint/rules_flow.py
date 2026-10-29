"""Flow and grant selection checks.

These rules decide *what* an authorisation response carries. On their own some
of them are arguable - an implicit-flow client behind a single exact-matched
callback on a dedicated origin is survivable - which is exactly why they are
joined to the redirect rules in :mod:`escalation` rather than being graded in
isolation.
"""

from __future__ import annotations

from .findings import Finding, Severity, finding
from .model import Configuration


def check(config: Configuration) -> list[Finding]:
    client = config.client
    out: list[Finding] = []
    locus = f"client {client.client_id}"

    implicit_types = [rt for rt in client.response_types if "token" in rt.split()]
    if implicit_types:
        out.append(
            finding(
                "FL001",
                locus=locus,
                detail=(
                    f"response_types includes {', '.join(repr(t) for t in implicit_types)}, so an access token is returned "
                    "in the URL fragment of the callback. Nothing in that exchange authenticates the client, and the fragment "
                    "survives in history and is sent onward by the callback page."
                ),
                evidence={"response_types": implicit_types},
            )
        )
        if client.application_type == "native":
            out.append(
                finding(
                    "FL007",
                    locus=locus,
                    detail=(
                        "This is a native client using a response type that returns a token in the front channel. The front "
                        "channel on a device is a URI scheme or a loopback listener, both of which other software can claim."
                    ),
                    evidence={"response_types": implicit_types},
                )
            )

    hybrid = client.hybrid_response_types
    if hybrid:
        carries_token = any("token" in rt.split() for rt in hybrid)
        out.append(
            finding(
                "FL002",
                locus=locus,
                detail=(
                    f"response_types includes the hybrid value(s) {', '.join(repr(t) for t in hybrid)}. The back-channel code "
                    "exchange does not protect the part delivered through the front channel: "
                    + (
                        "an access token in the fragment leaks exactly as it does in the implicit flow."
                        if carries_token
                        else "an ID token in the fragment is a replayable identity assertion if the client's nonce handling is not exact."
                    )
                ),
                severity_override=Severity.HIGH if carries_token else None,
                evidence={"response_types": hybrid},
            )
        )

    # -- PKCE --------------------------------------------------------------
    if client.uses_code and client.uses_authorization_code_grant:
        if not client.pkce.used:
            if client.is_public:
                out.append(
                    finding(
                        "FL003",
                        locus=locus,
                        detail=(
                            f"This is a public client ({client.client_type}/{client.application_type}) running the authorisation "
                            "code flow with no code_challenge. The code is the only credential in the exchange, and anything that "
                            "intercepts the redirect can exchange it."
                        ),
                    )
                )
            else:
                out.append(
                    finding(
                        "FL003",
                        locus=locus,
                        detail=(
                            "This confidential client runs the authorisation code flow with no code_challenge. The client secret "
                            "still stands between an intercepted code and a token, so the exposure is narrower than for a public "
                            "client - but it does not cover code injection into this client's own session."
                        ),
                        severity_override=Severity.LOW,
                    )
                )
        else:
            if client.pkce.method == "plain":
                out.append(
                    finding(
                        "FL004",
                        locus=locus,
                        detail="code_challenge_method is 'plain', so the challenge sent in the authorisation request is the verifier sent to the token endpoint.",
                        evidence={"method": "plain"},
                    )
                )
            for provider in config.providers:
                if provider.pkce_methods and client.pkce.method not in provider.pkce_methods:
                    out.append(
                        finding(
                            "FL010",
                            locus=f"provider {provider.name}",
                            detail=(
                                f"The client declares code_challenge_method {client.pkce.method!r}, but this provider advertises "
                                f"{provider.pkce_methods}. Either the request fails or it degrades to a method the client did not choose."
                            ),
                            evidence={
                                "client_method": client.pkce.method,
                                "provider_methods": provider.pkce_methods,
                            },
                        )
                    )

        for provider in config.providers:
            if not provider.enforces_pkce:
                out.append(
                    finding(
                        "FL005",
                        locus=f"provider {provider.name}",
                        detail=(
                            "enforces_pkce is false, so code_challenge is optional on this provider. A party who can shape the "
                            "authorisation request - which includes anyone who can get the victim's browser to start a flow - "
                            "omits it and receives a code that needs no verifier."
                            + (
                                " The client's own use of PKCE is therefore not a control an attacker has to defeat."
                                if client.pkce.used
                                else ""
                            )
                        ),
                        severity_override=Severity.HIGH if client.is_public else None,
                        evidence={"client_uses_pkce": client.pkce.used},
                    )
                )
            if "plain" in provider.pkce_methods:
                out.append(
                    finding(
                        "FL011",
                        locus=f"provider {provider.name}",
                        detail=f"pkce_methods includes 'plain' ({provider.pkce_methods}), so the weaker method remains requestable.",
                        evidence={"provider_methods": provider.pkce_methods},
                    )
                )

    # -- grants ------------------------------------------------------------
    if "password" in client.grant_types:
        out.append(
            finding(
                "FL006",
                locus=locus,
                detail="grant_types includes 'password'. The client handles the user's primary credential directly, so the provider's own authentication policy - including any second factor - is not in the path.",
                evidence={"grant_types": client.grant_types},
            )
        )

    # -- client authentication --------------------------------------------
    if client.secret_present and client.application_type in ("spa", "native"):
        out.append(
            finding(
                "FL008",
                locus=locus,
                detail=(
                    f"A client secret is configured for a {client.application_type!r} application. The secret ships to the user, "
                    "so it is not a secret; any provider-side decision that depends on this client being confidential is being "
                    "made on a false premise."
                ),
                evidence={"application_type": client.application_type},
            )
        )
    elif client.secret_present and client.client_type == "public":
        out.append(
            finding(
                "FL008",
                locus=locus,
                detail="A client secret is configured for a client registered as public. One of the two statements is wrong, and the provider will act on the registration.",
                severity_override=Severity.MEDIUM,
            )
        )

    # -- response mode -----------------------------------------------------
    if client.response_mode == "fragment" and not client.uses_implicit:
        out.append(
            finding(
                "FL009",
                locus=locus,
                detail="response_mode is 'fragment' on a flow that returns a code. The code lands where page script can read it and where the browser keeps it, for no gain over query or form_post.",
                evidence={"response_mode": client.response_mode},
            )
        )

    return out
