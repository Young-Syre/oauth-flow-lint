"""Cross-checks against a captured authorisation request and response.

A configuration describes what someone believes the client does. A captured
URL records what it did. Where the two disagree, the capture wins, and the
disagreement is itself the finding: it means the configuration under review is
not the configuration in force.

The captured URLs are parsed, never requested.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from .findings import Finding, Severity, finding
from .model import Capture, Configuration
from .urls import exact_match

#: Credentials that have no business in a query component. A ``code`` is
#: deliberately absent: the query is exactly where the code flow puts it, and a
#: linter that reports the specified behaviour teaches people to ignore it.
QUERY_CREDENTIAL_PARAMS = ("access_token", "id_token", "refresh_token")

#: Anything in the fragment is front-channel delivery, including a code, which
#: in the fragment means the response mode is not the one a code flow needs.
FRAGMENT_CREDENTIAL_PARAMS = ("access_token", "id_token", "refresh_token", "code")


def _params(url: str) -> tuple[dict[str, str], dict[str, str], str | None]:
    """Return (query params, fragment params, error)."""
    if not url:
        return {}, {}, None
    try:
        split = urlsplit(url)
    except ValueError as exc:
        return {}, {}, f"unparseable URL: {exc}"
    query = dict(parse_qsl(split.query, keep_blank_values=True))
    fragment = dict(parse_qsl(split.fragment, keep_blank_values=True))
    return query, fragment, None


def check(config: Configuration) -> list[Finding]:
    out: list[Finding] = []
    for capture in config.captures:
        out.extend(_check_capture(config, capture))
    return out


def _check_capture(config: Configuration, capture: Capture) -> list[Finding]:
    client = config.client
    out: list[Finding] = []

    req_q, req_f, req_err = _params(capture.authorization_request)
    res_q, res_f, res_err = _params(capture.authorization_response)
    locus = f"capture {capture.label}"

    if capture.authorization_request and not req_err:
        request = req_q or req_f
        response_type = request.get("response_type", "")

        if response_type and response_type not in client.response_types:
            out.append(
                finding(
                    "CP001",
                    locus=locus,
                    detail=(
                        f"The captured request sends response_type={response_type!r}, which is not in the client's declared "
                        f"response_types ({client.response_types}). The provider accepted it, so response types are not pinned "
                        "for this client."
                    ),
                    evidence={"observed": response_type, "declared": client.response_types},
                )
            )

        if "state" not in request:
            out.append(
                finding(
                    "CP002",
                    locus=locus,
                    detail="The captured authorisation request has no state parameter."
                    + (" The configuration says state is sent, so the configuration is describing a different code path." if client.state.sent else ""),
                    evidence={"declared_state_sent": client.state.sent},
                )
            )

        wants_code = "code" in response_type.split() if response_type else client.uses_code
        if wants_code and "code_challenge" not in request:
            out.append(
                finding(
                    "CP003",
                    locus=locus,
                    detail="The captured authorisation request has no code_challenge."
                    + (" The configuration declares PKCE in use, so what was captured is not what was configured." if client.pkce.used else ""),
                    severity_override=Severity.HIGH if client.is_public else Severity.MEDIUM,
                    evidence={"declared_pkce_used": client.pkce.used},
                )
            )
        elif "code_challenge" in request:
            method = request.get("code_challenge_method", "plain")
            if method != client.pkce.method:
                out.append(
                    finding(
                        "CP003",
                        locus=locus,
                        detail=(
                            f"The captured request sends code_challenge_method={method!r} while the configuration declares "
                            f"{client.pkce.method!r}."
                            + (" When the parameter is omitted the specification's default is 'plain'." if "code_challenge_method" not in request else "")
                        ),
                        severity_override=Severity.MEDIUM,
                        evidence={"observed_method": method, "declared_method": client.pkce.method},
                    )
                )

        wants_id_token = "id_token" in response_type.split() if response_type else client.requests_id_token
        if wants_id_token and "nonce" not in request:
            out.append(
                finding(
                    "CP004",
                    locus=locus,
                    detail="The captured request asks for an ID token and carries no nonce.",
                    evidence={"response_type": response_type},
                )
            )

        observed_redirect = request.get("redirect_uri")
        if observed_redirect and not any(exact_match(observed_redirect, r) for r in client.redirect_uris):
            out.append(
                finding(
                    "CP006",
                    locus=locus,
                    detail=(
                        f"The captured request sends redirect_uri={observed_redirect!r}, which is not equal as a string to any "
                        f"registered value ({client.redirect_uris}). The provider accepted it, so its comparison is looser than "
                        "a string comparison - whatever the configuration claims."
                    ),
                    evidence={"observed": observed_redirect, "registered": client.redirect_uris},
                )
            )

    if capture.authorization_response and not res_err:
        for name in QUERY_CREDENTIAL_PARAMS:
            if name in res_q:
                out.append(
                    finding(
                        "CP005",
                        locus=locus,
                        detail=f"The captured authorisation response carries {name} in the query component.",
                        evidence={"parameter": name},
                    )
                )
        for name in FRAGMENT_CREDENTIAL_PARAMS:
            if name in res_f:
                out.append(
                    finding(
                        "CP008",
                        locus=locus,
                        detail=(
                            f"The captured authorisation response carries {name} in the fragment, which confirms front-channel "
                            "credential delivery as observed behaviour rather than as a configuration claim."
                            + (
                                " A code in the fragment also means the response mode is not the one the code flow needs."
                                if name == "code"
                                else ""
                            )
                        ),
                        severity_override=Severity.MEDIUM if name == "code" else None,
                        evidence={"parameter": name},
                    )
                )

        if "iss" not in res_q and "iss" not in res_f:
            out.append(
                finding(
                    "CP007",
                    locus=locus,
                    detail="The captured authorisation response carries no iss parameter, so the issuer cannot be established from the response.",
                    severity_override=Severity.HIGH if config.multi_provider else None,
                    evidence={"provider_count": len(config.providers)},
                )
            )

    if capture.resource_request:
        q, _fragment, err = _params(capture.resource_request)
        if not err:
            for name in ("access_token", "token", "bearer"):
                if name in q:
                    out.append(
                        finding(
                            "CP005",
                            locus=f"{locus} resource request",
                            detail=f"The captured resource request carries {name} in the query component.",
                            evidence={"parameter": name},
                        )
                    )

    return out
