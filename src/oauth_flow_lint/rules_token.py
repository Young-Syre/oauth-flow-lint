"""Token handling and ID token validation checks.

An ID token is a bearer assertion about identity. Every validation step the
client skips widens the set of parties who can write that assertion, which is
why these checks are stated in terms of who gains the ability to mint one
rather than in terms of a missing field.
"""

from __future__ import annotations

from .findings import Finding, Severity, finding
from .model import Configuration
from .urls import parse_redirect_uri

#: Above this, an access token held in a browser is long-lived enough that the
#: leak paths described by the other rules matter more than the refresh cycle.
BROWSER_ACCESS_TOKEN_CEILING_SECONDS = 3600

def check(config: Configuration) -> list[Finding]:
    client = config.client
    t = client.tokens
    out: list[Finding] = []
    locus = f"client {client.client_id}"

    if client.requests_id_token:
        out.extend(_check_id_token(config, locus))

    # -- transport ---------------------------------------------------------
    if t.access_token_transport == "query":
        out.append(
            finding(
                "TK009",
                locus=locus,
                detail="access_token_transport is 'query', so the bearer token is written into request URLs - the one component of a request that is logged by default at every hop and sent onward in the Referer.",
                evidence={"transport": "query"},
            )
        )
    elif t.access_token_transport == "unknown":
        out.append(
            finding(
                "TK009",
                locus=locus,
                detail="How the access token is carried to resource servers has not been established. Until it is known, the query-string method cannot be ruled out.",
                severity_override=Severity.LOW,
                evidence={"transport": "unknown"},
            )
        )

    # -- refresh tokens ----------------------------------------------------
    if t.refresh_token_issued:
        if client.is_public and not t.refresh_token_rotation:
            out.append(
                finding(
                    "TK010",
                    locus=locus,
                    detail=(
                        "A refresh token is issued to a client that cannot authenticate itself, and it is not rotated on use. "
                        "One capture gives an attacker a credential that renews itself, that is indistinguishable from the real "
                        "client's, and whose reuse produces no signal the provider can act on."
                    ),
                )
            )
        if t.refresh_token_lifetime_seconds <= 0:
            out.append(
                finding(
                    "TK012",
                    locus=locus,
                    detail="refresh_token_lifetime_seconds is not set to a positive value, so the refresh token has no absolute expiry and revocation is the only way it ever stops working.",
                    evidence={"refresh_token_lifetime_seconds": t.refresh_token_lifetime_seconds},
                )
            )

    # -- access token lifetime --------------------------------------------
    if client.is_browser_based:
        if t.access_token_lifetime_seconds <= 0:
            out.append(
                finding(
                    "TK011",
                    locus=locus,
                    detail="access_token_lifetime_seconds is not set to a positive value for a browser client, so the lifetime is whatever the provider defaults to and the leak window is not a property anyone has chosen.",
                    evidence={"access_token_lifetime_seconds": t.access_token_lifetime_seconds},
                )
            )
        elif t.access_token_lifetime_seconds > BROWSER_ACCESS_TOKEN_CEILING_SECONDS:
            out.append(
                finding(
                    "TK011",
                    locus=locus,
                    detail=f"The access token lives for {t.access_token_lifetime_seconds} seconds in a browser client, above the {BROWSER_ACCESS_TOKEN_CEILING_SECONDS}-second ceiling this tool applies.",
                    evidence={"access_token_lifetime_seconds": t.access_token_lifetime_seconds},
                )
            )

    # -- storage -----------------------------------------------------------
    if t.browser_storage in ("localstorage", "sessionstorage"):
        out.append(
            finding(
                "TK013",
                locus=locus,
                detail=(
                    f"Tokens are held in {t.browser_storage}. Any script that executes on this origin can read them, which "
                    "includes script introduced by a cross-site scripting bug anywhere on the origin and script in any "
                    "third-party dependency the page loads."
                ),
                evidence={"browser_storage": t.browser_storage},
            )
        )

    return out


def _check_id_token(config: Configuration, locus: str) -> list[Finding]:
    client = config.client
    v = client.id_token_validation
    out: list[Finding] = []

    if not v.signature_verified:
        out.append(
            finding(
                "TK001",
                locus=locus,
                detail="signature_verified is false. The claims in the ID token - including sub, the value the application treats as the user's identity - are supplied by whoever sent the token.",
            )
        )

    if v.accepts_none_alg:
        out.append(
            finding(
                "TK003",
                locus=locus,
                detail="accepts_none_alg is true. An unsigned token is accepted, so an identity assertion for any user can be written by hand.",
            )
        )

    if not v.alg_pinned:
        out.append(
            finding(
                "TK002",
                locus=locus,
                detail=(
                    "alg_pinned is false, so the algorithm used to verify the token is read from the token's own header. "
                    "The token then chooses its own verification: the standard result is a token signed with HMAC-SHA256 using the "
                    "provider's published RSA public key as the shared secret, which a verifier that trusts the header accepts."
                ),
            )
        )
    elif not v.accepted_algs:
        out.append(
            finding(
                "TK002",
                locus=locus,
                detail="alg_pinned is true but accepted_algs is empty, so there is no record of what it is pinned to. A pin nobody can state is a pin nobody has reviewed.",
                severity_override=Severity.LOW,
            )
        )
    else:
        bad = [a for a in v.accepted_algs if a.lower() == "none"]
        if bad:
            out.append(
                finding(
                    "TK003",
                    locus=locus,
                    detail=f"accepted_algs contains {bad!r}, so the unsigned algorithm is on the allow-list.",
                )
            )

    if not v.aud_checked:
        out.append(
            finding(
                "TK004",
                locus=locus,
                detail=(
                    "aud_checked is false. A token minted by the same provider for a different client is accepted here, so every "
                    "other client of this issuer - including one an attacker registers, if registration is open - becomes a source "
                    "of valid logins for this application."
                ),
            )
        )
    elif not v.expected_audiences:
        out.append(
            finding(
                "TK004",
                locus=locus,
                detail="aud_checked is true but expected_audiences is empty, so what the audience is compared against is not recorded.",
                severity_override=Severity.LOW,
            )
        )

    if not v.iss_checked:
        out.append(
            finding(
                "TK005",
                locus=locus,
                detail="iss_checked is false, so a token's origin is unconstrained: any issuer whose key this client will accept can authenticate any user.",
            )
        )

    if not v.exp_checked:
        out.append(
            finding(
                "TK014",
                locus=locus,
                detail="exp_checked is false, so an ID token never expires from this client's point of view and a token captured once authenticates indefinitely.",
            )
        )

    if len(v.expected_audiences) > 1 and not v.azp_checked:
        out.append(
            finding(
                "TK006",
                locus=locus,
                detail=(
                    f"{len(v.expected_audiences)} audiences are expected ({v.expected_audiences}) and azp_checked is false. "
                    "With more than one audience, the audience check no longer identifies the party the token was issued to; azp does, and it is not being read."
                ),
                evidence={"expected_audiences": v.expected_audiences},
            )
        )

    # -- key resolution ----------------------------------------------------
    if v.jwks_source == "token_header":
        out.append(
            finding(
                "TK007",
                locus=locus,
                detail=(
                    "jwks_source is 'token_header', so the verification key is fetched from a location named inside the token "
                    "(jku, x5u or an embedded jwk). The token supplies its own key, and the signature check then proves only that "
                    "the token is consistent with itself."
                ),
            )
        )
    elif v.jwks_source == "unknown":
        out.append(
            finding(
                "TK008",
                locus=locus,
                detail="Where the verification keys come from has not been established. This is the single most load-bearing fact about the client's token validation, and it is not written down.",
                severity_override=Severity.HIGH,
                evidence={"jwks_source": "unknown"},
            )
        )
    elif v.jwks_source == "discovery" and not v.jwks_host_pinned:
        out.append(
            finding(
                "TK008",
                locus=locus,
                detail=(
                    "Keys are resolved through the provider's metadata document with no constraint on the host that serves them, "
                    "so the set of parties who can mint tokens this client accepts is whoever answers the metadata request."
                ),
                evidence={"jwks_source": "discovery", "jwks_host_pinned": False},
            )
        )

    # Cross-check the declared audience against the client_id, which is the
    # value OIDC Core requires the aud claim to contain.
    if v.expected_audiences and client.client_id not in v.expected_audiences:
        out.append(
            finding(
                "TK004",
                locus=locus,
                detail=(
                    f"expected_audiences is {v.expected_audiences} and does not contain this client's client_id "
                    f"({client.client_id!r}), so the audience comparison does not accept the tokens the provider issues to this client - "
                    "or the comparison is against something other than the client identifier."
                ),
                severity_override=Severity.MEDIUM,
                evidence={
                    "client_id": client.client_id,
                    "expected_audiences": v.expected_audiences,
                },
            )
        )

    # An issuer string that is not an https URL cannot be compared meaningfully.
    for provider in config.providers:
        if not provider.issuer:
            continue
        parsed = parse_redirect_uri(provider.issuer)
        if parsed.valid and parsed.scheme == "http":
            out.append(
                finding(
                    "TK005",
                    locus=f"provider {provider.name}",
                    detail=f"The configured issuer {provider.issuer!r} uses http, so the identifier the client compares against names an origin that is not authenticated.",
                    severity_override=Severity.MEDIUM,
                    evidence={"issuer": provider.issuer},
                )
            )

    return out
