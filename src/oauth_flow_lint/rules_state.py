"""State, nonce and issuer-binding checks.

All three answer the same question in different places: can the client tell
that the response it is processing belongs to the request it made, from the
provider it made it to? A value that is generated and echoed but never
compared answers none of them, which is why these rules look at the binding
fields rather than at whether a parameter is present.
"""

from __future__ import annotations

from .findings import Finding, Severity, finding
from .model import Configuration

MIN_STATE_ENTROPY_BITS = 128


def check(config: Configuration) -> list[Finding]:
    client = config.client
    state = client.state
    nonce = client.nonce
    out: list[Finding] = []
    locus = f"client {client.client_id}"

    # -- state -------------------------------------------------------------
    if not state.sent:
        out.append(
            finding(
                "SN001",
                locus=locus,
                detail="No state parameter is sent. The callback handler cannot distinguish a response to its own request from one an attacker caused the browser to make.",
            )
        )
    else:
        if not state.bound_to_session:
            out.append(
                finding(
                    "SN002",
                    locus=locus,
                    detail=(
                        "state is sent but bound_to_session is false, so the value is not compared against anything held for this "
                        "user. An attacker starts their own flow, takes the state value it produced, and uses it in a request aimed at the victim."
                    ),
                )
            )
        if not state.single_use:
            out.append(
                finding(
                    "SN003",
                    locus=locus,
                    detail="state is not single-use, so a captured callback URL remains valid and can be replayed.",
                )
            )
        if state.source in ("timestamp", "counter", "static"):
            out.append(
                finding(
                    "SN004",
                    locus=locus,
                    detail=f"state is generated from a {state.source!r} source, which an attacker can reproduce or guess, so the comparison on callback succeeds for a response they initiated.",
                    evidence={"source": state.source},
                )
            )
        elif state.source == "unknown":
            out.append(
                finding(
                    "SN004",
                    locus=locus,
                    detail="The source of the state value has not been established. Until it is known to be a cryptographically secure generator, it must be treated as predictable.",
                    severity_override=Severity.MEDIUM,
                    evidence={"source": "unknown"},
                )
            )
        elif state.entropy_bits and state.entropy_bits < MIN_STATE_ENTROPY_BITS:
            out.append(
                finding(
                    "SN004",
                    locus=locus,
                    detail=f"state carries {state.entropy_bits} bits of entropy, below the {MIN_STATE_ENTROPY_BITS}-bit floor this tool applies; a value small enough to enumerate is a value an attacker can supply.",
                    severity_override=Severity.MEDIUM,
                    evidence={"entropy_bits": state.entropy_bits},
                )
            )

    # -- nonce -------------------------------------------------------------
    if client.requests_id_token:
        why = (
            "response_types requests an id_token"
            if any("id_token" in rt.split() for rt in client.response_types)
            else "the openid scope is requested, so an ID token is returned"
        )
        if not nonce.sent:
            out.append(
                finding(
                    "SN005",
                    locus=locus,
                    detail=f"No nonce is sent and {why}. The returned ID token cannot be tied to this authentication request.",
                    evidence={"reason": why},
                )
            )
        elif not nonce.bound_to_session:
            out.append(
                finding(
                    "SN006",
                    locus=locus,
                    detail="A nonce is sent but bound_to_session is false, so no comparison happens against the nonce claim in the returned ID token. The parameter is present and the binding is not.",
                )
            )

    # -- issuer identification --------------------------------------------
    missing_iss = [p.name for p in config.providers if not p.returns_iss_parameter]
    if missing_iss:
        if config.multi_provider:
            out.append(
                finding(
                    "SN007",
                    locus=", ".join(f"provider {n}" for n in missing_iss),
                    detail=(
                        f"{len(config.providers)} providers are configured and {len(missing_iss)} of them "
                        f"({', '.join(missing_iss)}) do not return the iss authorisation response parameter. "
                        "The client therefore infers the issuer from its own stored state rather than from the response, which is "
                        "the mix-up condition: a response produced by one issuer is processed as though it came from another."
                    ),
                    evidence={
                        "providers_without_iss": missing_iss,
                        "provider_count": len(config.providers),
                    },
                )
            )
        else:
            out.append(
                finding(
                    "SN008",
                    locus=f"provider {missing_iss[0]}",
                    detail=(
                        "The iss authorisation response parameter is not returned. With a single issuer there is nothing to "
                        "confuse it with today; the risk is that adding a second issuer is a configuration change, not a code "
                        "change, so nothing in the client would be reviewed at the point the condition appears."
                    ),
                )
            )

    return out
