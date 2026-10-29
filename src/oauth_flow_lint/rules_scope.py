"""Scope and consent checks.

Scope is the only place in an OAuth configuration where the blast radius of a
leaked token is set, and it is usually set once, early, by whoever was getting
the flow to work.
"""

from __future__ import annotations

from .findings import Finding, finding
from .model import Configuration


def check(config: Configuration) -> list[Finding]:
    client = config.client
    out: list[Finding] = []
    locus = f"client {client.client_id}"

    scopes = list(client.scopes)
    purpose = set(client.stated_purpose_scopes)

    if "offline_access" in scopes and "offline_access" not in purpose:
        out.append(
            finding(
                "SC001",
                locus=locus,
                detail=(
                    "offline_access is in the default scope set but is not in stated_purpose_scopes, so every flow this client "
                    "runs asks for a refresh token whether or not that flow needs one."
                ),
                evidence={"scopes": scopes},
            )
        )

    for provider in config.providers:
        if provider.grants_offline_access_without_request:
            out.append(
                finding(
                    "SC001",
                    locus=f"provider {provider.name}",
                    detail="This provider grants offline access without the client requesting it, so refresh tokens are issued by default and the client's scope list does not describe what it holds.",
                    evidence={"grants_offline_access_without_request": True},
                )
            )

    if purpose:
        extra = [s for s in scopes if s not in purpose]
        if extra:
            out.append(
                finding(
                    "SC002",
                    locus=locus,
                    detail=(
                        f"The client requests {extra}, which stated_purpose_scopes does not include. Either the purpose statement "
                        "is out of date or the client holds authority it has no use for; both are answered by the same question, "
                        "asked of whoever owns the client."
                    ),
                    evidence={"requested_beyond_purpose": extra, "purpose": sorted(purpose)},
                )
            )

    if not client.scope_change_reconsent:
        out.append(
            finding(
                "SC003",
                locus=locus,
                detail=(
                    "scope_change_reconsent is false, so a later authorisation request can widen the granted scope without the "
                    "user being asked again. The grant in force is then larger than the grant the user agreed to, and nothing shows them the difference."
                ),
            )
        )

    return out
