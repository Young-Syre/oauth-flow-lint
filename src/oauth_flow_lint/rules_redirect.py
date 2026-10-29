"""Redirect URI checks.

The redirect URI is where every front-channel credential is delivered, so a
weakness here is not a weakness in isolation - it is the delivery mechanism
for whatever the flow hands over. These checks therefore describe *reach*:
which hosts and paths can receive a response. What the response contains is
decided by the flow rules, and the two are joined in :mod:`escalation`.
"""

from __future__ import annotations

from .findings import Finding, Severity, finding
from .model import Configuration
from .urls import (
    RedirectURI,
    host_in_domain,
    is_shared_platform_host,
    looseness_score,
    reflecting_path_segment,
)


def check(config: Configuration) -> list[Finding]:
    client = config.client
    out: list[Finding] = []

    if not client.redirect_uris:
        out.append(
            finding(
                "RU018",
                locus=f"client {client.client_id}",
                detail="No redirect_uris are registered for this client.",
            )
        )
        return out

    matching = config.loosest_matching
    loose_matching = matching != "exact"

    for provider in config.providers:
        if provider.matching_is_exact:
            continue
        out.append(
            finding(
                "RU002",
                locus=f"provider {provider.name}",
                detail=(
                    f"redirect_uri_matching is {provider.redirect_uri_matching!r}. "
                    + {
                        "prefix": "Every URI that begins with a registered value is accepted, so the registered path is a prefix, not a destination.",
                        "wildcard": "The provider expands a pattern, so the accepted set is not enumerable from the registration.",
                        "unknown": "The real comparison rule has not been established, so it must be assumed to be looser than exact; the plan subcommand lists the probes that settle it.",
                    }[provider.redirect_uri_matching]
                ),
                severity_override=(
                    Severity.MEDIUM if provider.redirect_uri_matching == "unknown" else None
                ),
                evidence={"redirect_uri_matching": provider.redirect_uri_matching},
            )
        )

    parsed = client.parsed_redirect_uris
    confirmed_open = set(client.confirmed_open_redirect_uris)

    for uri in parsed:
        locus = uri.raw
        if not uri.valid:
            out.append(
                finding(
                    "RU016",
                    locus=locus,
                    detail=f"This registration could not be parsed as a URI: {uri.error}. A value the provider and the client parse differently is not a comparison either of them can win.",
                    severity_override=Severity.MEDIUM,
                    evidence={"parse_error": uri.error},
                )
            )
            continue

        out.extend(_check_one(config, uri, loose_matching, confirmed_open))

    out.extend(_check_mixed_strictness(config, parsed))
    return out


def _check_one(
    config: Configuration,
    uri: RedirectURI,
    loose_matching: bool,
    confirmed_open: set[str],
) -> list[Finding]:
    client = config.client
    locus = uri.raw
    out: list[Finding] = []

    # -- wildcards ---------------------------------------------------------
    if uri.has_wildcard:
        where = "host" if "*" in uri.host else "path"
        out.append(
            finding(
                "RU001",
                locus=locus,
                detail=f"A wildcard appears in the {where} component ({uri.host or uri.path!r}). The set of URIs this registration accepts cannot be listed.",
                evidence={"component": where},
            )
        )

    # -- open path suffix --------------------------------------------------
    if uri.is_http and uri.path_is_open:
        shape = "a bare origin with no path" if uri.path in ("", "/") else "a path ending in a slash"
        out.append(
            finding(
                "RU003",
                locus=locus,
                detail=(
                    f"The registration is {shape}, so the path component is open. "
                    + (
                        "The provider matches by prefix or by an unestablished rule, so any path under this origin is a valid callback."
                        if loose_matching
                        else "Under the provider's exact matching this is currently contained; it becomes an open origin the moment the matching rule changes or a second, looser provider is added."
                    )
                ),
                severity_override=None if loose_matching else Severity.LOW,
                evidence={"loose_matching": loose_matching},
            )
        )

    # -- scheme ------------------------------------------------------------
    if uri.scheme == "http":
        if uri.is_loopback:
            if client.application_type == "native":
                out.append(
                    finding(
                        "RU006",
                        locus=locus,
                        detail=(
                            "A loopback http callback on a native client is the mechanism the specification provides, and is not a weakness. "
                            "The provider must accept any port on this host, because the app cannot reserve one in advance."
                        ),
                        evidence={"port": uri.port},
                    )
                )
            else:
                out.append(
                    finding(
                        "RU005",
                        locus=locus,
                        detail=(
                            f"A loopback callback is registered for a {client.application_type!r} client. "
                            "Loopback redirection exists for native apps, which have no server to redirect to; a browser client does, "
                            "so this registration cannot serve a real user and exists only as a path an attacker can aim a flow at."
                        ),
                    )
                )
        else:
            out.append(
                finding(
                    "RU004",
                    locus=locus,
                    detail=(
                        f"The callback uses http on {uri.host!r}, which is not a loopback host. "
                        "The authorisation response, and therefore the code or the token, crosses the network in clear text."
                    ),
                    evidence={"host": uri.host},
                )
            )

    # -- private-use schemes ----------------------------------------------
    if uri.is_private_use_scheme and not uri.is_reverse_dns_scheme:
        out.append(
            finding(
                "RU007",
                locus=locus,
                detail=(
                    f"The scheme {uri.scheme!r} is not a reverse-DNS name. Any application on the device may register it, "
                    "and on the platforms where first registration wins, the application that registers it receives the authorisation response."
                ),
                evidence={"scheme": uri.scheme},
            )
        )

    # -- host reachability -------------------------------------------------
    for domain in client.wildcard_dns_hosts:
        if not uri.host or not host_in_domain(uri.host, domain):
            continue
        apex = uri.host.rstrip(".") == domain.lower().rstrip(".").lstrip("*").lstrip(".")
        if apex:
            # The registered name itself is not one of the wildcard-covered
            # names, so this is weaker than the subdomain case and is graded
            # accordingly - but it still matters, because the provider only has
            # to compare hosts by suffix for the wildcard to become reachable.
            out.append(
                finding(
                    "RU008",
                    locus=locus,
                    detail=(
                        f"The callback is on {uri.host!r}, and the configuration declares {domain!r} to have wildcard DNS, so every "
                        "sibling name under it is attacker-reachable. The registered name itself is not one of those, so this is only "
                        "exploitable if the provider compares hosts by suffix rather than exactly, or if the application extends trust "
                        "to its own subdomains."
                    ),
                    severity_override=Severity.MEDIUM,
                    evidence={"wildcard_domain": domain, "match": "apex"},
                )
            )
        else:
            out.append(
                finding(
                    "RU008",
                    locus=locus,
                    detail=(
                        f"The callback host {uri.host!r} is itself a name under {domain!r}, which the configuration declares as a "
                        "wildcard DNS domain. The wildcard answers for this name's siblings and, depending on how it is configured, "
                        "for this name too, so the host does not identify the application that is supposed to receive the response."
                    ),
                    evidence={"wildcard_domain": domain, "match": "subdomain"},
                )
            )
        break

    suffix = is_shared_platform_host(uri.host) if uri.host else None
    if suffix:
        out.append(
            finding(
                "RU009",
                locus=locus,
                detail=(
                    f"The callback host is on {suffix!r}, a platform-provided domain whose names are handed out to unrelated tenants. "
                    "A sibling name is cheap to obtain, and under anything looser than exact matching a sibling path on the same name is too."
                ),
                evidence={"platform_suffix": suffix},
            )
        )

    # -- forwarding behaviour ---------------------------------------------
    if uri.raw in confirmed_open:
        out.append(
            finding(
                "RU011",
                locus=locus,
                detail=(
                    "The configuration declares this callback to be a confirmed open redirector. "
                    "The authorisation response reaches it and is then forwarded to a destination chosen by the request, "
                    "which moves the credential off the registered origin entirely."
                ),
            )
        )
    else:
        segment = reflecting_path_segment(uri.path)
        if segment or "credential-shaped-query" in uri.hazards:
            detail = []
            if segment:
                detail.append(f"the path segment {segment!r} is a conventional forwarder name")
            if "credential-shaped-query" in uri.hazards:
                detail.append(f"the query component names a conventional destination parameter ({uri.query!r})")
            out.append(
                finding(
                    "RU010",
                    locus=locus,
                    detail=(
                        "This registration has the shape of a forwarding endpoint: "
                        + " and ".join(detail)
                        + ". Confirm by hand whether it forwards from a parameter; if it does, record it in "
                        "confirmed_open_redirect_uris and this becomes RU011."
                    ),
                    evidence={"segment": segment, "query": uri.query},
                )
            )

    # -- components --------------------------------------------------------
    if uri.fragment:
        out.append(
            finding(
                "RU012",
                locus=locus,
                detail=(
                    f"The registration carries the fragment {uri.fragment!r}. RFC 6749 3.1.2 forbids this, "
                    "and the fragment is the component the implicit and hybrid flows use to deliver credentials, so a provider "
                    "that accepted this registration is not comparing URIs as strings."
                ),
                evidence={"fragment": uri.fragment},
            )
        )

    if uri.query and "credential-shaped-query" not in uri.hazards:
        out.append(
            finding(
                "RU013",
                locus=locus,
                detail=(
                    f"The registration carries the query component {uri.query!r}. This is permitted, but the provider must merge "
                    "its own response parameters into the same component, and providers differ on ordering and on what happens "
                    "when a key collides with one of theirs."
                ),
                evidence={"query": uri.query},
            )
        )

    if uri.userinfo:
        out.append(
            finding(
                "RU015",
                locus=locus,
                detail=(
                    f"The authority carries the userinfo component {uri.userinfo!r}, so the host is {uri.host!r} and not what a "
                    "reader skimming the registration would take it to be."
                ),
                evidence={"userinfo": uri.userinfo, "host": uri.host},
            )
        )

    if uri.host_is_ambiguous:
        out.append(
            finding(
                "RU016",
                locus=locus,
                detail=(
                    f"This single string names two hosts. A server-side URL parser reads the host as {uri.host!r}; a browser, "
                    f"which normalises the backslash to a forward slash before splitting the authority, navigates to {uri.browser_host!r}. "
                    "Whichever side the provider compares on, the browser goes to the other."
                ),
                severity_override=Severity.HIGH,
                evidence={"parser_host": uri.host, "browser_host": uri.browser_host},
            )
        )

    # -- IDN ---------------------------------------------------------------
    idn = [h for h in uri.hazards if h in ("idn-unicode-host", "punycode-host")]
    if idn:
        out.append(
            finding(
                "RU017",
                locus=locus,
                detail=(
                    f"The host {uri.host!r} has two spellings ({idn[0]}). Exact comparison on one spelling and resolution on the "
                    "other are not the same check, and a visually similar name registered by someone else passes a reader's eye."
                ),
                evidence={"hazard": idn[0], "host": uri.host},
            )
        )

    # -- remaining normalisation hazards ----------------------------------
    reported_elsewhere = {
        "userinfo",
        "idn-unicode-host",
        "punycode-host",
        "credential-shaped-query",
        "empty-path",
    }
    remaining = [h for h in uri.hazards if h not in reported_elsewhere]
    if uri.host_is_ambiguous:
        remaining = [h for h in remaining if h != "backslash"]
    if remaining:
        out.append(
            finding(
                "RU016",
                locus=locus,
                detail=(
                    "This registration has more than one spelling: "
                    + "; ".join(uri.describe_hazards_for(remaining))
                    + f". The canonical form is {uri.canonical!r}. Exact comparison protects you only if the "
                    "string the provider holds is the string the client sends, in every client and on every platform."
                ),
                severity_override=Severity.LOW if remaining == ["trailing-slash"] else None,
                evidence={"hazards": remaining, "canonical": uri.canonical},
            )
        )

    return out


def _check_mixed_strictness(config: Configuration, parsed: list[RedirectURI]) -> list[Finding]:
    usable = [u for u in parsed if u.valid]
    if len(usable) < 2:
        return []
    scored = sorted(usable, key=looseness_score, reverse=True)
    weakest, strongest = scored[0], scored[-1]
    if looseness_score(weakest) == looseness_score(strongest):
        return []
    return [
        finding(
            "RU014",
            locus=f"client {config.client.client_id}",
            detail=(
                f"{len(usable)} redirect URIs are registered and they are not equally strict. The attacker chooses which one "
                f"an authorisation request names, so this client's security is the security of {weakest.raw!r}, not of "
                f"{strongest.raw!r}."
            ),
            evidence={
                "weakest": weakest.raw,
                "strongest": strongest.raw,
                "count": len(usable),
            },
        )
    ]
