"""The escalation matrix.

This is the part of the tool that is not a checklist.

Almost no real OAuth finding is a single misconfiguration. A redirect URI
policy that allows a path suffix is a hygiene note until the client is a public
single-page app using the implicit flow, at which point it is account takeover:
the attacker points the authorisation request at a path they control on the
registered origin and the access token is delivered to them in the fragment. A
reviewer working down a list produces two medium findings and leaves the join
to the reader. The join is the vulnerability.

An escalation fires when at least one rule from ``left`` and at least one from
``right`` are both present in the same report. It emits one finding at its own
severity, and marks the contributing findings as escalated so that the report
shows the relationship in both directions. Nothing is removed: the components
remain in the output, because each is independently worth fixing and because a
reader needs to see what the combination was built from.

The matrix is data. ``oauth-flow-lint rules --matrix`` prints it, and the table
in the README is generated from the same structure, so the documentation cannot
describe a combination the tool does not implement.
"""

from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding, Rule, Severity, register

S = Severity

#: Rules that mean "an attacker can get the authorisation response delivered to
#: a path or host they control, on an origin the provider considers registered".
LOOSE_REDIRECT_REACH = ("RU001", "RU002", "RU003", "RU008", "RU009", "RU016")

#: Rules that mean "the callback forwards the response somewhere else", which
#: takes the credential off the registered origin entirely.
ONWARD_FORWARDING = ("RU010", "RU011")

#: Rules that mean "a credential is delivered through the front channel".
FRONT_CHANNEL_CREDENTIAL = ("FL001", "FL002", "CP008")


@dataclass(frozen=True)
class Escalation:
    """One combination, with the mechanism the combination creates."""

    id: str
    name: str
    severity: Severity
    left: tuple[str, ...]
    right: tuple[str, ...]
    mechanism: str
    narrative: str
    remediation: str = ""

    def matches(self, present: set[str]) -> tuple[list[str], list[str]]:
        return (
            [r for r in self.left if r in present],
            [r for r in self.right if r in present],
        )


MATRIX: tuple[Escalation, ...] = (
    Escalation(
        id="ESC001",
        name="front-channel-token-to-attacker-controlled-path",
        severity=S.CRITICAL,
        left=FRONT_CHANNEL_CREDENTIAL,
        right=LOOSE_REDIRECT_REACH,
        mechanism="An attacker-controlled path on a registered origin receives the access token directly.",
        narrative=(
            "The flow returns a credential in the URL fragment, and the provider accepts a callback the attacker can choose "
            "within the registered origin. The attacker sends the victim an authorisation request whose redirect_uri points at "
            "a path they control - an uploaded file, a reflected page, a tenant subdomain, or a second spelling of the "
            "registered URI - and the provider delivers the token there. There is no code to exchange, no client secret to "
            "obtain, and nothing for the victim to do beyond following one link while signed in. The result is use of the "
            "victim's account at the resource server for the lifetime of the token."
        ),
        remediation="Remove token from response_type and move to the authorisation code flow with PKCE; independently, make the provider's redirect_uri comparison exact and register complete URIs.",
    ),
    Escalation(
        id="ESC002",
        name="authorisation-code-interception-on-public-client",
        severity=S.CRITICAL,
        left=("FL003",),
        right=LOOSE_REDIRECT_REACH,
        mechanism="A code delivered to an attacker-controlled path is exchangeable, because the client has no secret and no verifier.",
        narrative=(
            "The client is public, so the token endpoint has nothing to authenticate it with, and no code_verifier is required, "
            "so possession of the code is sufficient. The redirect policy lets the attacker choose where the code is delivered "
            "within the registered origin. The two together mean the attacker receives a code and exchanges it for tokens "
            "themselves; PKCE is precisely the control that would have made the intercepted code useless."
        ),
        remediation="Send code_challenge with S256 and have the provider require it, and make the redirect_uri comparison exact.",
    ),
    Escalation(
        id="ESC003",
        name="pkce-stripped-then-code-intercepted",
        severity=S.HIGH,
        left=("FL005",),
        right=LOOSE_REDIRECT_REACH,
        mechanism="The attacker omits code_challenge from the request they craft, so the client's PKCE is not in the attack path at all.",
        narrative=(
            "The client uses PKCE correctly, but the provider treats code_challenge as optional, so the attacker simply does not "
            "send it in the authorisation request they construct. The provider issues a code that can be redeemed without a "
            "verifier, and the redirect policy lets the attacker choose where that code is delivered. Reviewing the client's "
            "code finds PKCE present and correct; the control is defeated at the provider, which is a different system and often "
            "a different team."
        ),
        remediation="Require PKCE per client at the provider so that a request without code_challenge is rejected outright.",
    ),
    Escalation(
        id="ESC004",
        name="idp-mix-up",
        severity=S.CRITICAL,
        left=("SN007",),
        right=("SN002", "SN001", "TK005"),
        mechanism="A response from one issuer is accepted as a response from another, because nothing in the response names the issuer and nothing in the client's state does either.",
        narrative=(
            "More than one provider is configured, the authorisation response carries no iss parameter, and the client's own "
            "per-request state is not a reliable record of which provider the flow was started with. The attacker starts a flow "
            "at the issuer they control, obtains a code or token from it, and returns it to the client's callback; the client "
            "exchanges or validates it against the other, trusted issuer's endpoints. Credentials intended for one issuer are "
            "presented to another, and the client's identity decision is made on the attacker's assertion."
        ),
        remediation="Require the iss response parameter (RFC 9207), or use a distinct redirect URI per provider, and bind the issuer into the session state that the callback compares.",
    ),
    Escalation(
        id="ESC005",
        name="id-token-forgery-by-key-and-algorithm-substitution",
        severity=S.CRITICAL,
        left=("TK002", "TK003"),
        right=("TK007", "TK008"),
        mechanism="The token chooses both the algorithm and the key used to verify it, so any party can mint an accepted identity assertion.",
        narrative=(
            "The verification algorithm is taken from the token's header and the verification key is resolved from somewhere the "
            "token or an unauthenticated response controls. Each half on its own is serious; together there is no step left in "
            "which the client consults something only the real issuer could have produced. The attacker writes claims for any "
            "subject, signs them with a key they chose, and the client authenticates them as that user."
        ),
        remediation="Pin the algorithm to the one registered for the client, resolve keys only from the issuer's configured JWKS location, and ignore jku, x5u and embedded jwk.",
    ),
    Escalation(
        id="ESC006",
        name="cross-client-id-token-replay",
        severity=S.CRITICAL,
        left=("TK004",),
        right=("TK006", "PV006", "TK005"),
        mechanism="An ID token issued to a different client of the same issuer is accepted here, and obtaining such a token is cheap.",
        narrative=(
            "The audience of the ID token is not constrained to this client, and there is a straightforward way to obtain a token "
            "with a different audience: a second authorised party named in azp that the client ignores, open registration that "
            "lets the attacker create their own client, or an unchecked issuer. The attacker logs into their own client as "
            "themselves, takes the ID token, and presents it here, where it authenticates them as whichever subject the token "
            "names. This is the standard way a 'sign in with X' integration is turned into authentication bypass."
        ),
        remediation="Require aud to contain this client_id, require azp to equal it where aud has several members, and compare iss against the exact expected issuer.",
    ),
    Escalation(
        id="ESC007",
        name="credential-forwarded-off-origin-by-redirector",
        severity=S.CRITICAL,
        left=FRONT_CHANNEL_CREDENTIAL,
        right=ONWARD_FORWARDING,
        mechanism="The registered callback forwards the browser onward, carrying the credential to a host the attacker names.",
        narrative=(
            "The callback is, or looks like, a forwarding endpoint, and the flow delivers a credential to it through the front "
            "channel. The attacker sets the forwarding parameter to their own host. The provider's redirect URI check passes - the "
            "response really does go to the registered URI - and the credential then leaves the origin. A fragment survives most "
            "redirects in the browser, and a query is handed over in the Referer or in the forwarded URL, so neither component is a defence."
        ),
        remediation="Remove the forwarding behaviour from the callback path, and move off front-channel credential delivery.",
    ),
    Escalation(
        id="ESC008",
        name="one-time-leak-becomes-persistent-access",
        severity=S.HIGH,
        left=("TK010",),
        right=("TK013", "FL001", "TK009", "CP008"),
        mechanism="A non-rotating refresh token held somewhere readable turns a single leak into access that renews itself indefinitely.",
        narrative=(
            "A refresh token is issued to a client that cannot authenticate and is not rotated on use, so it stays valid after it "
            "has been used. It is also held, or delivered, somewhere a single incident exposes: web storage reachable by any "
            "script on the origin, a URL fragment, or a query string in logs. The consequence of the leak is no longer bounded by "
            "an access token lifetime: the attacker refreshes indefinitely, the real client keeps working, and reuse of the "
            "stolen token produces no signal the provider can act on."
        ),
        remediation="Rotate refresh tokens on every use with reuse detection, and keep tokens out of web storage and out of URLs.",
    ),
    Escalation(
        id="ESC009",
        name="login-csrf-to-code-injection",
        severity=S.HIGH,
        left=("SN001", "SN002"),
        right=("FL003", "FL005"),
        mechanism="With neither a session-bound state value nor a verifier, an authorisation code from another flow can be injected into the victim's session.",
        narrative=(
            "The callback accepts a response it cannot tie to a request it made, and the token exchange requires nothing that is "
            "specific to that request. The attacker therefore completes the authorisation step themselves and delivers the "
            "resulting code to the victim's callback, which exchanges it and binds the victim's session to the attacker's account "
            "- or, in the other direction, injects a code obtained from the victim into the attacker's own session. PKCE would "
            "break the exchange and a session-bound state would break the delivery; neither is present."
        ),
        remediation="Bind state to the user's session and compare it on callback, and require PKCE so the code is only redeemable by the flow that started it.",
    ),
    Escalation(
        id="ESC010",
        name="silent-scope-widening-to-long-lived-access",
        severity=S.HIGH,
        left=("SC003",),
        right=("SC001", "TK012", "TK010"),
        mechanism="Scope can be widened without a consent interaction, and the widened scope yields a credential that outlives the session.",
        narrative=(
            "A later authorisation request can increase the granted scope without the user being asked again, and offline access "
            "is either requested by default or granted without being requested. The combination converts a narrow, in-session "
            "grant into background access with a long-lived or non-expiring refresh token, with no point at which the user is "
            "shown what changed."
        ),
        remediation="Require a fresh consent interaction whenever the requested scope is not a subset of the granted scope, and request offline_access only in the flows that need it.",
    ),
    Escalation(
        id="ESC011",
        name="open-registration-with-unauthenticated-token-endpoint",
        severity=S.HIGH,
        left=("PV006",),
        right=("PV003", "PV007"),
        mechanism="Anyone can create a client in this issuer, and the created client needs no credential to use - or can make the authorisation server fetch a URL.",
        narrative=(
            "Open dynamic client registration means the attacker can obtain a client_id inside the trusted issuer. Combined with "
            "an advertised 'none' token endpoint authentication method, that client is immediately usable with no credential to "
            "steal or guess; combined with request_uri support, it is a self-service way to make the authorisation server issue "
            "outbound requests. Either way the attacker now operates from inside the issuer, which is the position most "
            "cross-client attacks assume as a starting point."
        ),
        remediation="Require an initial access token for registration, pin the token endpoint authentication method per client, and disable or allow-list request_uri.",
    ),
    Escalation(
        id="ESC012",
        name="unauthenticated-metadata-supplies-verification-keys",
        severity=S.CRITICAL,
        left=("PV001",),
        right=("TK008", "PV002"),
        mechanism="A network attacker answers the metadata request and thereby chooses the keys the client will trust.",
        narrative=(
            "At least one endpoint is published over http, and the client resolves its verification keys through that metadata "
            "with no constraint on the host that serves them. A party on the network path answers the metadata request with their "
            "own jwks_uri, serves their own key set, and every token they sign verifies. The client's token validation is fully "
            "implemented and is validating against the attacker's key."
        ),
        remediation="Publish and fetch all metadata over https, pin the JWKS host or the key identifiers, and cache the key set.",
    ),
    Escalation(
        id="ESC013",
        name="native-app-callback-hijack",
        severity=S.HIGH,
        left=("RU007",),
        right=("FL003", "FL005", "FL001"),
        mechanism="Another application on the device claims the callback scheme and receives a credential it can use without a secret.",
        narrative=(
            "The callback uses a private-use URI scheme that is not derived from a domain the publisher controls, so any app on "
            "the device may register it, and on the platforms where first registration wins, a malicious app receives the "
            "authorisation response. Because the exchange needs no verifier - or because the response is a token outright - what "
            "that app receives is directly usable. The user installed two apps and one of them now holds their account."
        ),
        remediation="Use a claimed https callback or a reverse-DNS scheme derived from a domain you control, and require PKCE with S256.",
    ),
    Escalation(
        id="ESC014",
        name="token-in-url-handed-to-third-party",
        severity=S.CRITICAL,
        left=("TK009", "CP005"),
        right=ONWARD_FORWARDING,
        mechanism="A bearer token in a URL reaches an endpoint that forwards the request onward, so the token is handed to a host the attacker names and written into its logs.",
        narrative=(
            "The access token is carried in a query string, and a path that forwards from a request parameter is in the request "
            "path. The forwarding host receives the full URL, including the token, in the request line and in the Referer of what "
            "it loads next, and records it wherever it records requests. Unlike most leak paths this one needs no vulnerability in "
            "the forwarding host: logging the URL is the correct behaviour for a web server."
        ),
        remediation="Send the token in the Authorization header, and remove the forwarding behaviour from the callback path.",
    ),
)


def _escalation_rule(esc: Escalation) -> Rule:
    return Rule(
        id=esc.id,
        name=esc.name,
        category="escalation",
        severity=esc.severity,
        mechanism=esc.mechanism,
        reference="",
        remediation=esc.remediation,
    )


BY_ID: dict[str, Escalation] = {}
for _esc in MATRIX:
    BY_ID[_esc.id] = _esc
    register(_escalation_rule(_esc))


def apply(findings: list[Finding]) -> list[Finding]:
    """Add escalation findings and annotate the findings that produced them.

    Returns only the new findings; the input list is mutated to record the
    relationship, so that a reader of either half can see the other.
    """
    present: dict[str, list[Finding]] = {}
    for f in findings:
        present.setdefault(f.rule_id, []).append(f)

    produced: list[Finding] = []
    for esc in MATRIX:
        left, right = esc.matches(set(present))
        if not left or not right:
            continue
        contributors = [f for rid in left + right for f in present[rid]]
        loci = sorted({f.locus for f in contributors})
        shown = loci[:3]
        locus_text = "; ".join(shown)
        if len(loci) > len(shown):
            locus_text += f" (+{len(loci) - len(shown)} more)"
        produced.append(
            Finding(
                rule_id=esc.id,
                locus=locus_text,
                detail=(
                    esc.narrative
                    + "\n\nBuilt from: "
                    + ", ".join(f"{rid} ({_name(findings, rid)})" for rid in left + right)
                ),
                evidence={
                    "left": left,
                    "right": right,
                    "contributing_rules": list(left + right),
                    "contributing_loci": loci,
                },
            )
        )
        for f in contributors:
            if esc.id not in f.escalated_into:
                f.escalated_into.append(esc.id)
    return produced


def _name(findings: list[Finding], rule_id: str) -> str:
    for f in findings:
        if f.rule_id == rule_id:
            return f.rule.name
    return rule_id  # pragma: no cover


def matrix_rows() -> list[dict[str, object]]:
    """The matrix as data, for the ``rules --matrix`` output and the README."""
    return [
        {
            "id": e.id,
            "name": e.name,
            "severity": e.severity.label,
            "left": list(e.left),
            "right": list(e.right),
            "mechanism": e.mechanism,
        }
        for e in MATRIX
    ]
