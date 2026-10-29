"""Severities, the rule catalogue, and the finding record.

Every rule in this tool is declared here, once, with its severity, the
mechanism that makes it exploitable, and a spec reference where one exists and
is unambiguous. The checks in the ``rules_*`` modules look rules up by ID, so
the catalogue and the implementation cannot drift: a rule that is not in this
table cannot be emitted, and the ``rules`` subcommand prints this table
verbatim.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Ordered so that ``>=`` comparisons work for threshold filtering."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls[text.strip().upper()]
        except KeyError as exc:  # pragma: no cover - argparse validates first
            raise ValueError(f"unknown severity {text!r}") from exc


CATEGORIES = {
    "redirect": "Redirect URI registration and matching",
    "flow": "Flow and grant selection",
    "state": "State, nonce and issuer binding",
    "token": "Token handling and ID token validation",
    "scope": "Scope and consent",
    "provider": "Provider and discovery metadata",
    "capture": "Captured request/response cross-checks",
    "escalation": "Combinations of the above",
}


@dataclass(frozen=True)
class Rule:
    """One named weakness.

    ``mechanism`` is the sentence that answers "so what?" — it is printed with
    every finding, because a severity label on its own does not tell a reviewer
    what an attacker actually does with the condition.
    """

    id: str
    name: str
    category: str
    severity: Severity
    mechanism: str
    reference: str = ""
    remediation: str = ""


def _r(
    rid: str,
    name: str,
    category: str,
    severity: Severity,
    mechanism: str,
    reference: str = "",
    remediation: str = "",
) -> Rule:
    return Rule(rid, name, category, severity, mechanism, reference, remediation)


S = Severity

_RULE_LIST: list[Rule] = [
    # ------------------------------------------------------------------ redirect
    _r(
        "RU001",
        "redirect-uri-wildcard",
        "redirect",
        S.HIGH,
        "A wildcard in a registered redirect URI means the set of hosts or paths that may receive an authorisation response is not enumerable, so an attacker only has to find one member of that set they control.",
        "RFC 9700 (OAuth 2.0 Security BCP), redirect URI validation",
        "Register every callback as a complete, literal URI. There is no safe wildcard.",
    ),
    _r(
        "RU002",
        "redirect-uri-loose-matching",
        "redirect",
        S.HIGH,
        "If the provider matches a registered URI by prefix rather than by exact string, every URI that starts with the registered value is accepted, which turns any path-controlling primitive on the registered origin into a credential sink.",
        "OIDC Core 3.1.2.1 requires exact match (RFC 3986 6.2.1 simple string comparison); RFC 9700 requires exact string matching",
        "Configure the provider for exact string comparison of redirect_uri.",
    ),
    _r(
        "RU003",
        "redirect-uri-open-path-segment",
        "redirect",
        S.MEDIUM,
        "A registered URI that is a bare origin or ends in a slash leaves the path component open, which is only meaningful once the provider matches by prefix - but when it does, the whole origin becomes the callback.",
        "",
        "Register the exact callback path, with no trailing slash and no bare origin.",
    ),
    _r(
        "RU004",
        "redirect-uri-insecure-scheme",
        "redirect",
        S.HIGH,
        "An http callback on a routable host hands the authorisation response to any party on the network path, and the response carries either the code or the token itself.",
        "RFC 6749 3.1.2.1 (endpoint request confidentiality)",
        "Use https for every non-loopback callback.",
    ),
    _r(
        "RU005",
        "redirect-uri-loopback-on-browser-client",
        "redirect",
        S.MEDIUM,
        "A loopback callback registered for a web or single-page client is a development leftover: in production it cannot serve the real user, but it can serve an attacker who gets the victim's browser to start a flow while something listens on that port locally.",
        "RFC 8252 7.3 scopes loopback redirection to native apps",
        "Remove loopback URIs from browser-client registrations; keep them in a separate development client.",
    ),
    _r(
        "RU006",
        "redirect-uri-loopback-native-accepted",
        "redirect",
        S.INFO,
        "A loopback http callback is the specified mechanism for a native app and is not a weakness; it is reported only so that a reviewer can see the distinction was made rather than assume it was missed.",
        "RFC 8252 7.3 (loopback interface redirection)",
        "No change needed. Accept any port on the loopback callback, as the specification requires.",
    ),
    _r(
        "RU007",
        "redirect-uri-unclaimable-custom-scheme",
        "redirect",
        S.MEDIUM,
        "A private-use URI scheme that is not a reverse-DNS name the app's publisher controls can be registered by any other application on the device, which then receives the authorisation response.",
        "RFC 8252 7.1 (private-use URI scheme redirection)",
        "Use a scheme derived from a domain name you control, in reverse-DNS form, or use a claimed https URI.",
    ),
    _r(
        "RU008",
        "redirect-uri-wildcard-subdomain",
        "redirect",
        S.HIGH,
        "If any subdomain of the registered host can be pointed at attacker infrastructure - by wildcard DNS, by a dangling delegation, or by a self-service subdomain feature - then the registered origin is not a trust boundary.",
        "",
        "Register callbacks only on hosts whose DNS and hosting you control exclusively, and remove wildcard DNS from those names.",
    ),
    _r(
        "RU009",
        "redirect-uri-shared-platform-host",
        "redirect",
        S.HIGH,
        "A callback on a platform-provided hostname shares its registrable domain with every other tenant of that platform, so another tenant can host a page under a sibling name and, under anything looser than exact matching, under a sibling path.",
        "",
        "Move the callback to a hostname under your own registrable domain.",
    ),
    _r(
        "RU010",
        "redirect-uri-reflecting-path",
        "redirect",
        S.MEDIUM,
        "The registered path matches a shape that conventionally forwards the browser onward from a request parameter; if it does, the authorisation response is handed to whatever that parameter names.",
        "RFC 9700 describes credential leakage via onward redirection and the Referer header",
        "Point the callback at a path that does nothing but complete the flow, and confirm it never forwards from a parameter.",
    ),
    _r(
        "RU011",
        "redirect-uri-open-redirector",
        "redirect",
        S.HIGH,
        "The callback is a confirmed open redirector, so the authorisation response is forwarded off the registered origin to a destination the attacker chooses, carrying the code in the query or the token in the fragment.",
        "RFC 6819 (threat: open redirector on the client)",
        "Fix the open redirect, and do not register a forwarding endpoint as a callback.",
    ),
    _r(
        "RU012",
        "redirect-uri-has-fragment",
        "redirect",
        S.HIGH,
        "A fragment in a registered redirect URI is prohibited because the fragment is where the implicit and hybrid flows place credentials; a registered fragment either collides with that or reveals that the provider's comparison is not a string comparison at all.",
        "RFC 6749 3.1.2 (the endpoint URI MUST NOT include a fragment component)",
        "Remove the fragment from the registration.",
    ),
    _r(
        "RU013",
        "redirect-uri-has-query",
        "redirect",
        S.LOW,
        "A query component is permitted in a registered redirect URI, but it must survive the provider merging its own response parameters into the same component; providers differ on ordering and on duplicate keys, and the difference is where parameter-smuggling lives.",
        "RFC 6749 3.1.2 (the endpoint URI MAY include a query component)",
        "Prefer a callback with no query component, and keep client state in the state parameter instead.",
    ),
    _r(
        "RU014",
        "redirect-uri-mixed-strictness",
        "redirect",
        S.HIGH,
        "When several URIs are registered for one client, the client's security is set by the weakest of them, because the attacker picks which one to send; a strict production callback does not compensate for a loose one beside it.",
        "",
        "Split the loose registration into its own client, or remove it.",
    ),
    _r(
        "RU015",
        "redirect-uri-userinfo",
        "redirect",
        S.MEDIUM,
        "A userinfo component makes the authority ambiguous to readers and to some comparison code: everything before the @ is credentials, not a host, so a URI that appears to point at the registered origin may resolve elsewhere.",
        "RFC 3986 3.2.1 (userinfo subcomponent)",
        "Remove the userinfo component from the registration and reject it at the provider.",
    ),
    _r(
        "RU016",
        "redirect-uri-normalisation-hazard",
        "redirect",
        S.MEDIUM,
        "Exact string comparison is only safe if both sides agree on the string: a trailing slash, an explicitly written default port, percent-encoding, a dot segment, a double slash or a backslash each produce two spellings of one URI, and the provider and the browser need not resolve them the same way.",
        "OIDC Core 3.1.2.1 (comparison per RFC 3986 6.2.1)",
        "Register one canonical spelling, and test that the provider rejects the variants listed by the plan subcommand.",
    ),
    _r(
        "RU017",
        "redirect-uri-idn-host",
        "redirect",
        S.MEDIUM,
        "A host with non-ASCII labels, or with labels already in punycode, has two spellings; comparison on one spelling and resolution on the other, or a homograph of the registered name, both let a different host pass as the registered one.",
        "RFC 3986 3.2.2 and RFC 5890 (internationalised domain names)",
        "Register the A-label (punycode) form, compare on that form, and confirm the provider does not accept the U-label form as equivalent.",
    ),
    _r(
        "RU018",
        "redirect-uri-missing",
        "redirect",
        S.MEDIUM,
        "With no registered callback the provider has nothing to compare against, so whatever redirect_uri the authorisation request carries is where the response goes.",
        "RFC 6749 3.1.2.2 (registration requirements)",
        "Register at least one complete redirect URI for the client.",
    ),
    # ---------------------------------------------------------------------- flow
    _r(
        "FL001",
        "implicit-flow",
        "flow",
        S.HIGH,
        "The implicit flow returns the access token in the URL fragment, so the token exists in the browser history, in the Referer of anything the callback page loads, and in any onward redirection, with no client authentication anywhere in the exchange.",
        "RFC 6749 4.2.2 and 10.16; RFC 9700 recommends against the implicit flow",
        "Use the authorisation code flow with PKCE and drop token from response_type.",
    ),
    _r(
        "FL002",
        "hybrid-flow",
        "flow",
        S.MEDIUM,
        "A hybrid response_type delivers part of the credential set through the front channel; the front-channel part inherits the fragment's leakage paths even though a back-channel exchange also takes place.",
        "OIDC Core 3.3 (hybrid flow)",
        "Request response_type=code alone and obtain the ID token from the token endpoint.",
    ),
    _r(
        "FL003",
        "code-flow-without-pkce",
        "flow",
        S.HIGH,
        "A public client has no secret, so an authorisation code is the only thing standing between an attacker who intercepts the redirect and a valid token; without a code_verifier, interception of the code is sufficient.",
        "RFC 7636 (PKCE); RFC 9700 requires PKCE for public clients",
        "Send code_challenge with method S256 and verify the provider rejects a token request without the matching verifier.",
    ),
    _r(
        "FL004",
        "pkce-method-plain",
        "flow",
        S.MEDIUM,
        "With method plain the challenge is the verifier, so anything that can read the authorisation request can replay the token request; PKCE then proves only that the same party sent both messages to an observer who saw neither.",
        "RFC 7636 4.2 (S256 must be used where the client can compute it)",
        "Switch to S256.",
    ),
    _r(
        "FL005",
        "pkce-not-enforced-by-provider",
        "flow",
        S.MEDIUM,
        "If the provider treats code_challenge as optional, an attacker who can shape the authorisation request simply omits it, and the provider issues a code that needs no verifier - the client's correct use of PKCE is not a control the attacker has to defeat.",
        "RFC 7636 4.6 (server verifies code_verifier before returning tokens)",
        "Require PKCE per client at the provider, so a request without code_challenge is rejected.",
    ),
    _r(
        "FL006",
        "resource-owner-password-grant",
        "flow",
        S.HIGH,
        "The password grant requires the client to handle the user's primary credential, which removes the provider's ability to apply its own authentication policy and gives every client a credential-stuffing surface.",
        "RFC 6749 4.3; RFC 9700 prohibits the password grant",
        "Remove the grant from the client and the provider, and use a redirect-based flow.",
    ),
    _r(
        "FL007",
        "implicit-flow-on-native-client",
        "flow",
        S.HIGH,
        "A native app receives the implicit response through a URI scheme or loopback listener that other software on the device can claim, so the token is delivered to whatever registered for that scheme first.",
        "RFC 8252 (native apps must use the authorisation code flow with PKCE)",
        "Use the code flow with PKCE and a claimed https or reverse-DNS scheme callback.",
    ),
    _r(
        "FL008",
        "secret-in-public-client",
        "flow",
        S.HIGH,
        "A secret shipped inside a single-page app or a mobile binary is readable by anyone who has the app, so the client is public whatever it is registered as - and any control the provider applies because it believes the client is confidential is not applied.",
        "RFC 6749 2.1 (client types)",
        "Register the client as public, remove the secret, and rely on PKCE.",
    ),
    _r(
        "FL009",
        "response-mode-fragment-unnecessary",
        "flow",
        S.LOW,
        "Fragment response mode on a code flow puts the code where script on the callback page can read it and where it survives in history, for no benefit the query or form_post modes do not provide.",
        "OIDC Core 3.1.2.1 (response_mode)",
        "Use response_mode=query for the code flow, or form_post where the code must not appear in a URL.",
    ),
    _r(
        "FL012",
        "front-channel-id-token",
        "flow",
        S.MEDIUM,
        "An ID token returned in the callback fragment with no code exchange is a bearer assertion of identity, so a relying party that treats one as proof of authentication accepts whatever reaches its callback - the redirect URI and the nonce are the whole of the defence. Lower than FL001 because an ID token is not a key to an API, and not absent, because it is still an account takeover where the redirect is loose.",
        "OIDC Core 3.2 (implicit flow), 3.1.3.7 (ID token validation)",
        "Use the authorization code flow with PKCE. If the implicit flow is unavoidable, pin the redirect URI to an exact value and verify the nonce on every response.",
    ),
    _r(
        "FL010",
        "pkce-method-unsupported-by-provider",
        "flow",
        S.MEDIUM,
        "The client declares a challenge method the provider does not advertise, so in practice the request either fails or silently degrades to a weaker method - and a silent degradation is a control that is believed to be present and is not.",
        "RFC 7636 4.2 (S256 is mandatory to implement on the server)",
        "Confirm the provider supports S256 and reject plain for this client.",
    ),
    _r(
        "FL011",
        "provider-advertises-plain-pkce",
        "flow",
        S.LOW,
        "A provider that accepts method plain offers a downgrade an attacker can request even when the client always uses S256.",
        "RFC 7636 4.2",
        "Disable plain at the provider.",
    ),
    # --------------------------------------------------------------- state/nonce
    _r(
        "SN001",
        "state-absent",
        "state",
        S.HIGH,
        "Without state the callback cannot tell a response it caused from one an attacker caused, which is login cross-site request forgery: the victim's session is bound to the attacker's authorisation response, or the attacker's code is injected into the victim's session.",
        "RFC 6749 10.12 (cross-site request forgery)",
        "Send a per-request state value and reject callbacks whose state does not match the session.",
    ),
    _r(
        "SN002",
        "state-not-session-bound",
        "state",
        S.HIGH,
        "A state value that is generated and echoed but never compared against something held in the user's session proves nothing; the attacker obtains a valid state from their own flow and uses it in the victim's.",
        "RFC 6749 10.12",
        "Store the state value in the user's session and compare on callback, then discard it.",
    ),
    _r(
        "SN003",
        "state-reused",
        "state",
        S.MEDIUM,
        "A state value that is not single-use lets a captured callback be replayed, and removes the ordering guarantee that makes the comparison meaningful when several flows are in flight.",
        "RFC 6749 10.12",
        "Treat state as one-time: delete it from the session on first use.",
    ),
    _r(
        "SN004",
        "state-predictable",
        "state",
        S.HIGH,
        "A state value derived from a timestamp, a counter, or a fixed string can be produced by the attacker, so the comparison on callback succeeds for a response the attacker initiated.",
        "RFC 6749 10.10 (credentials-guessing attacks)",
        "Generate state from a cryptographically secure random source with at least 128 bits of entropy.",
    ),
    _r(
        "SN005",
        "nonce-absent",
        "state",
        S.HIGH,
        "Without a nonce the client cannot tell that an ID token was minted for this authentication request, so a token captured or obtained elsewhere can be replayed into this login.",
        "OIDC Core 3.1.2.1 (nonce) and 3.1.3.7 step 11",
        "Send a per-request nonce and require the returned ID token's nonce claim to equal it.",
    ),
    _r(
        "SN006",
        "nonce-not-session-bound",
        "state",
        S.MEDIUM,
        "A nonce that is sent but not stored and compared is a value in a URL, not a binding; the replay it is supposed to prevent still succeeds.",
        "OIDC Core 3.1.3.7 step 11",
        "Hold the nonce in the session and compare it against the ID token claim.",
    ),
    _r(
        "SN007",
        "iss-absent-multiple-providers",
        "state",
        S.HIGH,
        "With more than one provider configured and no issuer identifier in the authorisation response, the client must guess which provider a response came from; an attacker who controls or operates one provider gets a response accepted as if it came from another. This is the mix-up condition.",
        "RFC 9207 2 (iss response parameter); RFC 9700 (mix-up attacks)",
        "Require the iss authorisation response parameter, or run a distinct redirect URI per provider, and reject a response whose issuer does not match the one the flow was started with.",
    ),
    _r(
        "SN008",
        "iss-absent-single-provider",
        "state",
        S.LOW,
        "With one provider the mix-up attack has nothing to mix up, but the absence of the issuer parameter means that adding a second provider later silently introduces the condition, with no change to the client code that would prompt a review.",
        "RFC 9207 2",
        "Require the iss parameter now, while there is only one issuer to compare against.",
    ),
    # --------------------------------------------------------------------- token
    _r(
        "TK001",
        "id-token-signature-unverified",
        "token",
        S.CRITICAL,
        "An unverified ID token is a set of claims supplied by whoever sent the request, so the subject identifier - the thing the application treats as the user's identity - is attacker-chosen.",
        "OIDC Core 3.1.3.7 step 6 (ID token signature validation)",
        "Verify the signature against the provider's published keys before reading any claim.",
    ),
    _r(
        "TK002",
        "id-token-alg-not-pinned",
        "token",
        S.HIGH,
        "If the accepted algorithm is taken from the token's own header, the token chooses how it is checked; the classic result is a token signed with HMAC using the provider's public key as the shared secret.",
        "OIDC Core 3.1.3.7 step 6 and 16 (the alg must be the one registered for the client)",
        "Pin the expected algorithm to the one registered for the client and reject every other value, including none.",
    ),
    _r(
        "TK003",
        "id-token-none-alg-accepted",
        "token",
        S.CRITICAL,
        "Accepting alg none means an unsigned token is a valid token, so identity assertions can be written by hand.",
        "OIDC Core 3.1.3.7; RFC 8725 (JWT best current practice)",
        "Reject alg none unconditionally in this code path.",
    ),
    _r(
        "TK004",
        "id-token-aud-unchecked",
        "token",
        S.HIGH,
        "Without an audience check, a token minted for a different client of the same provider is accepted here; any other client - including one an attacker registers - becomes a source of valid identity assertions for this application.",
        "OIDC Core 3.1.3.7 step 3 (aud must contain the client_id)",
        "Require the aud claim to contain this client's client_id and reject tokens whose audience is anything else.",
    ),
    _r(
        "TK005",
        "id-token-iss-unchecked",
        "token",
        S.HIGH,
        "Without an issuer check the token's origin is unconstrained, so a token from any issuer whose key the client happens to accept passes.",
        "OIDC Core 3.1.3.7 step 2 (iss must match the issuer)",
        "Compare the iss claim against the exact expected issuer string.",
    ),
    _r(
        "TK006",
        "id-token-azp-ignored",
        "token",
        S.MEDIUM,
        "When a token carries multiple audiences, azp names the party it was actually issued to; ignoring it means a token legitimately issued to a different authorised party is accepted as one issued here.",
        "OIDC Core 2 (azp claim) and 3.1.3.7 steps 4 and 5",
        "Where aud has more than one member, require azp to equal this client's client_id.",
    ),
    _r(
        "TK007",
        "jwks-from-token-header",
        "token",
        S.CRITICAL,
        "Fetching the verification key from a location named inside the token means the token supplies its own key, so the signature check confirms only that the token is internally consistent.",
        "RFC 8725 (do not trust jku or x5u from the token)",
        "Resolve keys only from the issuer's configured JWKS location, and ignore jku, x5u and embedded jwk entirely.",
    ),
    _r(
        "TK008",
        "jwks-host-unpinned",
        "token",
        S.MEDIUM,
        "A key set resolved through discovery each time, with no constraint on the host it is served from, moves trust from the issuer to whatever answered the metadata request.",
        "RFC 8414 (authorisation server metadata)",
        "Pin the JWKS host, or the key identifiers, and cache the key set rather than resolving it per verification.",
    ),
    _r(
        "TK009",
        "access-token-in-query",
        "token",
        S.HIGH,
        "A token in a query string is recorded by proxies, access logs and analytics, and is sent in the Referer of requests the receiving page makes, so the bearer credential ends up in places the application does not control.",
        "RFC 6750 2.3 (the URI query parameter method is not recommended)",
        "Send the token in the Authorization header.",
    ),
    _r(
        "TK010",
        "refresh-token-public-client-no-rotation",
        "token",
        S.HIGH,
        "A refresh token issued to a client that cannot authenticate, and that stays valid after use, converts one theft into indefinite access with no further interaction and nothing to detect.",
        "RFC 9700 (refresh token protection for public clients); RFC 6749 10.4",
        "Rotate the refresh token on every use and revoke the whole chain when a used token is presented again.",
    ),
    _r(
        "TK011",
        "access-token-lifetime-excessive",
        "token",
        S.LOW,
        "A long-lived access token widens the window in which a leaked token is useful, and in a browser client the leak paths are the ones this tool's other rules describe.",
        "RFC 6749 10.3 (access token lifetime)",
        "Keep browser-client access tokens short-lived and refresh them.",
    ),
    _r(
        "TK012",
        "refresh-token-lifetime-unbounded",
        "token",
        S.MEDIUM,
        "A refresh token with no expiry is a permanent credential, so revocation becomes the only control and it has to work perfectly and forever.",
        "RFC 6749 10.4",
        "Give refresh tokens an absolute expiry as well as rotation.",
    ),
    _r(
        "TK013",
        "tokens-in-web-storage",
        "token",
        S.MEDIUM,
        "Tokens in localStorage or sessionStorage are readable by any script that runs on the origin, so every cross-site scripting bug in the application, or in anything it loads, becomes token theft.",
        "RFC 9700 (token storage in browser-based apps)",
        "Hold tokens in memory only, or keep them server-side behind a session cookie.",
    ),
    _r(
        "TK014",
        "id-token-exp-unchecked",
        "token",
        S.HIGH,
        "Without an expiry check an ID token never stops being accepted, so a token captured once authenticates forever.",
        "OIDC Core 3.1.3.7 step 9 (exp must be checked)",
        "Reject tokens whose exp has passed, allowing only a small clock skew.",
    ),
    # --------------------------------------------------------------------- scope
    _r(
        "SC001",
        "offline-access-by-default",
        "scope",
        S.MEDIUM,
        "Requesting offline access on every flow means every user grant produces a long-lived refresh token, including for the flows that only needed to identify the user, so the blast radius of a token leak is set by the default rather than by need.",
        "OIDC Core 11 (offline access)",
        "Request offline_access only in the flows that need background access, and only when the user is told.",
    ),
    _r(
        "SC002",
        "scope-exceeds-stated-purpose",
        "scope",
        S.MEDIUM,
        "A scope the client's stated purpose does not need is authority held for no reason; it is the difference between a token leak that exposes a profile and one that exposes mailboxes.",
        "RFC 9700 (scope restriction)",
        "Request the minimum scope set, and split the client if two purposes need different authority.",
    ),
    _r(
        "SC003",
        "scope-upgrade-without-reconsent",
        "scope",
        S.MEDIUM,
        "If a later request can widen the granted scope without a new consent step, the user's decision covers a smaller grant than the one in force, and the widening is invisible to them.",
        "RFC 6749 3.3 (access token scope)",
        "Require a fresh consent interaction whenever the requested scope is not a subset of the granted scope.",
    ),
    # ------------------------------------------------------------------ provider
    _r(
        "PV001",
        "discovery-endpoint-insecure-scheme",
        "provider",
        S.HIGH,
        "An endpoint published over http can be answered by anyone on the network path, and the endpoints in question are where codes are exchanged and keys are published.",
        "RFC 8414 (metadata endpoints use https)",
        "Serve and publish every endpoint over https.",
    ),
    _r(
        "PV002",
        "jwks-uri-foreign-host",
        "provider",
        S.MEDIUM,
        "A key set served from a host other than the issuer's means the set of parties who can mint tokens the client will accept includes whoever controls that host.",
        "RFC 8414",
        "Serve the JWKS from the issuer's own host, or pin the host explicitly and justify it.",
    ),
    _r(
        "PV003",
        "token-endpoint-auth-none-supported",
        "provider",
        S.MEDIUM,
        "Advertising none as a token endpoint authentication method means a client registered as confidential can be used without its secret if the provider does not pin the method per client.",
        "RFC 8414 (token_endpoint_auth_methods_supported)",
        "Pin the authentication method per client, and do not offer none to confidential clients.",
    ),
    _r(
        "PV004",
        "response-modes-fragment-supported",
        "provider",
        S.INFO,
        "Fragment response mode is advertised while no configured client needs it; it remains available to an attacker shaping an authorisation request, which is only useful to them in combination with a flow that returns credentials.",
        "OIDC Core 3.1.2.1 (response_mode)",
        "Restrict the permitted response modes per client.",
    ),
    _r(
        "PV005",
        "pkce-methods-not-advertised",
        "provider",
        S.MEDIUM,
        "Metadata that omits code_challenge_methods_supported gives a client no way to know whether PKCE is available, which in practice means clients ship without it or assume it and are wrong.",
        "RFC 8414 (code_challenge_methods_supported)",
        "Publish code_challenge_methods_supported with S256.",
    ),
    _r(
        "PV006",
        "dynamic-registration-open",
        "provider",
        S.HIGH,
        "Open dynamic client registration lets anyone create a client in the same issuer, which is the precondition for every attack that depends on a second client the provider considers legitimate.",
        "RFC 7591 (dynamic client registration)",
        "Require an initial access token for registration, or close it.",
    ),
    _r(
        "PV007",
        "request-uri-supported",
        "provider",
        S.MEDIUM,
        "Accepting a request object by reference means the authorisation server fetches a URL supplied in a request, which is a server-side request forgery primitive inside the authentication system. This tool reports the capability and never fetches anything.",
        "OIDC Core 6.2 (request_uri) ; RFC 9700 discusses request_uri fetching",
        "Disable request_uri, or allow only pre-registered request_uri values.",
    ),
    _r(
        "PV008",
        "discovery-issuer-mismatch",
        "provider",
        S.HIGH,
        "If the issuer in the metadata is not the issuer the client expects, then either the metadata is for a different authorisation server or the client's issuer comparison will reject every token; both mean the client's trust anchor is not the one it was reviewed against.",
        "RFC 8414 (the issuer value must match)",
        "Make the configured issuer exactly equal to the issuer in the metadata.",
    ),
    _r(
        "PV009",
        "implicit-response-types-supported",
        "provider",
        S.LOW,
        "The provider still offers response types that return tokens in the front channel, so the flow a client is not supposed to use remains reachable by anyone who can shape its authorisation request.",
        "RFC 9700 recommends against front-channel token delivery",
        "Restrict response_types per client, and remove token-bearing response types where no client needs them.",
    ),
    _r(
        "PV010",
        "discovery-s256-not-offered",
        "provider",
        S.MEDIUM,
        "Metadata that lists challenge methods without S256 means the only PKCE available is the one that protects nothing against an attacker who can read the authorisation request.",
        "RFC 7636 4.2",
        "Offer S256.",
    ),
    # ------------------------------------------------------------------- capture
    _r(
        "CP001",
        "captured-response-type-undeclared",
        "capture",
        S.HIGH,
        "The captured authorisation request uses a response type the configuration does not declare, so either the configuration under review is not the one in use or the provider does not restrict response types for this client.",
        "",
        "Reconcile the configuration with what the client actually sends, and pin response_types at the provider.",
    ),
    _r(
        "CP002",
        "captured-request-missing-state",
        "capture",
        S.HIGH,
        "No state parameter was present in the authorisation request that was actually sent, whatever the configuration says.",
        "RFC 6749 10.12",
        "Send state on every authorisation request.",
    ),
    _r(
        "CP003",
        "captured-request-missing-pkce",
        "capture",
        S.HIGH,
        "No code_challenge was present in the authorisation request that was actually sent, so PKCE was not in use for this flow regardless of what the client is configured to do.",
        "RFC 7636 4.3",
        "Send code_challenge and code_challenge_method on every code-flow request.",
    ),
    _r(
        "CP004",
        "captured-request-missing-nonce",
        "capture",
        S.HIGH,
        "The captured request asks for an ID token without a nonce, so the token that comes back cannot be bound to this request.",
        "OIDC Core 3.1.2.1",
        "Send nonce whenever response_type includes id_token.",
    ),
    _r(
        "CP005",
        "captured-token-in-query",
        "capture",
        S.HIGH,
        "A token was observed in a URL query component, which is the component that is logged and sent in the Referer.",
        "RFC 6750 2.3",
        "Move the token out of the URL.",
    ),
    _r(
        "CP006",
        "captured-redirect-uri-unregistered",
        "capture",
        S.HIGH,
        "The redirect_uri actually sent is not one of the registered values under exact comparison, which means the provider accepted something the registration does not contain - the matching rule is looser than the configuration claims.",
        "OIDC Core 3.1.2.1",
        "Determine the provider's real comparison rule, then register the exact value in use.",
    ),
    _r(
        "CP007",
        "captured-response-missing-iss",
        "capture",
        S.MEDIUM,
        "The captured authorisation response carries no iss parameter, so the client cannot establish which issuer produced it from the response alone.",
        "RFC 9207 2",
        "Enable the iss response parameter at the provider and require it at the client.",
    ),
    _r(
        "CP008",
        "captured-credential-in-fragment",
        "capture",
        S.HIGH,
        "A credential was observed in the fragment of a captured URL, which confirms front-channel delivery in practice rather than as a configuration claim.",
        "RFC 6749 4.2.2",
        "Move to the code flow so no credential reaches the fragment.",
    ),
]

RULES: dict[str, Rule] = {}
for _rule in _RULE_LIST:
    if _rule.id in RULES:  # pragma: no cover - guards a typo at import time
        raise AssertionError(f"duplicate rule id {_rule.id}")
    if _rule.category not in CATEGORIES:  # pragma: no cover
        raise AssertionError(f"unknown category {_rule.category} on {_rule.id}")
    RULES[_rule.id] = _rule


@dataclass
class Finding:
    """One instance of a rule firing, against one locus in the configuration."""

    rule_id: str
    locus: str
    detail: str
    severity_override: Severity | None = None
    escalated_into: list[str] = field(default_factory=list)
    evidence: dict[str, object] = field(default_factory=dict)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def severity(self) -> Severity:
        return self.severity_override if self.severity_override is not None else self.rule.severity

    @property
    def name(self) -> str:
        return self.rule.name

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.rule_id,
            "name": self.rule.name,
            "category": self.rule.category,
            "severity": self.severity.label,
            "base_severity": self.rule.severity.label,
            "locus": self.locus,
            "detail": self.detail,
            "mechanism": self.rule.mechanism,
            "reference": self.rule.reference,
            "remediation": self.rule.remediation,
            "escalated_into": list(self.escalated_into),
            "evidence": dict(self.evidence),
        }


def finding(rule_id: str, locus: str, detail: str, **kwargs: object) -> Finding:
    """Construct a finding, failing loudly on an unknown rule ID."""
    if rule_id not in RULES:
        raise KeyError(f"no such rule: {rule_id}")
    return Finding(rule_id=rule_id, locus=locus, detail=detail, **kwargs)  # type: ignore[arg-type]


def sort_key(f: Finding) -> tuple[int, str, str]:
    return (-int(f.severity), f.rule_id, f.locus)


def register(rule: Rule) -> Rule:
    """Add a rule to the catalogue.

    Used by :mod:`oauth_flow_lint.escalation`, whose rules are generated from
    the escalation matrix rather than written out one by one, so that the
    matrix and the catalogue cannot disagree.
    """
    if rule.id in RULES:  # pragma: no cover
        raise AssertionError(f"duplicate rule id {rule.id}")
    if rule.category not in CATEGORIES:  # pragma: no cover
        raise AssertionError(f"unknown category {rule.category} on {rule.id}")
    RULES[rule.id] = rule
    return rule
