"""Build the probe list that confirms a provider's real behaviour.

Everything this tool decides from a configuration is a statement about what
someone believes. Two of those beliefs matter more than the rest and are the
hardest to establish from documentation: how the provider compares redirect
URIs, and what it does when a request omits a parameter the client always
sends. The plan subcommand turns those into an explicit list of requests.

This module builds request *descriptions*. It sends nothing, and there is no
code in this package that could.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlencode

from .model import Configuration
from .urls import parse_redirect_uri

ALL_RESPONSE_TYPES = (
    "code",
    "token",
    "id_token",
    "code token",
    "code id_token",
    "id_token token",
    "code id_token token",
)


@dataclass
class Probe:
    id: str
    group: str
    intent: str
    parameters: dict[str, str] = field(default_factory=dict)
    vulnerable_response: str = ""
    correct_response: str = ""
    note: str = ""

    def query(self) -> str:
        return urlencode(self.parameters)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "group": self.group,
            "intent": self.intent,
            "parameters": dict(self.parameters),
            "query": self.query(),
            "vulnerable_response": self.vulnerable_response,
            "correct_response": self.correct_response,
            "note": self.note,
        }


def _redirect_variants(raw: str) -> list[tuple[str, str, str]]:
    """Return (label, candidate redirect_uri, what acceptance would mean)."""
    uri = parse_redirect_uri(raw)
    if not uri.valid or not uri.is_http:
        return []

    base = f"{uri.scheme}://{uri.authority}"
    path = uri.path or "/"
    trimmed = path.rstrip("/") or ""
    out: list[tuple[str, str, str]] = []

    out.append(
        (
            "appended-path-segment",
            f"{base}{trimmed}/oauth-flow-lint-probe",
            "the provider matches by prefix, so every path under the registered value is a valid callback",
        )
    )
    out.append(
        (
            "appended-query",
            f"{base}{path}?oauth_flow_lint=probe",
            "the provider ignores the query component when comparing, so parameters can be smuggled into the callback",
        )
    )
    out.append(
        (
            "appended-fragment",
            f"{base}{path}#probe",
            "the provider ignores the fragment, which matters because the fragment is where front-channel credentials land",
        )
    )
    if path.endswith("/"):
        out.append(("trailing-slash-removed", f"{base}{trimmed}", "slashes are normalised before comparison, so the two spellings are one registration"))
    else:
        out.append(("trailing-slash-added", f"{base}{path}/", "slashes are normalised before comparison, so the two spellings are one registration"))
    out.append(
        (
            "dot-segment-escape",
            f"{base}{trimmed}/../oauth-flow-lint-probe",
            "dot segments are resolved after comparison, so a registered prefix reaches outside its own directory",
        )
    )
    out.append(
        (
            "encoded-dot-segment-escape",
            f"{base}{trimmed}/..%2foauth-flow-lint-probe",
            "the path is decoded after comparison, which is the same escape with one more layer",
        )
    )
    out.append(
        (
            "double-slash",
            f"{base}{trimmed}//oauth-flow-lint-probe",
            "empty path segments are collapsed inconsistently between the comparison and the router",
        )
    )
    out.append(
        (
            "backslash-authority",
            f"{uri.scheme}://{uri.authority}\\@oauth-flow-lint-probe.example{path}",
            "the provider splits the authority on the backslash differently from a browser, so the comparison and the navigation disagree",
        )
    )
    out.append(
        (
            "userinfo-authority",
            f"{uri.scheme}://{uri.authority}@oauth-flow-lint-probe.example{path}",
            "the provider reads the registered host out of the userinfo component and the browser navigates to the real host",
        )
    )
    if uri.port is None:
        default_port = 443 if uri.scheme == "https" else 80
        out.append(
            (
                "default-port-written",
                f"{uri.scheme}://{uri.host}:{default_port}{path}",
                "the authority is normalised before comparison, so the two spellings are one registration",
            )
        )
    out.append(
        (
            "uppercase-host",
            f"{uri.scheme}://{uri.host.upper()}{path}",
            "the host is lowercased before comparison - expected for a host, but it proves the comparison is not a string comparison, so ask what else it normalises",
        )
    )
    out.append(
        (
            "trailing-dot-host",
            f"{uri.scheme}://{uri.host}.{(':' + str(uri.port)) if uri.port else ''}{path}",
            "the host is normalised, and a trailing-dot host is a distinct Host header to many front ends",
        )
    )
    out.append(
        (
            "sibling-subdomain",
            f"{uri.scheme}://oauth-flow-lint-probe.{uri.host}{path}",
            "subdomains of the registered host are accepted, so any name under that domain is a callback",
        )
    )
    out.append(
        (
            "scheme-downgrade",
            f"http://{uri.authority}{path}",
            "the scheme is not part of the comparison, so the response can be delivered in clear text",
        )
    )
    out.append(
        (
            "unrelated-host",
            f"{uri.scheme}://oauth-flow-lint-probe.example{path}",
            "the host is not compared at all; this is the control case and should always be rejected",
        )
    )
    return out


def build(config: Configuration) -> list[Probe]:
    client = config.client
    probes: list[Probe] = []
    n = 0

    def nid(prefix: str) -> str:
        nonlocal n
        n += 1
        return f"{prefix}-{n:03d}"

    declared_redirect = client.redirect_uris[0] if client.redirect_uris else ""

    # -- redirect URI comparison ------------------------------------------
    for raw in client.redirect_uris:
        for label, candidate, meaning in _redirect_variants(raw):
            probes.append(
                Probe(
                    id=nid("RU"),
                    group="redirect-uri-comparison",
                    intent=f"{label}: send redirect_uri={candidate} against the registration {raw}",
                    parameters={
                        "response_type": client.response_types[0] if client.response_types else "code",
                        "client_id": client.client_id,
                        "redirect_uri": candidate,
                        "scope": " ".join(client.scopes) or "openid",
                        "state": "<fresh random value>",
                    },
                    vulnerable_response=f"A redirect to the candidate URI, or any response other than an error, means {meaning}.",
                    correct_response="invalid_request or invalid_redirect_uri rendered on the authorisation server, with no redirect to the candidate.",
                    note="An error shown on the provider's own page is the correct outcome. An error delivered *to* the candidate URI is itself an acceptance.",
                )
            )

    # -- response type permutations ---------------------------------------
    for rt in ALL_RESPONSE_TYPES:
        declared = rt in client.response_types
        probes.append(
            Probe(
                id=nid("RT"),
                group="response-type-restriction",
                intent=f"request response_type={rt!r}" + (" (declared for this client)" if declared else " (not declared for this client)"),
                parameters={
                    "response_type": rt,
                    "client_id": client.client_id,
                    "redirect_uri": declared_redirect,
                    "scope": " ".join(client.scopes) or "openid",
                    "state": "<fresh random value>",
                    **({"nonce": "<fresh random value>"} if "id_token" in rt.split() else {}),
                },
                vulnerable_response=(
                    "A successful authorisation means response types are not pinned per client, so an attacker can choose the "
                    "flow - including a flow that returns a token in the fragment - for a client that never uses it."
                    if not declared
                    else "A successful authorisation is expected here; record which components come back and in which URL component."
                ),
                correct_response=(
                    "unsupported_response_type for a value this client is not registered for."
                    if not declared
                    else "The declared response, in the declared response mode."
                ),
            )
        )

    # -- PKCE --------------------------------------------------------------
    if client.uses_code:
        probes.append(
            Probe(
                id=nid("PK"),
                group="pkce-enforcement",
                intent="omit code_challenge entirely from an otherwise valid authorisation request",
                parameters={
                    "response_type": "code",
                    "client_id": client.client_id,
                    "redirect_uri": declared_redirect,
                    "scope": " ".join(client.scopes) or "openid",
                    "state": "<fresh random value>",
                },
                vulnerable_response="A code is issued, and redeeming it at the token endpoint without a code_verifier succeeds: PKCE is optional, so it is not a control an attacker has to defeat (see FL005 and ESC003).",
                correct_response="invalid_request, naming the missing code_challenge, for a client registered as requiring PKCE.",
            )
        )
        probes.append(
            Probe(
                id=nid("PK"),
                group="pkce-enforcement",
                intent="send code_challenge_method=plain with the challenge equal to the verifier",
                parameters={
                    "response_type": "code",
                    "client_id": client.client_id,
                    "redirect_uri": declared_redirect,
                    "code_challenge": "<verifier, verbatim>",
                    "code_challenge_method": "plain",
                    "state": "<fresh random value>",
                },
                vulnerable_response="Accepted: the weaker method is available, so an attacker who can read the authorisation request can complete the exchange (FL004, FL011).",
                correct_response="invalid_request, with only S256 accepted.",
            )
        )
        probes.append(
            Probe(
                id=nid("PK"),
                group="pkce-enforcement",
                intent="send a valid S256 code_challenge, then redeem the code with a different verifier",
                parameters={
                    "grant_type": "authorization_code",
                    "code": "<code from the previous step>",
                    "redirect_uri": declared_redirect,
                    "code_verifier": "<a different, well-formed verifier>",
                },
                vulnerable_response="Tokens are returned: the verifier is accepted without being checked against the challenge, which is PKCE present and not implemented (RFC 7636 4.6).",
                correct_response="invalid_grant.",
                note="Send this to the token endpoint, not the authorisation endpoint.",
            )
        )
        probes.append(
            Probe(
                id=nid("PK"),
                group="pkce-enforcement",
                intent="send a valid S256 code_challenge, then redeem the code with no code_verifier at all",
                parameters={
                    "grant_type": "authorization_code",
                    "code": "<code from a request that carried a challenge>",
                    "redirect_uri": declared_redirect,
                },
                vulnerable_response="Tokens are returned: the challenge is recorded and not enforced at redemption.",
                correct_response="invalid_grant.",
                note="Send this to the token endpoint.",
            )
        )

    # -- state -------------------------------------------------------------
    probes.append(
        Probe(
            id=nid("ST"),
            group="state-binding",
            intent="omit state from the authorisation request and complete the flow",
            parameters={
                "response_type": client.response_types[0] if client.response_types else "code",
                "client_id": client.client_id,
                "redirect_uri": declared_redirect,
                "scope": " ".join(client.scopes) or "openid",
            },
            vulnerable_response="The client's callback completes a login: it does not require state, so it cannot distinguish its own flows from someone else's (SN001, ESC009).",
            correct_response="The client's callback rejects the response. Note that the provider is permitted to accept the request - this probe tests the client, not the provider.",
        )
    )
    probes.append(
        Probe(
            id=nid("ST"),
            group="state-binding",
            intent="complete a flow in one browser session and replay the full callback URL in a second, fresh session",
            parameters={"_": "replay the callback URL verbatim, including state and code"},
            vulnerable_response="The second session logs in: state is not bound to the session that started the flow, and the code is not single-use (SN002, SN003).",
            correct_response="The callback rejects the response because the state value is not the one held for that session.",
        )
    )
    probes.append(
        Probe(
            id=nid("ST"),
            group="state-binding",
            intent="collect ten state values from ten fresh flows and compare them",
            parameters={"_": "ten authorisation requests, states recorded"},
            vulnerable_response="Any shared prefix, monotonic component, or timestamp-derived structure means the value is predictable (SN004).",
            correct_response="Ten independent values with no structure, each at least 128 bits of entropy.",
        )
    )

    # -- nonce -------------------------------------------------------------
    if client.requests_id_token:
        probes.append(
            Probe(
                id=nid("NO"),
                group="nonce-binding",
                intent="request an ID token without a nonce, then with a nonce the client did not generate",
                parameters={
                    "response_type": "code",
                    "client_id": client.client_id,
                    "redirect_uri": declared_redirect,
                    "scope": "openid",
                },
                vulnerable_response="A login completes in either case: the client is not comparing the nonce claim against a stored value (SN005, SN006).",
                correct_response="The client rejects an ID token whose nonce is absent or does not equal the value it stored for the session.",
            )
        )

    # -- issuer identification --------------------------------------------
    if config.multi_provider:
        probes.append(
            Probe(
                id=nid("IS"),
                group="issuer-identification",
                intent="deliver an authorisation response obtained from provider A to the callback used for provider B",
                parameters={"_": "cross-deliver a complete authorisation response between the configured providers"},
                vulnerable_response="The client proceeds to exchange or validate against provider B's endpoints: the mix-up condition is live (SN007, ESC004).",
                correct_response="The callback rejects the response because the issuer it recorded for the session does not match.",
                note="Run this between every pair of configured providers, in both directions.",
            )
        )
    for provider in config.providers:
        probes.append(
            Probe(
                id=nid("IS"),
                group="issuer-identification",
                intent=f"complete one flow at provider {provider.name!r} and record whether the response carries iss",
                parameters={"_": "inspect the authorisation response URL"},
                vulnerable_response="No iss parameter: the client cannot establish the issuer from the response alone (SN007 or SN008).",
                correct_response="iss present and equal to the provider's issuer identifier (RFC 9207).",
            )
        )

    # -- scope -------------------------------------------------------------
    probes.append(
        Probe(
            id=nid("SC"),
            group="scope-and-consent",
            intent="request a scope beyond the client's granted set after consent has already been given once",
            parameters={
                "response_type": client.response_types[0] if client.response_types else "code",
                "client_id": client.client_id,
                "redirect_uri": declared_redirect,
                "scope": " ".join(sorted(set(client.scopes) | {"offline_access"})),
                "state": "<fresh random value>",
            },
            vulnerable_response="The widened scope is granted with no consent interaction: the user's decision no longer describes the grant in force (SC003, ESC010).",
            correct_response="A consent screen naming the additional scope, or invalid_scope.",
        )
    )

    # -- provider surface --------------------------------------------------
    for provider in config.providers:
        if provider.supports_request_uri or (
            provider.discovery.get("request_uri_parameter_supported") is True
        ):
            probes.append(
                Probe(
                    id=nid("PV"),
                    group="provider-surface",
                    intent=f"send request_uri pointing at a host you control and watch for the fetch (provider {provider.name!r})",
                    parameters={
                        "response_type": "code",
                        "client_id": client.client_id,
                        "request_uri": "<a URL on a host you control and are authorised to use for this test>",
                    },
                    vulnerable_response="A request arrives at your host from the authorisation server: the server fetches URLs named in a request, which is a server-side request forgery primitive (PV007).",
                    correct_response="invalid_request_uri, or the value rejected because it is not pre-registered.",
                    note="Only against a host you control, and only within the scope of an authorisation to test. This tool will not perform this request.",
                )
            )
        if provider.dynamic_client_registration != "closed":
            probes.append(
                Probe(
                    id=nid("PV"),
                    group="provider-surface",
                    intent=f"attempt an unauthenticated client registration at provider {provider.name!r}",
                    parameters={"_": "POST a minimal client metadata document to the registration endpoint with no credential"},
                    vulnerable_response="A client_id is returned: registration is open, and the attacker now holds a client inside the trusted issuer (PV006, ESC011).",
                    correct_response="401 or 403, with an initial access token required.",
                )
            )

    return probes
