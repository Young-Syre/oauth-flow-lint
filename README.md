# oauth-flow-lint

[![tests](https://github.com/Young-Syre/oauth-flow-lint/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/oauth-flow-lint/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-success.svg)](pyproject.toml)
[![Offline](https://img.shields.io/badge/network-never-success.svg)](#no-network-ever)

An offline linter for OAuth 2.0 and OpenID Connect client configurations. You
describe a client and its providers in a TOML file; it reports the weaknesses,
and - the part that matters - the combinations those weaknesses add up to.

72 rules and 14 escalations. No dependencies, no network access.

---

## OAuth is not one protocol

OAuth 2.0 is not one protocol. It is a set of specifications with an enormous
number of locally reasonable configurations, a small minority of which are
secure, and almost no way to tell the two apart by looking at any single
setting.

Consider a redirect URI policy where the provider matches a registered value by
prefix rather than comparing it as a string. Taken alone, this is a hygiene
note. Plenty of large deployments run that way; the registered origin is still
yours, so the response still arrives somewhere you control. A reviewer reads it,
thinks "we should tighten that", and moves on.

Now suppose the same client is a single-page application using the implicit
flow. Taken alone, that is also a known item: the implicit flow is deprecated,
everyone agrees it should be migrated, it is on a roadmap somewhere.

Put the two together and you do not have two things on a roadmap. You have
account takeover. The attacker sends the victim one link - an authorisation
request whose `redirect_uri` points at any path on the registered origin that
the attacker can influence: an uploaded file, a page that reflects input, a
tenant subdomain, a second spelling of the registered path. The provider's
redirect check passes, because the string starts with the registered value. The
provider then delivers the access token to that path in the URL fragment,
because that is what `response_type=token` means. There is no code to exchange,
no client secret to obtain, and nothing for the victim to do beyond following
the link while signed in.

Neither of the two settings is the vulnerability. The combination is, and no
line of the configuration contains it.

This is the shape of nearly every real OAuth finding. The redirect URI decides
*where* a response can be delivered; the flow decides *what the response
contains*; the state and nonce handling decide *whether the client can tell its
own response from someone else's*; the token validation decides *who can mint an
identity assertion it will accept*. Each is reviewed by a different checklist
item, frequently by a different person, and the exploitable condition lives in
the join. Checklists are good at items and bad at joins, which is why
configurations pass review and then get exploited by a mechanism every reviewer
already knew about.

So this tool does two things a checklist does not. It reasons about the whole
configuration at once rather than one field at a time, and it has an explicit
dependency model: rules declare which other rules they escalate with, and a
satisfied combination is reported as **one** finding at its own severity, with
the attack written out, instead of as two mediums the reader is expected to join
by hand.

It is also deliberately offline. The input is a description of a configuration,
not a live system. That is a real trade - the tool cannot discover what you did
not write down - but it buys three things: you can run it during review, before
anything is deployed; you can run it against a production tenant without
touching it; and filling in the file *is* the review, because a field you cannot
answer is a thing nobody in the organisation knows.

## Install

Python 3.11 or newer. There is nothing to install alongside it.

```console
$ git clone https://github.com/Young-Syre/oauth-flow-lint
$ cd oauth-flow-lint
$ pip install .
```

Or run it from a checkout with no install at all:

```console
$ PYTHONPATH=src python3 -m oauth_flow_lint --help
```

## Usage

```
usage: oauth-flow-lint [-h] [--version] <command> ...

Lint an OAuth 2.0 / OpenID Connect client configuration offline, and report the
combinations of weaknesses that escalate into each other.

positional arguments:
  <command>
    lint      check a configuration and report findings and escalations
    plan      print the probe list that confirms the provider's real behaviour
    init      write a commented scaffold configuration
    rules     print the rule catalogue and the escalation matrix

options:
  -h, --help  show this help message and exit
  --version   show program's version number and exit

exit codes:
  0  no findings at or above the failure threshold (default: medium)
  1  at least one finding at or above the failure threshold
  2  the configuration could not be read or understood, or the arguments were invalid

This tool performs no network requests. A provider metadata document must be
saved to a local JSON file and referenced by path; the plan subcommand prints
requests for a human to send, and sends nothing itself.
```

Start from the scaffold, which is commented field by field and lints clean:

```console
$ oauth-flow-lint init my-client.toml
$ oauth-flow-lint lint my-client.toml
```

### The escalation case

`examples/vulnerable-spa-implicit.toml` is the configuration described above.
Here is the head of the real output:

```console
$ oauth-flow-lint lint examples/vulnerable-spa-implicit.toml
oauth-flow-lint  examples/vulnerable-spa-implicit.toml
client 'analytics-dashboard-spa' (public/spa), 1 provider(s): legacy-idp

====================================================================================================
ESCALATED COMBINATIONS
====================================================================================================

[CRIT] ESC001  front-channel-token-to-attacker-controlled-path
        at: capture dashboard sign-in, captured in a browser; client analytics-dashboard-spa; https://dash.example/ (+5 more)
        The flow returns a credential in the URL fragment, and the provider accepts a callback
        the attacker can choose within the registered origin. The attacker sends the victim an
        authorisation request whose redirect_uri points at a path they control - an uploaded
        file, a reflected page, a tenant subdomain, or a second spelling of the registered URI -
        and the provider delivers the token there. There is no code to exchange, no client
        secret to obtain, and nothing for the victim to do beyond following one link while
        signed in. The result is use of the victim's account at the resource server for the
        lifetime of the token.

        Built from: FL001 (implicit-flow), CP008 (captured-credential-in-fragment), RU002
        (redirect-uri-loose-matching), RU003 (redirect-uri-open-path-segment), RU008
        (redirect-uri-wildcard-subdomain), RU009 (redirect-uri-shared-platform-host)
        mechanism: An attacker-controlled path on a registered origin receives the access token
        directly.
        fix: Remove token from response_type and move to the authorisation code flow with PKCE;
        independently, make the provider's redirect_uri comparison exact and register complete
        URIs.
```

Nine escalations fire on that one file, and the component findings remain in the
report below them, each annotated with the combination it feeds:

```
----------------------------------------------------------------------------------------------------
total: 6 critical, 23 high, 16 medium, 4 low, 0 info  (threshold: medium)
escalations: ESC001, ESC005, ESC006, ESC007, ESC008, ESC010, ESC011, ESC012, ESC014
```

### The mix-up case

`examples/multi-idp-missing-iss.toml` is a client that is competent in almost
every respect - code flow, PKCE with S256, complete ID token validation, tokens
held server-side - and federates to three identity providers. Two of them do not
return the `iss` authorisation response parameter, and the client's `state` is
not bound to the session that started the flow:

```console
$ oauth-flow-lint lint examples/multi-idp-missing-iss.toml
oauth-flow-lint  examples/multi-idp-missing-iss.toml
client 'workspace-federated-login' (confidential/web), 3 provider(s): primary-idp, customer-a-idp, customer-b-idp

====================================================================================================
ESCALATED COMBINATIONS
====================================================================================================

[CRIT] ESC004  idp-mix-up
        at: client workspace-federated-login; provider customer-a-idp, provider customer-b-idp
        More than one provider is configured, the authorisation response carries no iss
        parameter, and the client's own per-request state is not a reliable record of which
        provider the flow was started with. The attacker starts a flow at the issuer they
        control, obtains a code or token from it, and returns it to the client's callback; the
        client exchanges or validates it against the other, trusted issuer's endpoints.
        Credentials intended for one issuer are presented to another, and the client's identity
        decision is made on the attacker's assertion.

        Built from: SN007 (iss-absent-multiple-providers), SN002 (state-not-session-bound)
        mechanism: A response from one issuer is accepted as a response from another, because
        nothing in the response names the issuer and nothing in the client's state does either.
        fix: Require the iss response parameter (RFC 9207), or use a distinct redirect URI per
        provider, and bind the issuer into the session state that the callback compares.
```

The two components are a high and a high. The combination is what gets written
up, and its fix is not the fix for either component alone.

### A clean report

A tool that cannot produce an empty report is a tool nobody reads.
`examples/hardened-web-confidential.toml` is a correctly configured confidential
web client:

```console
$ oauth-flow-lint lint examples/hardened-web-confidential.toml
oauth-flow-lint  examples/hardened-web-confidential.toml
client 'billing-portal-web' (confidential/web), 1 provider(s): corp-idp

No findings at or above medium.

----------------------------------------------------------------------------------------------------
total: 0 critical, 0 high, 0 medium, 0 low, 0 info  (threshold: medium)
$ echo $?
0
```

### Native clients, and a distinction worth getting right

An `http://` callback on a routable host is a serious finding. An
`http://127.0.0.1` callback on a native app is the mechanism the specification
provides (RFC 8252 §7.3) and is not a finding at all. Collapsing the two is how
a linter trains people to ignore it, so the native case is reported as
informational, visible only with `--all`, purely so a reviewer can see the
distinction was made rather than missed:

```console
$ oauth-flow-lint lint examples/hardened-native-pkce.toml --all
oauth-flow-lint  examples/hardened-native-pkce.toml
client 'field-app-native' (public/native), 1 provider(s): corp-idp

====================================================================================================
FINDINGS
====================================================================================================

-- Redirect URI registration and matching --------------------------------------------------------

[INFO] RU006  redirect-uri-loopback-native-accepted
        at: http://127.0.0.1/oauth2redirect
        A loopback http callback on a native client is the mechanism the specification provides,
        and is not a weakness. The provider must accept any port on this host, because the app
        cannot reserve one in advance.
        reference: RFC 8252 7.3 (loopback interface redirection)
        fix: No change needed. Accept any port on the loopback callback, as the specification
        requires.

----------------------------------------------------------------------------------------------------
total: 0 critical, 0 high, 0 medium, 0 low, 1 info  (threshold: medium; showing all severities)
```

The same URI registered for a `web` or `spa` client is reported as `RU005`,
because a browser client has a server to redirect to and therefore has no
business registering a loopback callback in production.

### `plan` - the probes that confirm what the provider actually does

Two facts decide most of this tool's output and are the hardest to establish
from documentation: how the provider really compares redirect URIs, and what it
really does when a request omits a parameter the client always sends. `plan`
turns those into an explicit list of requests for a tester to send. It builds
request descriptions and sends nothing.

```console
$ oauth-flow-lint plan examples/hardened-web-confidential.toml
oauth-flow-lint plan  examples/hardened-web-confidential.toml

These are requests for a tester to send by hand, against a system they are authorised to test.
oauth-flow-lint does not send them: this package contains no networking code. Each probe says
what a vulnerable provider does and what a correct one does, because 'it returned an error' and
'it returned an error to the URI I asked it to' are different results.


== redirect-uri-comparison =========================================================================

  RU-001  appended-path-segment: send redirect_uri=https://portal.example/auth/callback/oauth-flow-lint-probe against the registration https://portal.example/auth/callback
        response_type = code
        client_id = billing-portal-web
        redirect_uri = https://portal.example/auth/callback/oauth-flow-lint-probe
        scope = openid profile email
        state = <fresh random value>
        vulnerable: A redirect to the candidate URI, or any response other than an error, means
        the provider matches by prefix, so every path under the registered value is a valid
        callback.
        correct:    invalid_request or invalid_redirect_uri rendered on the authorisation
        server, with no redirect to the candidate.
        note:       An error shown on the provider's own page is the correct outcome. An error
        delivered *to* the candidate URI is itself an acceptance.
```

That example produces 32 probes; the vulnerable SPA, with four registered URIs
and a provider that supports `request_uri` and open registration, produces 90.
The redirect-URI group covers the normalisation traps in full: appended path
segment, appended query, appended fragment, trailing slash added and removed,
dot-segment escape, encoded dot-segment escape, double slash, backslash
authority, userinfo authority, explicitly written default port, uppercase host,
trailing-dot host, sibling subdomain, scheme downgrade, and an unrelated host as
the control case.

`--format json` and `--format markdown` are available on `lint`, `plan` and
`rules`.

## Findings

Reproduce this table with `oauth-flow-lint rules --format markdown`.

| ID | Name | Severity | Mechanism |
| --- | --- | --- | --- |
| `RU001` | redirect-uri-wildcard | high | A wildcard in a registered redirect URI means the set of hosts or paths that may receive an authorisation response is not enumerable, so an attacker only has to find one member of that set they control. |
| `RU002` | redirect-uri-loose-matching | high | If the provider matches a registered URI by prefix rather than by exact string, every URI that starts with the registered value is accepted, which turns any path-controlling primitive on the registered origin into a credential sink. |
| `RU003` | redirect-uri-open-path-segment | medium | A registered URI that is a bare origin or ends in a slash leaves the path component open, which is only meaningful once the provider matches by prefix - but when it does, the whole origin becomes the callback. |
| `RU004` | redirect-uri-insecure-scheme | high | An http callback on a routable host hands the authorisation response to any party on the network path, and the response carries either the code or the token itself. |
| `RU005` | redirect-uri-loopback-on-browser-client | medium | A loopback callback registered for a web or single-page client is a development leftover: in production it cannot serve the real user, but it can serve an attacker who gets the victim's browser to start a flow while something listens on that port locally. |
| `RU006` | redirect-uri-loopback-native-accepted | info | A loopback http callback is the specified mechanism for a native app and is not a weakness; it is reported only so that a reviewer can see the distinction was made rather than assume it was missed. |
| `RU007` | redirect-uri-unclaimable-custom-scheme | medium | A private-use URI scheme that is not a reverse-DNS name the app's publisher controls can be registered by any other application on the device, which then receives the authorisation response. |
| `RU008` | redirect-uri-wildcard-subdomain | high | If any subdomain of the registered host can be pointed at attacker infrastructure - by wildcard DNS, by a dangling delegation, or by a self-service subdomain feature - then the registered origin is not a trust boundary. |
| `RU009` | redirect-uri-shared-platform-host | high | A callback on a platform-provided hostname shares its registrable domain with every other tenant of that platform, so another tenant can host a page under a sibling name and, under anything looser than exact matching, under a sibling path. |
| `RU010` | redirect-uri-reflecting-path | medium | The registered path matches a shape that conventionally forwards the browser onward from a request parameter; if it does, the authorisation response is handed to whatever that parameter names. |
| `RU011` | redirect-uri-open-redirector | high | The callback is a confirmed open redirector, so the authorisation response is forwarded off the registered origin to a destination the attacker chooses, carrying the code in the query or the token in the fragment. |
| `RU012` | redirect-uri-has-fragment | high | A fragment in a registered redirect URI is prohibited because the fragment is where the implicit and hybrid flows place credentials; a registered fragment either collides with that or reveals that the provider's comparison is not a string comparison at all. |
| `RU013` | redirect-uri-has-query | low | A query component is permitted in a registered redirect URI, but it must survive the provider merging its own response parameters into the same component; providers differ on ordering and on duplicate keys, and the difference is where parameter-smuggling lives. |
| `RU014` | redirect-uri-mixed-strictness | high | When several URIs are registered for one client, the client's security is set by the weakest of them, because the attacker picks which one to send; a strict production callback does not compensate for a loose one beside it. |
| `RU015` | redirect-uri-userinfo | medium | A userinfo component makes the authority ambiguous to readers and to some comparison code: everything before the @ is credentials, not a host, so a URI that appears to point at the registered origin may resolve elsewhere. |
| `RU016` | redirect-uri-normalisation-hazard | medium | Exact string comparison is only safe if both sides agree on the string: a trailing slash, an explicitly written default port, percent-encoding, a dot segment, a double slash or a backslash each produce two spellings of one URI, and the provider and the browser need not resolve them the same way. |
| `RU017` | redirect-uri-idn-host | medium | A host with non-ASCII labels, or with labels already in punycode, has two spellings; comparison on one spelling and resolution on the other, or a homograph of the registered name, both let a different host pass as the registered one. |
| `RU018` | redirect-uri-missing | medium | With no registered callback the provider has nothing to compare against, so whatever redirect_uri the authorisation request carries is where the response goes. |
| `FL001` | implicit-flow | high | The implicit flow returns the access token in the URL fragment, so the token exists in the browser history, in the Referer of anything the callback page loads, and in any onward redirection, with no client authentication anywhere in the exchange. |
| `FL002` | hybrid-flow | medium | A hybrid response_type delivers part of the credential set through the front channel; the front-channel part inherits the fragment's leakage paths even though a back-channel exchange also takes place. |
| `FL003` | code-flow-without-pkce | high | A public client has no secret, so an authorisation code is the only thing standing between an attacker who intercepts the redirect and a valid token; without a code_verifier, interception of the code is sufficient. |
| `FL004` | pkce-method-plain | medium | With method plain the challenge is the verifier, so anything that can read the authorisation request can replay the token request; PKCE then proves only that the same party sent both messages to an observer who saw neither. |
| `FL005` | pkce-not-enforced-by-provider | medium | If the provider treats code_challenge as optional, an attacker who can shape the authorisation request simply omits it, and the provider issues a code that needs no verifier - the client's correct use of PKCE is not a control the attacker has to defeat. |
| `FL006` | resource-owner-password-grant | high | The password grant requires the client to handle the user's primary credential, which removes the provider's ability to apply its own authentication policy and gives every client a credential-stuffing surface. |
| `FL007` | implicit-flow-on-native-client | high | A native app receives the implicit response through a URI scheme or loopback listener that other software on the device can claim, so the token is delivered to whatever registered for that scheme first. |
| `FL008` | secret-in-public-client | high | A secret shipped inside a single-page app or a mobile binary is readable by anyone who has the app, so the client is public whatever it is registered as - and any control the provider applies because it believes the client is confidential is not applied. |
| `FL009` | response-mode-fragment-unnecessary | low | Fragment response mode on a code flow puts the code where script on the callback page can read it and where it survives in history, for no benefit the query or form_post modes do not provide. |
| `FL012` | front-channel-id-token | medium | An ID token returned in the callback fragment with no code exchange is a bearer assertion of identity, so a relying party that treats one as proof of authentication accepts whatever reaches its callback — the redirect URI and the nonce are the whole of the defence. Lower than `FL001` because an ID token is not a key to an API, and not absent, because it is still an account takeover where the redirect is loose. |
| `FL010` | pkce-method-unsupported-by-provider | medium | The client declares a challenge method the provider does not advertise, so in practice the request either fails or silently degrades to a weaker method - and a silent degradation is a control that is believed to be present and is not. |
| `FL011` | provider-advertises-plain-pkce | low | A provider that accepts method plain offers a downgrade an attacker can request even when the client always uses S256. |
| `SN001` | state-absent | high | Without state the callback cannot tell a response it caused from one an attacker caused, which is login cross-site request forgery: the victim's session is bound to the attacker's authorisation response, or the attacker's code is injected into the victim's session. |
| `SN002` | state-not-session-bound | high | A state value that is generated and echoed but never compared against something held in the user's session proves nothing; the attacker obtains a valid state from their own flow and uses it in the victim's. |
| `SN003` | state-reused | medium | A state value that is not single-use lets a captured callback be replayed, and removes the ordering guarantee that makes the comparison meaningful when several flows are in flight. |
| `SN004` | state-predictable | high | A state value derived from a timestamp, a counter, or a fixed string can be produced by the attacker, so the comparison on callback succeeds for a response the attacker initiated. |
| `SN005` | nonce-absent | high | Without a nonce the client cannot tell that an ID token was minted for this authentication request, so a token captured or obtained elsewhere can be replayed into this login. |
| `SN006` | nonce-not-session-bound | medium | A nonce that is sent but not stored and compared is a value in a URL, not a binding; the replay it is supposed to prevent still succeeds. |
| `SN007` | iss-absent-multiple-providers | high | With more than one provider configured and no issuer identifier in the authorisation response, the client must guess which provider a response came from; an attacker who controls or operates one provider gets a response accepted as if it came from another. This is the mix-up condition. |
| `SN008` | iss-absent-single-provider | low | With one provider the mix-up attack has nothing to mix up, but the absence of the issuer parameter means that adding a second provider later silently introduces the condition, with no change to the client code that would prompt a review. |
| `TK001` | id-token-signature-unverified | critical | An unverified ID token is a set of claims supplied by whoever sent the request, so the subject identifier - the thing the application treats as the user's identity - is attacker-chosen. |
| `TK002` | id-token-alg-not-pinned | high | If the accepted algorithm is taken from the token's own header, the token chooses how it is checked; the classic result is a token signed with HMAC using the provider's public key as the shared secret. |
| `TK003` | id-token-none-alg-accepted | critical | Accepting alg none means an unsigned token is a valid token, so identity assertions can be written by hand. |
| `TK004` | id-token-aud-unchecked | high | Without an audience check, a token minted for a different client of the same provider is accepted here; any other client - including one an attacker registers - becomes a source of valid identity assertions for this application. |
| `TK005` | id-token-iss-unchecked | high | Without an issuer check the token's origin is unconstrained, so a token from any issuer whose key the client happens to accept passes. |
| `TK006` | id-token-azp-ignored | medium | When a token carries multiple audiences, azp names the party it was actually issued to; ignoring it means a token legitimately issued to a different authorised party is accepted as one issued here. |
| `TK007` | jwks-from-token-header | critical | Fetching the verification key from a location named inside the token means the token supplies its own key, so the signature check confirms only that the token is internally consistent. |
| `TK008` | jwks-host-unpinned | medium | A key set resolved through discovery each time, with no constraint on the host it is served from, moves trust from the issuer to whatever answered the metadata request. |
| `TK009` | access-token-in-query | high | A token in a query string is recorded by proxies, access logs and analytics, and is sent in the Referer of requests the receiving page makes, so the bearer credential ends up in places the application does not control. |
| `TK010` | refresh-token-public-client-no-rotation | high | A refresh token issued to a client that cannot authenticate, and that stays valid after use, converts one theft into indefinite access with no further interaction and nothing to detect. |
| `TK011` | access-token-lifetime-excessive | low | A long-lived access token widens the window in which a leaked token is useful, and in a browser client the leak paths are the ones this tool's other rules describe. |
| `TK012` | refresh-token-lifetime-unbounded | medium | A refresh token with no expiry is a permanent credential, so revocation becomes the only control and it has to work perfectly and forever. |
| `TK013` | tokens-in-web-storage | medium | Tokens in localStorage or sessionStorage are readable by any script that runs on the origin, so every cross-site scripting bug in the application, or in anything it loads, becomes token theft. |
| `TK014` | id-token-exp-unchecked | high | Without an expiry check an ID token never stops being accepted, so a token captured once authenticates forever. |
| `SC001` | offline-access-by-default | medium | Requesting offline access on every flow means every user grant produces a long-lived refresh token, including for the flows that only needed to identify the user, so the blast radius of a token leak is set by the default rather than by need. |
| `SC002` | scope-exceeds-stated-purpose | medium | A scope the client's stated purpose does not need is authority held for no reason; it is the difference between a token leak that exposes a profile and one that exposes mailboxes. |
| `SC003` | scope-upgrade-without-reconsent | medium | If a later request can widen the granted scope without a new consent step, the user's decision covers a smaller grant than the one in force, and the widening is invisible to them. |
| `PV001` | discovery-endpoint-insecure-scheme | high | An endpoint published over http can be answered by anyone on the network path, and the endpoints in question are where codes are exchanged and keys are published. |
| `PV002` | jwks-uri-foreign-host | medium | A key set served from a host other than the issuer's means the set of parties who can mint tokens the client will accept includes whoever controls that host. |
| `PV003` | token-endpoint-auth-none-supported | medium | Advertising none as a token endpoint authentication method means a client registered as confidential can be used without its secret if the provider does not pin the method per client. |
| `PV004` | response-modes-fragment-supported | info | Fragment response mode is advertised while no configured client needs it; it remains available to an attacker shaping an authorisation request, which is only useful to them in combination with a flow that returns credentials. |
| `PV005` | pkce-methods-not-advertised | medium | Metadata that omits code_challenge_methods_supported gives a client no way to know whether PKCE is available, which in practice means clients ship without it or assume it and are wrong. |
| `PV006` | dynamic-registration-open | high | Open dynamic client registration lets anyone create a client in the same issuer, which is the precondition for every attack that depends on a second client the provider considers legitimate. |
| `PV007` | request-uri-supported | medium | Accepting a request object by reference means the authorisation server fetches a URL supplied in a request, which is a server-side request forgery primitive inside the authentication system. This tool reports the capability and never fetches anything. |
| `PV008` | discovery-issuer-mismatch | high | If the issuer in the metadata is not the issuer the client expects, then either the metadata is for a different authorisation server or the client's issuer comparison will reject every token; both mean the client's trust anchor is not the one it was reviewed against. |
| `PV009` | implicit-response-types-supported | low | The provider still offers response types that return tokens in the front channel, so the flow a client is not supposed to use remains reachable by anyone who can shape its authorisation request. |
| `PV010` | discovery-s256-not-offered | medium | Metadata that lists challenge methods without S256 means the only PKCE available is the one that protects nothing against an attacker who can read the authorisation request. |
| `CP001` | captured-response-type-undeclared | high | The captured authorisation request uses a response type the configuration does not declare, so either the configuration under review is not the one in use or the provider does not restrict response types for this client. |
| `CP002` | captured-request-missing-state | high | No state parameter was present in the authorisation request that was actually sent, whatever the configuration says. |
| `CP003` | captured-request-missing-pkce | high | No code_challenge was present in the authorisation request that was actually sent, so PKCE was not in use for this flow regardless of what the client is configured to do. |
| `CP004` | captured-request-missing-nonce | high | The captured request asks for an ID token without a nonce, so the token that comes back cannot be bound to this request. |
| `CP005` | captured-token-in-query | high | A token was observed in a URL query component, which is the component that is logged and sent in the Referer. |
| `CP006` | captured-redirect-uri-unregistered | high | The redirect_uri actually sent is not one of the registered values under exact comparison, which means the provider accepted something the registration does not contain - the matching rule is looser than the configuration claims. |
| `CP007` | captured-response-missing-iss | medium | The captured authorisation response carries no iss parameter, so the client cannot establish which issuer produced it from the response alone. |
| `CP008` | captured-credential-in-fragment | high | A credential was observed in the fragment of a captured URL, which confirms front-channel delivery in practice rather than as a configuration claim. |

## Escalation matrix

An escalation fires when at least one rule from the left column and at least
one from the middle column are both present in the same report. It produces one
finding at its own severity, with the attack written out; the component findings
stay in the report, each annotated with the combination it feeds, because each
is independently worth fixing and because the reader needs to see what the
combination was built from.

The matrix is data, not prose: this table is generated from the same structure
the tool evaluates (`oauth-flow-lint rules --matrix`), so the documentation
cannot describe a combination that is not implemented.

| ID | Severity | Any of | Combined with any of | Result |
| --- | --- | --- | --- | --- |
| `ESC001` | critical | `FL001`, `FL002`, `CP008` | `RU001`, `RU002`, `RU003`, `RU008`, `RU009`, `RU016` | An attacker-controlled path on a registered origin receives the access token directly. |
| `ESC002` | critical | `FL003` | `RU001`, `RU002`, `RU003`, `RU008`, `RU009`, `RU016` | A code delivered to an attacker-controlled path is exchangeable, because the client has no secret and no verifier. |
| `ESC003` | high | `FL005` | `RU001`, `RU002`, `RU003`, `RU008`, `RU009`, `RU016` | The attacker omits code_challenge from the request they craft, so the client's PKCE is not in the attack path at all. |
| `ESC004` | critical | `SN007` | `SN002`, `SN001`, `TK005` | A response from one issuer is accepted as a response from another, because nothing in the response names the issuer and nothing in the client's state does either. |
| `ESC005` | critical | `TK002`, `TK003` | `TK007`, `TK008` | The token chooses both the algorithm and the key used to verify it, so any party can mint an accepted identity assertion. |
| `ESC006` | critical | `TK004` | `TK006`, `PV006`, `TK005` | An ID token issued to a different client of the same issuer is accepted here, and obtaining such a token is cheap. |
| `ESC007` | critical | `FL001`, `FL002`, `CP008` | `RU010`, `RU011` | The registered callback forwards the browser onward, carrying the credential to a host the attacker names. |
| `ESC008` | high | `TK010` | `TK013`, `FL001`, `TK009`, `CP008` | A non-rotating refresh token held somewhere readable turns a single leak into access that renews itself indefinitely. |
| `ESC009` | high | `SN001`, `SN002` | `FL003`, `FL005` | With neither a session-bound state value nor a verifier, an authorisation code from another flow can be injected into the victim's session. |
| `ESC010` | high | `SC003` | `SC001`, `TK012`, `TK010` | Scope can be widened without a consent interaction, and the widened scope yields a credential that outlives the session. |
| `ESC011` | high | `PV006` | `PV003`, `PV007` | Anyone can create a client in this issuer, and the created client needs no credential to use - or can make the authorisation server fetch a URL. |
| `ESC012` | critical | `PV001` | `TK008`, `PV002` | A network attacker answers the metadata request and thereby chooses the keys the client will trust. |
| `ESC013` | high | `RU007` | `FL003`, `FL005`, `FL001` | Another application on the device claims the callback scheme and receives a credential it can use without a secret. |
| `ESC014` | critical | `TK009`, `CP005` | `RU010`, `RU011` | A bearer token in a URL reaches an endpoint that forwards the request onward, so the token is handed to a host the attacker names and written into its logs. |

### Two escalations that look similar and are not

`ESC001` and `ESC007` both start from a credential delivered through the front
channel, and they are deliberately separated by where the credential ends up.
`ESC001` is delivery *to a path on the registered origin* that the attacker can
influence - the response never leaves your origin, and the provider's check was
satisfied the whole time. `ESC007` is delivery to the registered callback
followed by the callback *forwarding the browser off the origin*, which puts the
credential on the attacker's own host. They have different fixes: the first is
fixed at the provider's comparison rule and in the flow, the second in the
callback's own behaviour. Reporting them as one finding would hide that.

## Input format

The configuration is a single TOML file. `oauth-flow-lint init` writes a
commented scaffold that documents every field, and the scaffold lints clean, so
the first run teaches the right defaults rather than the wrong ones.

The three things worth knowing before you start:

**Secrets are never needed.** The tool asks whether a client secret exists
(`secret_present = true`) and how it is handled, never what it is. If a
configuration does contain a `client_secret` string, only its presence is read;
the value is discarded. Use `"REDACTED-TEST-VALUE"` if you want the field there
for shape.

**A provider metadata document is a local file.** `discovery_document` takes a
path, resolved relative to the configuration file. A URL is an error with an
explanation, not an invitation - save the document first.

**Captures outrank declarations.** The optional `[capture]` section takes URLs
from a real flow. The configuration says what someone believes the client does;
a capture records what it did. Where they disagree, the capture wins and the
disagreement is itself a finding (`CP001`-`CP008`), because it means the
configuration under review is not the configuration in force.

An unrecognised key is reported rather than ignored. In a linter, an ignored key
is a check that quietly did not run, and nobody notices a check that did not
run.

## Redirect URI normalisation

Every redirect URI question is decided on a parsed URL - scheme, userinfo, host,
port, path, query, fragment - never on a substring of the raw text. The
specification's comparison rule is simple string equality (RFC 3986 §6.2.1,
required by OIDC Core §3.1.2.1), which is only safe when both sides agree on the
spelling, so the parser's second job is to enumerate the places where one URI
has two spellings:

| Hazard | Example | Why it matters |
| --- | --- | --- |
| trailing slash | `https://app.example/cb/` | the same callback also has a spelling without it |
| bare origin | `https://app.example` | the equivalent spelling with an explicit `/` is a different string |
| explicit default port | `https://app.example:443/cb` | the same origin also has a spelling without the port |
| percent-encoded separator | `https://app.example/cb%2Fsub` | decoded and encoded spellings name the same resource to a server that decodes before routing |
| percent-encoding case | `%2f` versus `%2F` | RFC 3986 §6.2.2.1 normalises escapes to uppercase, so two spellings exist |
| userinfo | `https://app.example@evil.example/cb` | everything before the `@` is credentials; the host is `evil.example` |
| IDN / punycode | `https://xn--80ak6aa92e.example/cb` | a U-label and an A-label spelling of one name, plus homographs |
| backslash | `https://app.example\@evil.example/cb` | a browser normalises `\` to `/` before splitting the authority and goes to `app.example`; a server-side parser reads the host as `evil.example` |
| double slash | `https://app.example//cb` | some routers collapse empty segments and some do not; a path beginning `//` is read as a scheme-relative authority |
| dot segment | `https://app.example/cb/../other` | resolves to a different path than the one written, letting a registered prefix reach outside its own directory |
| uppercase host | `https://APP.example/cb` | the host is case-insensitive and a string comparison is not |
| trailing-dot host | `https://app.example./cb` | resolves identically, compares differently, and is a distinct `Host` header to many front ends |

Each of those has a test, and each appears in the `plan` output as a probe, so
you can find out which of them your provider actually normalises before
comparing.

The backslash case is the one most worth looking at, because the tool reports
both readings rather than asserting that one is right:

```
[HIGH] RU016  redirect-uri-normalisation-hazard [adjusted from medium]
        at: https://app.example\@evil.example/cb
        This single string names two hosts. A server-side URL parser reads the host as
        'evil.example'; a browser, which normalises the backslash to a forward slash before
        splitting the authority, navigates to 'app.example'. Whichever side the provider
        compares on, the browser goes to the other.
        escalates into: ESC002
        reference: OIDC Core 3.1.2.1 (comparison per RFC 3986 6.2.1)
```

(The `[adjusted from medium]` marker appears whenever an instance of a rule is
graded differently from the rule's base severity, and the reason is always in
the detail text. The `escalates into` line is there because this registration is
reachable by an attacker, which makes it one half of `ESC002`.)

## No network, ever

This is the claim the tool makes most prominently, so it has a test rather than
a sentence. `tests/test_no_network.py` parses the abstract syntax tree of every
module in the package and asserts that none of them imports `socket`, `ssl`,
`urllib.request`, `http.client`, `subprocess`, `requests`, `httpx`, `aiohttp`,
`asyncio`, or any of the other roots on its list; that the only member of
`urllib` imported anywhere is `urllib.parse`; and, as a cruder second check,
that no module contains a dynamic-import or request-function call by name. It
also asserts that `pyproject.toml` declares no dependencies.

The AST check is used rather than a text search so that it cannot be defeated by
formatting and does not trip over the word appearing in prose.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | no finding at or above the failure threshold. For `plan`, `rules` and `init`, success. |
| `1` | at least one finding at or above the failure threshold. |
| `2` | the tool could not do its job: a configuration that will not parse, a value outside its permitted set, a file that cannot be read or written, invalid arguments, or a `discovery_document` given as a URL. |

The threshold defaults to `medium` and is set with `--fail-on {critical,high,medium,low,info}`.

The distinction between `1` and `2` is the one that matters in a pipeline: `1`
is an answer, `2` is the absence of one. A pipeline that treats every nonzero
exit the same will pass silently the day someone renames the configuration file.

## What this tool does not do

Stated plainly, because a linter's limitations are the part people most need to
know and the part most often left out.

- **It does not look at your code.** It reads a description of a configuration.
  If the description is wrong, the output is wrong. The `[capture]` section
  exists to catch exactly that, by comparing the description against URLs from a
  real flow, and the `plan` subcommand exists to establish the provider-side
  facts the description asserts.
- **It never touches the network.** It cannot discover your provider's real
  redirect URI matching rule, fetch a metadata document, read a JWKS, or confirm
  that PKCE is enforced. It tells you which of those facts its conclusions rest
  on, and `plan` prints the requests that settle them.
- **It does not validate tokens.** It takes no token as input and parses no JWT.
  The ID token rules read the client's *declared* validation steps. A client
  that declares `signature_verified = true` and does not verify signatures gets
  a clean report, which is a limitation of any configuration-level review.
- **The shared-platform host list is a short, explicit list, not a public-suffix
  implementation.** It covers the common multi-tenant hosting suffixes and will
  miss others. It is in `src/oauth_flow_lint/urls.py` and is meant to be edited.
- **Forwarding detection is pattern-based.** `RU010` fires on path and query
  shapes that conventionally forward the browser onward. It is a prompt to check
  by hand, not a confirmed open redirect. When you have confirmed one, record it
  in `confirmed_open_redirect_uris` and it becomes `RU011`, which is what the
  `ESC007` and `ESC014` escalations are built on.
- **Severities are this tool's opinion.** They are a starting point for
  triage, not a risk assessment for your deployment. Every finding prints the
  mechanism so you can disagree on an informed basis.
- **It covers no extension it has not been taught.** There are no rules for
  pushed authorisation requests, DPoP, mTLS-bound tokens, JARM, token exchange,
  the device grant, or CIBA. A configuration using them will lint without
  comment on those parts, which is silence rather than approval.
- **It does not know your threat model.** A `LOW` here may be the finding that
  matters to you, and a `CRITICAL` may be unreachable in your deployment for a
  reason the configuration does not express.

## A note on the specification references

Each rule carries a reference where one exists and is unambiguous. Section
numbers are given only where they are specific and checkable - RFC 6749 §3.1.2
for the prohibition on a fragment in a registered redirect URI, RFC 7636 §4.2
for `S256` being mandatory to implement on the server, RFC 8252 §7.3 for
loopback redirection, OIDC Core §3.1.3.7 for the ID token validation steps, RFC
9207 §2 for the `iss` response parameter. Where a requirement is clearly in a
document but the precise section would be a guess, the reference names the
document only: several rules cite "RFC 9700 (OAuth 2.0 Security BCP)" or "RFC
6819" without a section for that reason. If you find a citation that is wrong,
that is a bug worth reporting - a confidently wrong section number is worse than
none.

## Development

```console
$ python -m unittest discover -s tests -t . -v
```

The suite is 406 tests with no fixtures outside `examples/`, and it runs offline
in well under a second. It covers every rule in the catalogue, every row of the
escalation matrix in both directions - fires when both halves are present, does
not fire when either is removed - every normalisation hazard above, the loader's
validation, the CLI's three output formats and three exit codes, and the
assertion that the package cannot make a network request.

Current state, run with Python 3.14 locally and in the matrix on 3.11, 3.12 and
3.13 in CI:

```console
$ python -m unittest discover -s tests -t .
----------------------------------------------------------------------
Ran 406 tests in 0.162s

OK
```

An invariant test asserts that every rule ID in the catalogue appears somewhere
in the test suite's source, so a rule cannot be added without a test.

## Licence

MIT. See [LICENSE](LICENSE).
