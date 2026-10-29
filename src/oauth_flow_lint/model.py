"""The declarative model of a client and its providers.

The input to this tool is a description of a configuration, not a live system.
That is a deliberate trade: the tool cannot discover what you did not write
down, but it can reason about the whole configuration at once, offline, in
review, before anything is deployed - and the act of filling the file in is
itself the review, because a field you cannot answer is a thing nobody knows.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .urls import RedirectURI, parse_redirect_uri

CLIENT_TYPES = ("confidential", "public")
APPLICATION_TYPES = ("web", "spa", "native", "service")
MATCHING_RULES = ("exact", "prefix", "wildcard", "unknown")
REGISTRATION_MODES = ("closed", "protected", "open")
TRANSPORTS = ("header", "body", "query", "fragment", "unknown")
STORAGE_MODES = ("none", "memory", "localstorage", "sessionstorage", "cookie", "server")
STATE_SOURCES = ("csprng", "timestamp", "counter", "static", "unknown")
JWKS_SOURCES = ("pinned", "discovery", "token_header", "unknown")
PKCE_METHODS = ("S256", "plain")

#: Response types that return a credential through the front channel.
FRONT_CHANNEL_TOKEN_TYPES = ("token", "id_token")


@dataclass
class PKCE:
    used: bool = False
    method: str = "S256"


@dataclass
class StateHandling:
    sent: bool = False
    bound_to_session: bool = False
    single_use: bool = True
    entropy_bits: int = 0
    source: str = "unknown"


@dataclass
class NonceHandling:
    sent: bool = False
    bound_to_session: bool = False


@dataclass
class IdTokenValidation:
    signature_verified: bool = False
    alg_pinned: bool = False
    accepted_algs: list[str] = field(default_factory=list)
    accepts_none_alg: bool = False
    aud_checked: bool = False
    iss_checked: bool = False
    exp_checked: bool = False
    azp_checked: bool = False
    jwks_source: str = "unknown"
    jwks_host_pinned: bool = False
    expected_audiences: list[str] = field(default_factory=list)


@dataclass
class TokenHandling:
    access_token_transport: str = "header"
    refresh_token_issued: bool = False
    refresh_token_rotation: bool = False
    access_token_lifetime_seconds: int = 0
    refresh_token_lifetime_seconds: int = 0
    browser_storage: str = "none"


@dataclass
class Client:
    client_id: str = "unnamed-client"
    client_type: str = "public"
    application_type: str = "web"
    secret_present: bool = False
    redirect_uris: list[str] = field(default_factory=list)
    confirmed_open_redirect_uris: list[str] = field(default_factory=list)
    wildcard_dns_hosts: list[str] = field(default_factory=list)
    response_types: list[str] = field(default_factory=lambda: ["code"])
    response_mode: str = "query"
    grant_types: list[str] = field(default_factory=lambda: ["authorization_code"])
    scopes: list[str] = field(default_factory=list)
    stated_purpose_scopes: list[str] = field(default_factory=list)
    scope_change_reconsent: bool = True
    pkce: PKCE = field(default_factory=PKCE)
    state: StateHandling = field(default_factory=StateHandling)
    nonce: NonceHandling = field(default_factory=NonceHandling)
    id_token_validation: IdTokenValidation = field(default_factory=IdTokenValidation)
    tokens: TokenHandling = field(default_factory=TokenHandling)

    # -- derived -----------------------------------------------------------
    @property
    def parsed_redirect_uris(self) -> list[RedirectURI]:
        return [parse_redirect_uri(u) for u in self.redirect_uris]

    @property
    def is_public(self) -> bool:
        """Whether the client can actually keep a secret.

        A single-page or native application is public whatever it is
        registered as, because its code is in the hands of the user.
        """
        return self.client_type == "public" or self.application_type in ("spa", "native")

    @property
    def is_browser_based(self) -> bool:
        return self.application_type in ("web", "spa")

    @property
    def uses_implicit(self) -> bool:
        return any("token" in rt.split() for rt in self.response_types)

    @property
    def uses_code(self) -> bool:
        return any("code" in rt.split() for rt in self.response_types)

    @property
    def requests_id_token(self) -> bool:
        if any("id_token" in rt.split() for rt in self.response_types):
            return True
        return "openid" in [s.lower() for s in self.scopes]

    @property
    def hybrid_response_types(self) -> list[str]:
        out = []
        for rt in self.response_types:
            parts = set(rt.split())
            if "code" in parts and parts & {"token", "id_token"}:
                out.append(rt)
        return out

    @property
    def uses_authorization_code_grant(self) -> bool:
        return "authorization_code" in self.grant_types


@dataclass
class Provider:
    name: str = "unnamed-provider"
    issuer: str = ""
    redirect_uri_matching: str = "unknown"
    enforces_pkce: bool = False
    pkce_methods: list[str] = field(default_factory=list)
    returns_iss_parameter: bool = False
    dynamic_client_registration: str = "closed"
    supports_request_uri: bool = False
    grants_offline_access_without_request: bool = False
    discovery_document: str | None = None
    #: Parsed contents of the local discovery JSON file, if one was given.
    discovery: dict[str, object] = field(default_factory=dict)
    discovery_path: str | None = None

    @property
    def matching_is_exact(self) -> bool:
        return self.redirect_uri_matching == "exact"


@dataclass
class Capture:
    """A captured authorisation request and response, as URLs."""

    label: str = "capture"
    authorization_request: str = ""
    authorization_response: str = ""
    resource_request: str = ""


@dataclass
class Configuration:
    client: Client = field(default_factory=Client)
    providers: list[Provider] = field(default_factory=list)
    captures: list[Capture] = field(default_factory=list)
    source_path: str = "<memory>"
    #: Keys present in the file that this version does not understand. These
    #: are reported, not ignored silently: a misspelt key is a check that
    #: quietly did not run.
    unknown_keys: list[str] = field(default_factory=list)

    @property
    def multi_provider(self) -> bool:
        return len(self.providers) > 1

    @property
    def loosest_matching(self) -> str:
        """The weakest matching rule across configured providers."""
        order = {"exact": 0, "prefix": 2, "wildcard": 3, "unknown": 1}
        if not self.providers:
            return "unknown"
        return max((p.redirect_uri_matching for p in self.providers), key=lambda m: order.get(m, 1))

    @property
    def any_matching_loose(self) -> bool:
        return any(not p.matching_is_exact for p in self.providers)
