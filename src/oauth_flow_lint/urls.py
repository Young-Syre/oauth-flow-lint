"""Redirect URI parsing, classification and normalisation hazards.

Redirect URI questions are decided here, on a parsed URL, never on a substring
of the raw text. The specification's comparison rule is simple string equality
(RFC 3986 6.2.1, required by OIDC Core 3.1.2.1), which is safe only when both
sides agree on the spelling - so this module's second job is to enumerate the
places where two spellings of one URI exist.

Only ``urllib.parse`` is used, and only to parse. Nothing in this package opens
a connection or resolves a name.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit

#: Hosts that denote the loopback interface. RFC 8252 7.3 scopes loopback
#: redirection to native apps, where an http loopback callback is correct.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"})

DEFAULT_PORTS = {"http": 80, "https": 443}

#: Registrable-suffix shapes where a hostname is handed out to tenants. A
#: callback here shares its registrable domain with unrelated parties, so the
#: origin is not a trust boundary. The list is deliberately short and explicit;
#: it is not a public-suffix implementation.
SHARED_PLATFORM_SUFFIXES = (
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "netlify.com",
    "github.io",
    "gitlab.io",
    "herokuapp.com",
    "azurewebsites.net",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "onrender.com",
    "fly.dev",
    "glitch.me",
    "repl.co",
    "replit.app",
    "surge.sh",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "s3.amazonaws.com",
    "cloudfront.net",
    "blob.core.windows.net",
    "storage.googleapis.com",
)

#: Path shapes that conventionally forward the browser onward from a request
#: parameter. A match is a prompt to check, not a confirmed open redirect; the
#: configuration can confirm one with ``confirmed_open_redirect_uris``.
REFLECTING_PATH_SEGMENTS = (
    "redirect",
    "redir",
    "goto",
    "go",
    "out",
    "away",
    "exit",
    "link",
    "jump",
    "forward",
    "continue",
    "proxy",
    "url",
    "return",
)

#: Query parameter names that conventionally carry an onward destination.
REFLECTING_QUERY_KEYS = (
    "next",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "returnto",
    "return_to",
    "returnurl",
    "return_url",
    "url",
    "target",
    "dest",
    "destination",
    "continue",
    "goto",
    "r",
    "u",
)

# ---------------------------------------------------------------------------
# Hazard identifiers. Each one names a way in which one URI has two spellings.
# ---------------------------------------------------------------------------
HAZARD_DESCRIPTIONS: dict[str, str] = {
    "backslash": "contains a backslash; browsers treat it as a path separator while most server-side URL parsers do not, so the authority a comparison sees and the authority the browser navigates to can differ",
    "trailing-slash": "path ends in a slash, so the same callback also has a spelling without it and an exact comparison accepts only one of the two",
    "empty-path": "no path component, so the callback is the bare origin; the equivalent spelling with an explicit '/' is a different string",
    "default-port-written": "writes the scheme's default port explicitly, so the same origin also has a spelling without the port",
    "percent-encoded-reserved": "percent-encodes a reserved character in the path, so the decoded and encoded spellings differ while naming the same resource to a server that decodes before routing",
    "percent-encoding-case": "uses lowercase hexadecimal in a percent-escape; RFC 3986 6.2.2.1 normalises escapes to uppercase, so two spellings exist",
    "dot-segment": "contains a '.' or '..' path segment, which resolves to a different path than the one written and lets a registered prefix reach outside its own directory",
    "double-slash": "contains an empty path segment ('//'), which some routers collapse and some do not; a path beginning '//' is also read as a scheme-relative authority by a browser",
    "userinfo": "carries a userinfo component, so everything before the '@' is credentials rather than a host and the real authority is easy to misread",
    "idn-unicode-host": "host contains non-ASCII labels, which have both a U-label and an A-label spelling",
    "punycode-host": "host contains an A-label (xn--) prefix, so a Unicode spelling of the same name exists",
    "uppercase-host": "host contains uppercase characters; the host is case-insensitive but a string comparison is not",
    "trailing-dot-host": "host ends in a dot, which resolves identically but compares as a different string",
    "credential-shaped-query": "query names a parameter that conventionally carries an onward destination",
}


@dataclass(frozen=True)
class RedirectURI:
    """A registered or observed redirect URI, parsed once.

    ``raw`` is kept because the specification's comparison is on the raw
    string; ``canonical`` is the normalised form, used only to decide whether
    two registrations are spellings of one URI.
    """

    raw: str
    scheme: str
    userinfo: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    hazards: tuple[str, ...]
    error: str | None = None
    #: The host a browser would navigate to, when it differs from the host a
    #: server-side parser reads. A backslash is the usual cause: browsers
    #: normalise it to a forward slash before splitting the authority, and
    #: ``urlsplit`` does not, so one string names two hosts.
    browser_host: str | None = None

    # -- shape -------------------------------------------------------------
    @property
    def valid(self) -> bool:
        return self.error is None

    @property
    def is_http(self) -> bool:
        return self.scheme in ("http", "https")

    @property
    def is_loopback(self) -> bool:
        return self.host in LOOPBACK_HOSTS

    @property
    def is_private_use_scheme(self) -> bool:
        """A non-http scheme, as used by native apps (RFC 8252 7.1)."""
        return bool(self.scheme) and not self.is_http

    @property
    def is_reverse_dns_scheme(self) -> bool:
        """``com.example.app`` rather than ``myapp``."""
        return self.is_private_use_scheme and "." in self.scheme

    @property
    def authority(self) -> str:
        if not self.host:
            return ""
        if self.port is None:
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.authority}" if self.is_http else f"{self.scheme}:"

    @property
    def registrable_host(self) -> str:
        return self.host

    @property
    def has_wildcard(self) -> bool:
        return "*" in self.host or "*" in self.path

    @property
    def path_is_open(self) -> bool:
        """True when the path leaves a suffix free under prefix matching."""
        return self.path in ("", "/") or self.path.endswith("/")

    @property
    def canonical(self) -> str:
        """A normalised spelling, for equivalence only - never for matching."""
        host = self.host.rstrip(".")
        port = ""
        if self.port is not None and self.port != DEFAULT_PORTS.get(self.scheme):
            port = f":{self.port}"
        path = resolve_dot_segments(collapse_empty_segments(self.path)) or "/"
        path = quote(unquote(path), safe="/-._~!$&'()*+,;=:@%")
        base = f"{self.scheme}://{host}{port}{path}" if self.is_http else f"{self.scheme}:{host}{path}"
        if self.query:
            base += "?" + self.query
        return base

    @property
    def host_is_ambiguous(self) -> bool:
        return self.browser_host is not None and self.browser_host != self.host

    def describe_hazards(self) -> list[str]:
        return self.describe_hazards_for(self.hazards)

    @staticmethod
    def describe_hazards_for(hazards: tuple[str, ...] | list[str]) -> list[str]:
        return [f"{h} ({HAZARD_DESCRIPTIONS[h]})" for h in hazards if h in HAZARD_DESCRIPTIONS]


def collapse_empty_segments(path: str) -> str:
    """Collapse runs of slashes, as a router that normalises paths would."""
    if "//" not in path:
        return path
    leading = path.startswith("/")
    parts = [p for p in path.split("/") if p != ""]
    out = "/".join(parts)
    return ("/" + out) if leading else out


def resolve_dot_segments(path: str) -> str:
    """Apply RFC 3986 5.2.4 remove_dot_segments to a path."""
    if "." not in path:
        return path
    absolute = path.startswith("/")
    trailing = path.endswith(("/", "/.", "/.."))
    out: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    resolved = "/".join(out)
    if absolute:
        resolved = "/" + resolved
    if trailing and not resolved.endswith("/"):
        resolved += "/"
    return resolved


def _percent_hazards(component: str) -> list[str]:
    hazards: list[str] = []
    if "%" not in component:
        return hazards
    i = 0
    reserved_encoded = False
    lowercase_hex = False
    while True:
        i = component.find("%", i)
        if i == -1:
            break
        escape = component[i + 1 : i + 3]
        if len(escape) == 2:
            if any(c in "abcdef" for c in escape):
                lowercase_hex = True
            try:
                value = int(escape, 16)
            except ValueError:
                value = -1
            # Separators and dots: the characters whose decoded form changes
            # how a path is routed.
            if value in (0x2F, 0x5C, 0x2E, 0x3F, 0x23, 0x00, 0x25):
                reserved_encoded = True
        i += 1
    if reserved_encoded:
        hazards.append("percent-encoded-reserved")
    if lowercase_hex:
        hazards.append("percent-encoding-case")
    return hazards


def parse_redirect_uri(raw: str) -> RedirectURI:
    """Parse a redirect URI and record every normalisation hazard it carries.

    Parsing never fails by raising: an unusable value comes back with ``error``
    set, so one malformed registration cannot stop the rest of the audit.
    """
    text = raw
    hazards: list[str] = []

    if not isinstance(raw, str) or not raw.strip():
        return RedirectURI("", "", "", "", None, "", "", "", (), "empty value")

    if "\\" in text:
        hazards.append("backslash")
    if any(ch in text for ch in "\r\n\t") or any(ord(ch) < 0x20 for ch in text):
        return RedirectURI(raw, "", "", "", None, "", "", "", tuple(hazards), "contains a control character")

    # A wildcard is not valid in a URI, so take it out before parsing and
    # record it on the parsed result instead. Parsing a placeholder keeps the
    # host/path split correct for a value like https://*.app.example/cb.
    placeholder = "\u0001"
    had_wildcard = "*" in text
    if had_wildcard:
        text = text.replace("*", placeholder)

    try:
        split = urlsplit(text)
    except ValueError as exc:
        return RedirectURI(raw, "", "", "", None, "", "", "", tuple(hazards), f"unparseable: {exc}")

    scheme = split.scheme.lower()
    if not scheme:
        return RedirectURI(raw, "", "", "", None, "", "", "", tuple(hazards), "no scheme; a redirect URI must be an absolute URI (RFC 6749 3.1.2)")

    netloc = split.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, _, netloc = netloc.rpartition("@")
        hazards.append("userinfo")

    try:
        port = split.port
    except ValueError as exc:
        return RedirectURI(raw, scheme, userinfo, "", None, split.path, split.query, split.fragment, tuple(hazards), f"invalid port: {exc}")

    hostname = netloc
    if hostname.startswith("["):
        hostname = hostname.partition("]")[0] + "]"
    elif ":" in hostname:
        hostname = hostname.partition(":")[0]

    explicit_port_text = ""
    bare = netloc
    if bare.startswith("["):
        _, _, after = bare.partition("]")
        explicit_port_text = after[1:] if after.startswith(":") else ""
    elif ":" in bare:
        explicit_port_text = bare.partition(":")[2]

    host_raw = hostname.strip("[]")
    if any(c.isupper() for c in host_raw):
        hazards.append("uppercase-host")
    host = host_raw.lower()
    if host.endswith(".") and len(host) > 1:
        hazards.append("trailing-dot-host")
    if any(ord(c) > 127 for c in host):
        hazards.append("idn-unicode-host")
    elif any(label.startswith("xn--") for label in host.split(".")):
        hazards.append("punycode-host")

    if explicit_port_text and port is not None and DEFAULT_PORTS.get(scheme) == port:
        hazards.append("default-port-written")

    path = split.path
    if scheme in ("http", "https"):
        if path == "":
            hazards.append("empty-path")
        elif path.endswith("/") and path != "/":
            hazards.append("trailing-slash")
        elif path == "/":
            hazards.append("empty-path")
    if "//" in path:
        hazards.append("double-slash")
    segments = path.split("/")
    if "." in segments or ".." in segments:
        hazards.append("dot-segment")
    hazards.extend(_percent_hazards(path))
    if split.query:
        keys = {kv.partition("=")[0].lower() for kv in split.query.split("&")}
        if keys & set(REFLECTING_QUERY_KEYS):
            hazards.append("credential-shaped-query")

    def restore(value: str) -> str:
        return value.replace(placeholder, "*") if had_wildcard else value

    browser_host: str | None = None
    if "\\" in raw:
        # Re-parse with the browser's reading of a backslash, so the finding
        # can name both hosts rather than asserting that one of them is right.
        try:
            alt = urlsplit(text.replace("\\", "/"))
            alt_netloc = alt.netloc.rpartition("@")[2]
            alt_host = alt_netloc.partition(":")[0].strip("[]").lower()
            browser_host = restore(alt_host)
        except ValueError:  # pragma: no cover - defensive
            browser_host = None

    # Deduplicate while keeping declaration order, so output is stable.
    seen: dict[str, None] = {}
    for h in hazards:
        seen.setdefault(h, None)

    return RedirectURI(
        raw=raw,
        scheme=scheme,
        userinfo=restore(userinfo),
        host=restore(host),
        port=port,
        path=restore(path),
        query=restore(split.query),
        fragment=restore(split.fragment),
        hazards=tuple(seen),
        error=None,
        browser_host=browser_host,
    )


def exact_match(a: str, b: str) -> bool:
    """The comparison the specification requires: simple string equality."""
    return a == b


def equivalent(a: RedirectURI, b: RedirectURI) -> bool:
    """Whether two parsed URIs are spellings of the same URI."""
    return a.valid and b.valid and a.canonical == b.canonical


def is_shared_platform_host(host: str) -> str | None:
    """Return the matching platform suffix, or None."""
    h = host.lower().rstrip(".")
    for suffix in SHARED_PLATFORM_SUFFIXES:
        if h == suffix or h.endswith("." + suffix):
            return suffix
    return None


def host_in_domain(host: str, domain: str) -> bool:
    """True when ``host`` is ``domain`` or a subdomain of it."""
    h = host.lower().rstrip(".")
    d = domain.lower().rstrip(".").lstrip("*").lstrip(".")
    return bool(d) and (h == d or h.endswith("." + d))


def reflecting_path_segment(path: str) -> str | None:
    """Return the path segment that looks like a forwarder, or None."""
    for segment in path.lower().split("/"):
        base = segment.split(".")[0]
        if base in REFLECTING_PATH_SEGMENTS:
            return segment
    return None


def looseness_score(uri: RedirectURI) -> int:
    """A coarse ordering of how loose one registration is relative to another.

    Used only to name the weakest member of a mixed-strictness registration
    set; the number has no meaning outside that comparison.
    """
    if not uri.valid:
        return 0
    score = 0
    if uri.has_wildcard:
        score += 8
    if uri.path_is_open:
        score += 4
    if uri.scheme == "http" and not uri.is_loopback:
        score += 4
    if uri.fragment:
        score += 2
    if uri.userinfo:
        score += 2
    if reflecting_path_segment(uri.path):
        score += 2
    if is_shared_platform_host(uri.host):
        score += 3
    score += len([h for h in uri.hazards if h != "credential-shaped-query"])
    return score
