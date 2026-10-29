"""Load a configuration from TOML, strictly.

Two decisions worth stating. First, a value that is not one of the permitted
enumerations is an error rather than a default, because silently defaulting
``redirect_uri_matching = "Exact"`` to ``unknown`` would turn a typo into a
finding that reads as a real weakness. Second, a key this version does not
recognise is reported: in a linter, an ignored key is a check that did not run,
and nobody notices a check that did not run.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

from . import model as m


class ConfigError(Exception):
    """A configuration this tool cannot interpret. Maps to exit code 2."""


def _expect(value: Any, kind: type | tuple[type, ...], where: str) -> Any:
    if not isinstance(value, kind):
        names = kind.__name__ if isinstance(kind, type) else "/".join(k.__name__ for k in kind)
        raise ConfigError(f"{where}: expected {names}, got {type(value).__name__}")
    return value


def _enum(value: Any, allowed: tuple[str, ...], where: str) -> str:
    text = _expect(value, str, where)
    if text not in allowed:
        raise ConfigError(f"{where}: {text!r} is not one of {', '.join(allowed)}")
    return text


def _str_list(value: Any, where: str) -> list[str]:
    items = _expect(value, list, where)
    out = []
    for i, item in enumerate(items):
        out.append(_expect(item, str, f"{where}[{i}]"))
    return out


def _int(value: Any, where: str) -> int:
    if isinstance(value, bool):
        raise ConfigError(f"{where}: expected integer, got boolean")
    return int(_expect(value, int, where))


class _Reader:
    """Pops known keys off a table so that whatever is left is unknown."""

    def __init__(self, table: dict[str, Any], where: str, unknown: list[str]) -> None:
        self.table = dict(table)
        self.where = where
        self.unknown = unknown

    def flag(self, key: str, default: bool) -> bool:
        if key not in self.table:
            return default
        return bool(_expect(self.table.pop(key), bool, f"{self.where}.{key}"))

    def text(self, key: str, default: str) -> str:
        if key not in self.table:
            return default
        return _expect(self.table.pop(key), str, f"{self.where}.{key}")

    def enum(self, key: str, allowed: tuple[str, ...], default: str) -> str:
        if key not in self.table:
            return default
        return _enum(self.table.pop(key), allowed, f"{self.where}.{key}")

    def strings(self, key: str, default: list[str] | None = None) -> list[str]:
        if key not in self.table:
            return list(default or [])
        return _str_list(self.table.pop(key), f"{self.where}.{key}")

    def number(self, key: str, default: int) -> int:
        if key not in self.table:
            return default
        return _int(self.table.pop(key), f"{self.where}.{key}")

    def table_at(self, key: str) -> dict[str, Any]:
        if key not in self.table:
            return {}
        return _expect(self.table.pop(key), dict, f"{self.where}.{key}")

    def finish(self) -> None:
        for key in self.table:
            self.unknown.append(f"{self.where}.{key}")


def _read_pkce(table: dict[str, Any], unknown: list[str]) -> m.PKCE:
    r = _Reader(table, "client.pkce", unknown)
    out = m.PKCE(
        used=r.flag("used", False),
        method=r.enum("method", m.PKCE_METHODS, "S256"),
    )
    r.finish()
    return out


def _read_state(table: dict[str, Any], unknown: list[str]) -> m.StateHandling:
    r = _Reader(table, "client.state", unknown)
    out = m.StateHandling(
        sent=r.flag("sent", False),
        bound_to_session=r.flag("bound_to_session", False),
        single_use=r.flag("single_use", True),
        entropy_bits=r.number("entropy_bits", 0),
        source=r.enum("source", m.STATE_SOURCES, "unknown"),
    )
    r.finish()
    return out


def _read_nonce(table: dict[str, Any], unknown: list[str]) -> m.NonceHandling:
    r = _Reader(table, "client.nonce", unknown)
    out = m.NonceHandling(
        sent=r.flag("sent", False),
        bound_to_session=r.flag("bound_to_session", False),
    )
    r.finish()
    return out


def _read_id_token_validation(table: dict[str, Any], unknown: list[str]) -> m.IdTokenValidation:
    r = _Reader(table, "client.id_token_validation", unknown)
    out = m.IdTokenValidation(
        signature_verified=r.flag("signature_verified", False),
        alg_pinned=r.flag("alg_pinned", False),
        accepted_algs=r.strings("accepted_algs"),
        accepts_none_alg=r.flag("accepts_none_alg", False),
        aud_checked=r.flag("aud_checked", False),
        iss_checked=r.flag("iss_checked", False),
        exp_checked=r.flag("exp_checked", False),
        azp_checked=r.flag("azp_checked", False),
        jwks_source=r.enum("jwks_source", m.JWKS_SOURCES, "unknown"),
        jwks_host_pinned=r.flag("jwks_host_pinned", False),
        expected_audiences=r.strings("expected_audiences"),
    )
    r.finish()
    return out


def _read_tokens(table: dict[str, Any], unknown: list[str]) -> m.TokenHandling:
    r = _Reader(table, "client.tokens", unknown)
    out = m.TokenHandling(
        access_token_transport=r.enum("access_token_transport", m.TRANSPORTS, "header"),
        refresh_token_issued=r.flag("refresh_token_issued", False),
        refresh_token_rotation=r.flag("refresh_token_rotation", False),
        access_token_lifetime_seconds=r.number("access_token_lifetime_seconds", 0),
        refresh_token_lifetime_seconds=r.number("refresh_token_lifetime_seconds", 0),
        browser_storage=r.enum("browser_storage", m.STORAGE_MODES, "none"),
    )
    r.finish()
    return out


def _read_client(table: dict[str, Any], unknown: list[str]) -> m.Client:
    r = _Reader(table, "client", unknown)
    pkce_table = r.table_at("pkce")
    state_table = r.table_at("state")
    nonce_table = r.table_at("nonce")
    idt_table = r.table_at("id_token_validation")
    tok_table = r.table_at("tokens")

    # The secret's value is never read. Its presence is the whole signal, so a
    # configuration may say `secret_present = true` instead of pasting one.
    secret_present = r.flag("secret_present", False)
    if "client_secret" in r.table:
        literal = _expect(r.table.pop("client_secret"), str, "client.client_secret")
        secret_present = secret_present or bool(literal.strip())

    client = m.Client(
        client_id=r.text("client_id", "unnamed-client"),
        client_type=r.enum("client_type", m.CLIENT_TYPES, "public"),
        application_type=r.enum("application_type", m.APPLICATION_TYPES, "web"),
        secret_present=secret_present,
        redirect_uris=r.strings("redirect_uris"),
        confirmed_open_redirect_uris=r.strings("confirmed_open_redirect_uris"),
        wildcard_dns_hosts=r.strings("wildcard_dns_hosts"),
        response_types=r.strings("response_types", ["code"]),
        response_mode=r.text("response_mode", "query"),
        grant_types=r.strings("grant_types", ["authorization_code"]),
        scopes=r.strings("scopes"),
        stated_purpose_scopes=r.strings("stated_purpose_scopes"),
        scope_change_reconsent=r.flag("scope_change_reconsent", True),
        pkce=_read_pkce(pkce_table, unknown),
        state=_read_state(state_table, unknown),
        nonce=_read_nonce(nonce_table, unknown),
        id_token_validation=_read_id_token_validation(idt_table, unknown),
        tokens=_read_tokens(tok_table, unknown),
    )
    r.finish()
    return client


def _read_provider(table: dict[str, Any], where: str, unknown: list[str], base: Path) -> m.Provider:
    r = _Reader(table, where, unknown)
    discovery_ref = r.text("discovery_document", "")
    provider = m.Provider(
        name=r.text("name", "unnamed-provider"),
        issuer=r.text("issuer", ""),
        redirect_uri_matching=r.enum("redirect_uri_matching", m.MATCHING_RULES, "unknown"),
        enforces_pkce=r.flag("enforces_pkce", False),
        pkce_methods=r.strings("pkce_methods"),
        returns_iss_parameter=r.flag("returns_iss_parameter", False),
        dynamic_client_registration=r.enum(
            "dynamic_client_registration", m.REGISTRATION_MODES, "closed"
        ),
        supports_request_uri=r.flag("supports_request_uri", False),
        grants_offline_access_without_request=r.flag("grants_offline_access_without_request", False),
        discovery_document=discovery_ref or None,
    )
    r.finish()
    if discovery_ref:
        provider.discovery, provider.discovery_path = _load_discovery(discovery_ref, where, base)
    return provider


def _load_discovery(ref: str, where: str, base: Path) -> tuple[dict[str, Any], str]:
    """Read a provider metadata document from a local file.

    A URL here is an error, not an invitation. This tool has no code that can
    make a request, so pointing it at a remote document would fail later and
    less clearly than it fails now.
    """
    if "://" in ref:
        raise ConfigError(
            f"{where}.discovery_document: {ref!r} looks like a URL. "
            "Give a path to a local JSON file; this tool never performs network requests. "
            "Save the document first, then point at the file."
        )
    path = Path(ref)
    if not path.is_absolute():
        path = base / path
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"{where}.discovery_document: cannot read {ref}: {exc.strerror}") from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{where}.discovery_document: {ref} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ConfigError(f"{where}.discovery_document: {ref} must contain a JSON object")
    return parsed, str(path)


def _read_capture(table: dict[str, Any], where: str, unknown: list[str], label: str) -> m.Capture:
    r = _Reader(table, where, unknown)
    out = m.Capture(
        label=r.text("label", label),
        authorization_request=r.text("authorization_request", ""),
        authorization_response=r.text("authorization_response", ""),
        resource_request=r.text("resource_request", ""),
    )
    r.finish()
    return out


def load_mapping(data: dict[str, Any], source_path: str = "<memory>", base: Path | None = None) -> m.Configuration:
    """Build a configuration from an already-parsed TOML mapping."""
    unknown: list[str] = []
    table = dict(data)
    base_dir = base if base is not None else Path(".")

    if "schema" in table:
        schema = _int(table.pop("schema"), "schema")
        if schema != 1:
            raise ConfigError(f"schema: version {schema} is not supported by this build (expected 1)")

    client_table = _expect(table.pop("client", {}), dict, "client")
    client = _read_client(client_table, unknown)

    providers: list[m.Provider] = []
    if "provider" in table:
        providers.append(_read_provider(_expect(table.pop("provider"), dict, "provider"), "provider", unknown, base_dir))
    if "providers" in table:
        entries = _expect(table.pop("providers"), list, "providers")
        for i, entry in enumerate(entries):
            where = f"providers[{i}]"
            providers.append(_read_provider(_expect(entry, dict, where), where, unknown, base_dir))
    if not providers:
        raise ConfigError("no provider configured: add a [provider] table or one or more [[providers]] tables")

    names = [p.name for p in providers]
    if len(set(names)) != len(names):
        raise ConfigError("provider names must be distinct so findings can name the provider at fault")

    captures: list[m.Capture] = []
    if "capture" in table:
        captures.append(_read_capture(_expect(table.pop("capture"), dict, "capture"), "capture", unknown, "capture"))
    if "captures" in table:
        entries = _expect(table.pop("captures"), list, "captures")
        for i, entry in enumerate(entries):
            where = f"captures[{i}]"
            captures.append(_read_capture(_expect(entry, dict, where), where, unknown, f"capture[{i}]"))

    for key in table:
        unknown.append(key)

    return m.Configuration(
        client=client,
        providers=providers,
        captures=captures,
        source_path=source_path,
        unknown_keys=unknown,
    )


def load_text(text: str, source_path: str = "<memory>", base: Path | None = None) -> m.Configuration:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source_path}: invalid TOML: {exc}") from exc
    return load_mapping(data, source_path=source_path, base=base)


def load_file(path: str | Path) -> m.Configuration:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {p}: {exc.strerror}") from exc
    return load_text(text, source_path=str(p), base=p.parent)
