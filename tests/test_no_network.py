"""The package must not be able to make a network request.

This is the claim the README makes most prominently, so it is the one that
needs a test rather than a sentence. The check is on the abstract syntax tree
of every module in the package, not on a text search, so it cannot be defeated
by formatting and does not trip over the word appearing in prose.

The forbidden names are constructed from fragments where they appear as string
literals in this file, so that the second, cruder source-text assertion below
does not match its own test.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

import oauth_flow_lint

PACKAGE_ROOT = Path(oauth_flow_lint.__file__).resolve().parent

#: Top-level modules that can open a socket, directly or as a client.
FORBIDDEN_ROOTS = frozenset(
    {
        "so" + "cket",
        "ssl",
        "ftplib",
        "smtplib",
        "poplib",
        "imaplib",
        "telnetlib",
        "asyncio",
        "selectors",
        "socketserver",
        "xmlrpc",
        "webbrowser",
        "subprocess",
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
    }
)

#: Submodules of otherwise-permitted packages that perform requests.
FORBIDDEN_SUBMODULES = frozenset(
    {
        "urllib." + "request",
        "urllib." + "error",
        "http." + "client",
        "http." + "server",
        "wsgiref." + "simple_server",
    }
)

#: ``urllib.parse`` is the one member of urllib this package uses, and it only
#: splits strings.
PERMITTED_URLLIB = frozenset({"urllib.parse"})


def package_modules() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # a relative import stays inside the package
                continue
            if node.module:
                names.add(node.module)
                for alias in node.names:
                    names.add(f"{node.module}.{alias.name}")
    return names


class NoNetworkCapability(unittest.TestCase):
    def test_there_is_something_to_check(self):
        modules = package_modules()
        self.assertGreater(len(modules), 10)
        self.assertIn("cli.py", {m.name for m in modules})

    def test_no_module_imports_a_networking_package(self):
        for path in package_modules():
            for name in imported_names(path):
                root = name.split(".")[0]
                self.assertNotIn(
                    root,
                    FORBIDDEN_ROOTS,
                    f"{path.name} imports {name}",
                )

    def test_no_module_imports_a_networking_submodule(self):
        for path in package_modules():
            for name in imported_names(path):
                self.assertNotIn(name, FORBIDDEN_SUBMODULES, f"{path.name} imports {name}")

    def test_the_only_urllib_member_used_is_the_parser(self):
        for path in package_modules():
            for name in imported_names(path):
                if not name.startswith("urllib"):
                    continue
                self.assertIn(
                    ".".join(name.split(".")[:2]),
                    PERMITTED_URLLIB,
                    f"{path.name} imports {name}",
                )

    def test_no_module_calls_a_request_function_by_name(self):
        """A crude second check, in case something is imported dynamically."""
        needles = ("url" + "open(", "so" + "cket.", "HTTPConnection", "__import__", "importlib")
        for path in package_modules():
            source = path.read_text(encoding="utf-8")
            for needle in needles:
                self.assertNotIn(needle, source, f"{path.name} contains {needle!r}")

    def test_loading_a_configuration_that_names_a_url_raises_rather_than_fetching(self):
        from oauth_flow_lint.loader import ConfigError, load_text

        text = """
[client]
client_id = "c"
redirect_uris = ["https://app.example/cb"]

[provider]
name = "p"
issuer = "https://idp.example"
redirect_uri_matching = "exact"
discovery_document = "https://idp.example/.well-known/openid-configuration"
"""
        with self.assertRaises(ConfigError) as ctx:
            load_text(text)
        self.assertIn("never performs network requests", str(ctx.exception))

    def test_the_declared_dependency_list_is_empty(self):
        pyproject = PACKAGE_ROOT.parent.parent / "pyproject.toml"
        import tomllib

        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["dependencies"], [])

    def test_the_minimum_python_matches_the_tomllib_requirement(self):
        pyproject = PACKAGE_ROOT.parent.parent / "pyproject.toml"
        import tomllib

        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["requires-python"], ">=3.11")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
