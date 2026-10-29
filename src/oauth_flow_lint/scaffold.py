"""The commented scaffold emitted by ``oauth-flow-lint init``.

The scaffold is a real file in the package rather than a string in the source,
so that the test suite can lint it and the CI workflow can assert that the
configuration the tool hands a new user reports nothing. A scaffold that does
not lint clean teaches the wrong defaults on the first run.
"""

from __future__ import annotations

from pathlib import Path

SCAFFOLD_PATH = Path(__file__).with_name("scaffold.toml")


def scaffold_text() -> str:
    return SCAFFOLD_PATH.read_text(encoding="utf-8")
