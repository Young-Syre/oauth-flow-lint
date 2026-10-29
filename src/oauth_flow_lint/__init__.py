"""oauth-flow-lint: an offline linter for OAuth 2.0 and OIDC client configurations.

The package contains no networking code. Input is a local TOML description of a
client and its providers, optionally with a provider metadata document saved to
a local JSON file and URLs captured from a real flow.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
