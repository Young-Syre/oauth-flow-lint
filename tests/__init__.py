"""Test package.

``src`` is prepended to ``sys.path`` here so that

    python -m unittest discover -s tests -t . -v

works in a checkout with nothing installed. CI additionally installs the
package and exercises the console script, so both paths are covered.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
