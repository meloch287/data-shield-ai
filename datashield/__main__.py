"""Точка входа для `python3 -m datashield`."""
from __future__ import annotations

import sys

from datashield.cli import main

if __name__ == "__main__":
    sys.exit(main())
