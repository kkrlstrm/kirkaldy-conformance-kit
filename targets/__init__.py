"""Target adapters: one directory per product, each with an ``adapter.py``.

Adapters may also live outside this directory. ``KIRKALDY_TARGETS_PATH`` names further
directories laid out as this one is (``<root>/<name>/adapter.py``), separated by the platform's
path separator (``:`` on POSIX). Each is appended to this package's ``__path__``, so
``targets.<name>.adapter`` imports from whichever root holds ``<name>``, this directory first, and
``targets._common`` may be a helper module in an outside root. `roots()` lists the roots in that
order; `conformance.runner` lists and loads adapters from every root, and `conformance.versions`
hashes an outside adapter as every file in its own directory, exactly as one here.

A name in ``KIRKALDY_TARGETS_PATH`` that is not a directory stops the import: a mistyped root
would otherwise leave its adapters out with no error.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

PATH_ENV = "KIRKALDY_TARGETS_PATH"


def extra_roots(value: Optional[str] = None) -> List[Path]:
    """The directories `value` (default: ``$KIRKALDY_TARGETS_PATH``) names, resolved, in order,
    each once, without this package's own directory. Raises NotADirectoryError for a name that
    is not a directory."""
    raw = os.environ.get(PATH_ENV, "") if value is None else value
    own = Path(__file__).resolve().parent
    out: List[Path] = []
    for part in raw.split(os.pathsep):
        if not part.strip():
            continue
        p = Path(part.strip()).expanduser().resolve()
        if not p.is_dir():
            raise NotADirectoryError(f"{PATH_ENV} names {part!r}, which is not a directory")
        if p != own and p not in out:
            out.append(p)
    return out


def roots() -> List[Path]:
    """Every directory adapters are found in, this package's own first, in import order."""
    out: List[Path] = []
    for p in __path__:
        r = Path(p).resolve()
        if r not in out:
            out.append(r)
    return out


__path__ = list(__path__) + [str(p) for p in extra_roots()  # noqa: F821 - set by the import
                             if str(p) not in __path__]    # noqa: F821 - system
