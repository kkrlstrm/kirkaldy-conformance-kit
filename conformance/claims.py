"""The claims ledger: what each product's own documentation states about each property.

One JSON file per target in `claims/`. Every entry has a basis, because "the vendor claims X"
is itself a statement that needs a receipt:

- `vendor-docs` — a verbatim quote from the vendor's own documentation or repository, with URL.
- `not-found`   — no statement found; `source` lists the pages checked. Most of the field's
                  guarantees are in this state, which is the point of measuring them.
- `secondary`   — from our own write-up of the vendor's docs, not yet traced to a vendor
                  sentence. Never shown as a vendor claim.
- `author`      — the kit author's own project (the reference implementation). Labelled so
                  nobody mistakes it for a third party's statement.

Adapters read their claims from here, so a result and the matrix quote the same thing.

``KIRKALDY_CLAIMS_DIR`` names a directory of ledgers read before the kit's own `claims/`
(`ledgers`): a repository that keeps its adapters outside the kit keeps their ledgers beside them,
and the kit's example ledgers still resolve. A ledger in the first directory that has one is
the target's; the others are not read.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

CLAIMS_ENV = "KIRKALDY_CLAIMS_DIR"
KIT_LEDGER = Path(__file__).resolve().parent.parent / "claims"
LEDGER = (Path(os.environ[CLAIMS_ENV]).expanduser().resolve() if os.environ.get(CLAIMS_ENV)
          else KIT_LEDGER)
"""The first ledger directory: ``$KIRKALDY_CLAIMS_DIR``, or the kit's own `claims/`."""
BASES = ("vendor-docs", "not-found", "secondary", "author")


def ledgers() -> List[Path]:
    """The ledger directories in the order they are read: `LEDGER`, then the kit's own."""
    return [LEDGER] + ([KIT_LEDGER] if LEDGER != KIT_LEDGER else [])


def ledger_path(target: str) -> Path:
    """`target`'s ledger file: the first directory's that exists, else where `LEDGER` would hold
    it (missing)."""
    for d in ledgers():
        if (d / f"{target}.json").exists():
            return d / f"{target}.json"
    return LEDGER / f"{target}.json"


def load(target: str) -> Dict[str, Dict[str, Any]]:
    path = ledger_path(target)
    if not path.exists():
        return {}
    doc = json.loads(path.read_text())
    out = {}
    for e in doc.get("claims", []):
        if e.get("basis") not in BASES:
            raise ValueError(f"{path.name}: {e.get('property')} has unknown basis {e.get('basis')!r}")
        out[e["property"]] = e
    return out


def as_text(entry: Dict[str, Any]) -> str:
    basis = entry["basis"]
    if basis == "not-found":
        return f"not stated (checked {entry.get('checked', '?')}: {entry.get('source', '')})"
    label = {"vendor-docs": "vendor docs", "secondary": "our write-up, not traced to a vendor "
             "sentence", "author": "author's own project"}[basis]
    return f"\"{entry.get('quote', '')}\" ({label}: {entry.get('source', '')})"


def vendor_claims(target: str) -> Dict[str, str]:
    """Property id -> display text, for adapters."""
    return {pid: as_text(e) for pid, e in load(target).items()}


def not_applicable(target: str) -> Dict[str, str]:
    """Property id -> one line on why the product has no such mechanism. Kept in the ledger
    beside the claims, under `not_applicable`, so the reason a property was not run is stated
    in the same place as what the vendor says about the ones that were."""
    path = ledger_path(target)
    if not path.exists():
        return {}
    return dict(json.loads(path.read_text()).get("not_applicable", {}))


def role(target: str) -> str:
    """"vendor" (default) or "reference": the kit author's own code, shown apart from the
    vendor comparison so nobody reads the author's library passing as an independent result."""
    path = ledger_path(target)
    return json.loads(path.read_text()).get("role", "vendor") if path.exists() else "vendor"
