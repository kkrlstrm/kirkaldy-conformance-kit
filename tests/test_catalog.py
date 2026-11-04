"""The failure-mode catalog keeps its own promises: every KRK-M entry is numbered in order (with
gaps only where a design not yet built names the number), cites at least one test, and every
cited test exists. An unpinned entry is an assertion in a project whose argument is that
assertions need receipts."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "docs" / "FAILURE-MODES.md").read_text(encoding="utf-8")
SECTIONS = re.findall(r"^## KRK-M(\d+) — (.+?)\n(.*?)(?=^## |\Z)", DOC, re.M | re.S)


def _tests():
    return {p.name: set(re.findall(r"^def (test_\w+)", p.read_text(encoding="utf-8"), re.M))
            for p in (ROOT / "tests").glob("test_*.py")}


def test_the_catalog_parses():
    assert len(SECTIONS) >= 10


RESERVED = {49, 149} | {135, 136, 137, 138, 144, 146}
"""Numbers the catalog may skip. 49 and 149: no design has named them. 135 to 138, 144 and 146:
the B-issuer design's modes for P19B, P20B and P16B, pinned when those are built."""


def test_ids_are_contiguous():
    ids = [int(n) for n, _, _ in SECTIONS]
    assert ids == sorted(set(ids)), ids
    missing = set(range(1, max(ids) + 1)) - set(ids)
    assert missing <= RESERVED, sorted(missing - RESERVED)


def test_every_entry_cites_a_test_that_exists():
    known = _tests()
    for n, title, body in SECTIONS:
        cites = re.findall(r"`(test_\w+\.py)::(test_\w+)`", body)
        assert cites, f"KRK-M{n} {title} cites no test"
        for f, t in cites:
            assert t in known.get(f, set()), f"KRK-M{n} cites {f}::{t}, which does not exist"


def test_the_summary_table_lists_every_mode_once():
    table = re.findall(r"^\| `KRK-M(\d+)` \|", DOC, re.M)
    assert sorted(map(int, table)) == [int(n) for n, _, _ in SECTIONS]
