"""The claims ledger: every entry says where its statement comes from, and a statement that is
not the vendor's own is never displayed as if it were."""
import json
from pathlib import Path

from conformance import claims

LEDGER = Path(__file__).resolve().parent.parent / "claims"
FILES = sorted(LEDGER.glob("*.json"))


def test_there_is_a_ledger():
    assert FILES


def test_every_entry_has_a_known_basis_and_a_source():
    for f in FILES:
        for e in json.loads(f.read_text())["claims"]:
            assert e["basis"] in claims.BASES, (f.name, e)
            assert e.get("source"), (f.name, e["property"], "no source")
            assert e.get("checked"), (f.name, e["property"], "no date checked")
            if e["basis"] in ("vendor-docs", "author", "secondary"):
                assert e.get("quote"), (f.name, e["property"], "a quoted basis needs a quote")
            if e["basis"] == "vendor-docs":
                assert e["source"].startswith("http"), (f.name, e["property"], "vendor quote needs a URL")


def test_a_secondary_statement_is_never_shown_as_the_vendors():
    text = claims.as_text({"basis": "secondary", "quote": "x", "source": "write-up"})
    assert "not traced to a vendor" in text


def test_reference_targets_are_marked():
    roles = {f.stem: json.loads(f.read_text()).get("role", "vendor") for f in FILES}
    assert roles.get("toys") == "reference"
    assert claims.role("toys") == "reference" and claims.role("no-such-target") == "vendor"


def test_not_applicable_reasons_are_one_line_and_not_claimed():
    """A property marked n/a in the ledger has a one-line reason, and the same file does not also
    quote the vendor about it as if it had been measured."""
    for f in FILES:
        doc = json.loads(f.read_text())
        na = doc.get("not_applicable", {})
        claimed = {e["property"] for e in doc["claims"]}
        for pid, why in na.items():
            assert why.strip() and "\n" not in why, (f.name, pid)
            assert pid not in claimed, (f.name, pid, "both n/a and claimed")
