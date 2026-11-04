"""KRK-19 formats (`conformance/status.py`): grants, status snapshots, notices and the bitstring
profile read as the vectors say, and a correct B's derivation for a grant chain matches the
hand-written answers."""
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import receipts, status  # noqa: E402

HERE = Path(__file__).resolve().parent / "vectors" / "krk19"
VEC = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))
PINNED = {k: bytes.fromhex(v) for k, v in VEC["pinned"].items()}
TYP = {"grants": status.GRANT_TYP, "snapshots": status.STATUS_TYP,
       "notices": status.NOTICE_TYP}


@pytest.mark.parametrize("group,name", [(g, n) for g in TYP for n in sorted(VEC[g])])
def test_verify_matches_the_vectors(group, name):
    v = VEC[group][name]
    got = status.verify(v["token"], PINNED, TYP[group])
    assert (got.ok, got.reason) == (v["ok"], v["reason"]), got.detail


def test_a_token_is_read_only_as_the_type_it_names():
    tok = VEC["snapshots"]["all-valid"]["token"]
    assert status.typ_of(tok) == status.STATUS_TYP
    assert status.verify(tok, PINNED, status.GRANT_TYP).reason == "malformed"


@pytest.mark.parametrize("name", sorted(VEC["chains"]))
def test_chain_state_matches_the_hand_written_answers(name):
    c = VEC["chains"][name]
    grants = {g["grant_id"]: g for g in VEC["grant_claims"].values()}
    snap = {"entries": c["entries"], "standing": c["standing"]}
    snap.update({k: c[k] for k in ("issued_at", "expires_at") if c.get(k) is not None})
    got = status.chain_state(snap, [grants[g] for g in c["chain"]])
    assert (got["state"], got["ceiling"]) == (c["state"], c["ceiling"]), got["why"]
    assert (got["state"] in status.IN_FORCE) == (c["state"] in ("valid", "narrowed",
                                                                "not-yet-listed"))
    assert bool(got["not_yet_listed"]) == (c["state"] == "not-yet-listed")


def test_absence_reads_by_issue_time():
    """A grant absent from a snapshot A signed before the grant existed, or in its own instant,
    is not yet listed (in force until B's next fetch), even past the snapshot's expiry (that is
    B's age limit); absent from one A signed after its issue it is unknown and refused. Every case is a vector; this reads them by
    name so a vector that disappears fails here."""
    want = {"not-yet-listed": "not-yet-listed", "absent-from-a-later-snapshot": "unknown",
            "sibling-absent-from-a-later-snapshot": "unknown",
            "issued-in-the-same-instant": "not-yet-listed",
            "issued-after-the-snapshot-expired": "not-yet-listed",
            "no-snapshot-times": "unknown",
            "not-yet-listed-parent-revoked": "revoked",
            "not-yet-listed-standing-withdrawn": "standing-withdrawn",
            "not-yet-listed-parent-narrowed": "not-yet-listed"}
    assert {k: VEC["chains"][k]["state"] for k in want} == want
    g = VEC["grant_claims"]
    snap = {"issued_at": "2026-11-02T10:00:00.250Z"}
    assert status.absent_state(snap, g["U"])[0] == "not-yet-listed"
    assert status.absent_state(snap, g["L"])[0] == "unknown"
    assert status.absent_state(snap, g["Q"])[0] == "not-yet-listed"
    assert status.absent_state(snap, g["X"])[0] == "not-yet-listed"
    assert status.absent_state({}, g["U"])[0] == "unknown"
    assert status.absent_state(snap, {k: v for k, v in g["U"].items() if k != "issued_at"})[
        0] == "unknown"


def test_a_principal_a_listing_snapshot_leaves_out_reads_unknown():
    """A snapshot that lists a grant states its principal's standing. A principal it leaves out
    reads unknown (refused), with or without a standing section; a grant not yet listed is not
    covered, but a listed parent's principal is. Every case is a vector, read here by name, and
    every chain vector states the standing of each principal whose grant it lists."""
    want = {"principal-not-stated": "unknown", "sibling-principal-not-stated": "unknown",
            "not-yet-listed-parent-principal-not-stated": "unknown",
            "not-yet-listed-principal-not-stated": "not-yet-listed"}
    assert {k: VEC["chains"][k]["state"] for k in want} == want
    grants = {g["grant_id"]: g for g in VEC["grant_claims"].values()}
    for name, c in VEC["chains"].items():
        if name in want:
            continue
        listed = [grants[g] for g in c["chain"] if g in c["entries"]]
        assert all(g["principal"] in c["standing"] for g in listed), name
    snap = {"issued_at": "2026-11-02T10:00:00.250Z", "entries": {
        grants[g]["grant_id"]: {"state": "valid", "ceiling": None} for g in grants},
        "standing": {"bob@a.example": "standing"}}
    w = [g for g in grants.values() if g["principal"] == "alice@a.example"
         and g["grant_id"] in snap["entries"]][0]
    got = status.chain_state(snap, [w] + ([grants[w["parent"]]] if w["parent"] else []))
    assert got["state"] == "unknown" and "does not state the standing" in got["why"]
    snap["standing"]["alice@a.example"] = "standing"
    assert status.chain_state(snap, [w] + ([grants[w["parent"]]] if w["parent"] else []))[
        "state"] == "valid"


def test_the_bitstring_vector_sets_exactly_the_bits_written_by_hand():
    b = VEC["bitstring"]
    v = status.verify(b["token"], PINNED, status.BITSTRING_TYP)
    assert v.ok, v.detail
    for i in b["set"]:
        assert status.bit(v.claims["encoded_list"], i) is True
    for i in b["clear"]:
        assert status.bit(v.claims["encoded_list"], i) is False


def test_a_bitstring_cannot_say_narrowed_suspended_or_standing():
    """KRK-M62: the binary profile drops these; `bitstring_gaps` names each one."""
    snap = status.snapshot_claims(
        issuer="did:web:a.example", source="s", version=3, issued_at=1_700_000_000.5, ttl_s=30,
        entries={"gr-00000000000000a1": {"state": "narrowed", "ceiling": {"max_amount": 5}},
                 "gr-00000000000000b2": {"state": "suspended"},
                 "gr-00000000000000c3": {"state": "revoked"}},
        standing={"alice": "withdrawn", "bob": "standing"})
    assert status.snapshot_problem(snap) is None
    gaps = status.bitstring_gaps(snap)
    assert {g.get("grant_id") or g.get("principal") for g in gaps} == {
        "gr-00000000000000a1", "gr-00000000000000b2", "alice"}
    bits = status.bitstring_claims(snap, {"gr-00000000000000a1": 0, "gr-00000000000000b2": 1,
                                          "gr-00000000000000c3": 2})
    assert status.bitstring_problem(bits) is None
    assert [status.bit(bits["encoded_list"], i) for i in range(3)] == [False, False, True]


def test_round_trip_through_the_builders():
    key = receipts.Keypair.generate("a-status-test")
    agent = receipts.Keypair.generate("agent-k")
    g = status.grant_claims(issuer="did:web:a.example", audience="did:web:b.example",
                            subject="agent-1", agent_kid=agent.kid,
                            agent_public=agent.public_bytes(), principal="alice",
                            operation="crm.record.push", ceiling={"max_amount": 10}, parent=None,
                            issued_at=1_700_003_000.125, not_before=1_700_000_000,
                            not_after=1_700_003_600, source="s", index=4)
    assert status.grant_problem(g) is None
    tok = status.sign(g, key, status.GRANT_TYP)
    got = status.verify(tok, {key.kid: key.public_bytes()}, status.GRANT_TYP)
    assert got.ok and got.claims == g
    assert g["grant_id"].startswith("gr-") and len(g["grant_id"]) == 19
    assert g["issued_at"] == "2023-11-14T23:03:20.125Z"   # 1_700_000_000 is 22:13:20Z


def test_times_keep_milliseconds_and_round_trip():
    s = status.utc_ms(1_700_000_000.257)
    assert s.endswith(".257Z")
    assert abs(status.epoch_of(s) - 1_700_000_000.257) < 1e-6
    assert status.epoch_of(status.utc_s(1_700_000_000.9)) == 1_700_000_000


def test_within_reads_the_ceiling():
    assert status.within({"amount": 10}, {"max_amount": 10}) is None
    assert status.within({"amount": 11}, {"max_amount": 10})
    assert status.within({"amount": 11}, None) is None
