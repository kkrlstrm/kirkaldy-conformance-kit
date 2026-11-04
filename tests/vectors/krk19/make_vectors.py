"""Writes the KRK-19 test vectors in this directory. Run from the repo root:

    python tests/vectors/krk19/make_vectors.py

Grants, status snapshots, notices and one bitstring snapshot, signed with the RFC 8032 test keys
(Ed25519 is deterministic, so the tokens are byte-stable). Every claim is written out here by
hand, not built by `conformance.status`, and every expected answer (verify reason, the state a
correct B derives for a chain, which bits are set) is written by hand, so a bug in the module
cannot make its own vector agree with it.
"""
from __future__ import annotations

import base64
import json
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from conformance import receipts as r  # noqa: E402

A_KID = "a-status-2026-11"
A = r.Keypair.from_seed(A_KID, bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
OTHER_AS_A = r.Keypair.from_seed(A_KID, bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
A_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
AGENT_PUBLIC = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
SOURCE = "http://127.0.0.1:9/status/list"

P = "gr-00000000000000a1"     # a parent grant
W = "gr-00000000000000b2"     # delegated from P
L = "gr-00000000000000c3"     # the sibling, issued directly
U = "gr-00000000000000d4"     # delegated from P, issued after the snapshot
Q = "gr-00000000000000e5"     # issued in the snapshot's own millisecond
X = "gr-00000000000000f6"     # issued after the snapshot expired

# The snapshot every chain case is read against: issued 10:00:00.250, expires 10:00:30.250.
SNAP_AT, SNAP_EXP = "2026-11-02T10:00:00.250Z", "2026-11-02T10:00:30.250Z"


def grant(gid, *, parent=None, principal="alice@a.example", ceiling=None, index=0,
          issued_at="2026-11-02T09:59:00.000Z", **patch):
    c = {"schema": "kirkaldy.grant/0.1", "grant_id": gid, "issuer": "did:web:a.example",
         "audience": "did:web:b.example", "subject": "agent-7",
         "agent_key": {"kid": "agent-7-k1", "public_key": AGENT_PUBLIC},
         "principal": principal, "operation": "crm.record.push",
         "ceiling": ceiling or {"max_amount": 99999}, "parent": parent,
         "issued_at": issued_at, "not_before": "2026-11-02T09:00:00Z", "not_after": "2026-11-02T21:00:00Z",
         "status": {"source": SOURCE, "index": index}}
    c.update(patch)
    return c


def snapshot(entries, standing=None, *, version=7, **patch):
    c = {"schema": "kirkaldy.status/0.1", "issuer": "did:web:a.example", "source": SOURCE,
         "version": version, "issued_at": SNAP_AT, "ttl_s": 30,
         "expires_at": SNAP_EXP, "entries": entries,
         "standing": standing or {"alice@a.example": "standing", "bob@a.example": "standing"}}
    c.update(patch)
    return c


def jws(claims, typ, key=A, header=None, unsigned=False):
    payload = r.canonical_json(claims)
    if unsigned:
        return f"{r._b64e(r.canonical_json({'alg': 'none', 'typ': typ}))}.{r._b64e(payload)}."
    return r.sign_payload(payload, key, header or {"alg": "EdDSA", "kid": key.kid, "typ": typ})


V, RV, N = ({"state": "valid", "ceiling": None}, {"state": "revoked", "ceiling": None},
            {"state": "narrowed", "ceiling": {"max_amount": 5000}})
GP, GW, GL = (grant(P, index=0),
              grant(W, parent=P, ceiling={"max_amount": 20000}, index=1,
                    issued_at="2026-11-02T09:59:10.000Z"),
              grant(L, principal="bob@a.example", index=2, issued_at="2026-11-02T09:59:20.000Z"))
# Issued after the snapshot (10:00:05.000 > 10:00:00.250, and before 10:00:30.250).
GU = grant(U, parent=P, ceiling={"max_amount": 30000}, index=3,
           issued_at="2026-11-02T10:00:05.000Z")
# Issued at the snapshot's own instant, 10:00:00.250.
GQ = grant(Q, principal="bob@a.example", index=4, issued_at="2026-11-02T10:00:00.250Z")
# Issued after the snapshot expired (10:00:31.000 > 10:00:30.250).
GX = grant(X, principal="bob@a.example", index=5, issued_at="2026-11-02T10:00:31.000Z")
ALL_VALID = snapshot({P: V, W: V, L: V})

GRANTS = {
    "parent": (jws(GP, "krk-grant+jws"), True, None),
    "delegated": (jws(GW, "krk-grant+jws"), True, None),
    "unsigned": (jws(GP, "krk-grant+jws", unsigned=True), False, "unsigned"),
    "other-key-under-a-kid": (jws(GP, "krk-grant+jws", key=OTHER_AS_A), False, "bad-signature"),
    "snapshot-typ": (jws(GP, "krk-status+jws"), False, "malformed"),
    "window-inverted": (jws(grant(P, not_after="2026-11-02T08:59:59Z"), "krk-grant+jws"), False,
                        "malformed"),
    "unknown-ceiling-member": (jws(grant(P, ceiling={"max_amount": 1, "region": "eu"}),
                                   "krk-grant+jws"), False, "malformed"),
    "seed-shaped-id": (jws(grant("gr-7"), "krk-grant+jws"), False, "malformed"),
    "issued-after-the-snapshot": (jws(GU, "krk-grant+jws"), True, None),
    "issued-at-whole-seconds": (jws(grant(P, issued_at="2026-11-02T09:59:00Z"),
                                    "krk-grant+jws"), False, "malformed"),
    "no-issued-at": (jws({k: v for k, v in GP.items() if k != "issued_at"}, "krk-grant+jws"),
                     False, "malformed"),
}

SNAPSHOTS = {
    "all-valid": (jws(ALL_VALID, "krk-status+jws"), True, None),
    "w-revoked": (jws(snapshot({P: V, W: RV, L: V}, version=8), "krk-status+jws"), True, None),
    "narrowed-without-ceiling": (jws(snapshot({P: V, W: {"state": "narrowed", "ceiling": None},
                                               L: V}), "krk-status+jws"), False, "malformed"),
    "grant-typ": (jws(ALL_VALID, "krk-grant+jws"), False, "malformed"),
    "whole-second-time": (jws(snapshot({P: V}, issued_at="2026-11-02T10:00:00Z"),
                              "krk-status+jws"), False, "malformed"),
    "version-zero": (jws(snapshot({P: V}, version=0), "krk-status+jws"), False, "malformed"),
}

NOTICES = {
    "w-revoked": (jws({"schema": "kirkaldy.status-notice/0.1", "issuer": "did:web:a.example",
                       "source": SOURCE, "version": 8, "issued_at": "2026-11-02T10:00:01.000Z",
                       "entries": {W: RV}, "standing": {}}, "krk-notice+jws"), True, None),
    "unknown-state": (jws({"schema": "kirkaldy.status-notice/0.1", "issuer": "did:web:a.example",
                           "source": SOURCE, "version": 8,
                           "issued_at": "2026-11-02T10:00:01.000Z",
                           "entries": {W: {"state": "paused", "ceiling": None}}, "standing": {}},
                          "krk-notice+jws"), False, "malformed"),
}

# chain -> snapshot entries/standing (and its issued_at / expires_at) -> what a correct B
# derives, by hand. Unless a case says otherwise the snapshot is issued at 10:00:00.250 and
# expires at 10:00:30.250; P, W and L were issued before it, U after it. A
# snapshot states the standing of every principal whose grant it lists: P, W and
# U rest on alice, L, Q and X on bob.
T0 = {"issued_at": SNAP_AT, "expires_at": SNAP_EXP}
BOTH = {"alice@a.example": "standing", "bob@a.example": "standing"}
ALICE_OUT = {"alice@a.example": "withdrawn", "bob@a.example": "standing"}
CHAINS = {
    "all-valid": {"chain": [W, P], "entries": {P: V, W: V, L: V}, "standing": BOTH, **T0,
                  "state": "valid", "ceiling": {"max_amount": 20000}},
    "parent-revoked": {"chain": [W, P], "entries": {P: RV, W: V, L: V}, "standing": BOTH, **T0,
                       "state": "revoked", "ceiling": None},
    # P was issued at 09:59:00, before the snapshot, and is absent: the source does not list it.
    "parent-missing": {"chain": [W, P], "entries": {W: V, L: V}, "standing": BOTH, **T0,
                       "state": "unknown", "ceiling": None},
    "narrowed": {"chain": [W, P], "entries": {P: V, W: N, L: V}, "standing": BOTH, **T0,
                 "state": "narrowed", "ceiling": {"max_amount": 5000}},
    "standing-withdrawn": {"chain": [W, P], "entries": {P: V, W: V, L: V},
                           "standing": ALICE_OUT, **T0,
                           "state": "standing-withdrawn", "ceiling": None},
    "sibling-other-principal": {"chain": [L], "entries": {P: V, W: V, L: V},
                                "standing": ALICE_OUT, **T0,
                                "state": "valid", "ceiling": {"max_amount": 99999}},
    # KRK-M46. U (10:00:05.000) was issued after the snapshot (10:00:00.250), so its
    # absence reads not yet listed: in force until B's next fetch, under P's entry.
    "not-yet-listed": {"chain": [U, P], "entries": {P: V, W: V, L: V}, "standing": BOTH, **T0,
                       "state": "not-yet-listed", "ceiling": {"max_amount": 30000}},
    "not-yet-listed-parent-revoked": {"chain": [U, P], "entries": {P: RV, W: V, L: V},
                                      "standing": BOTH, **T0,
                                      "state": "revoked", "ceiling": None},
    "not-yet-listed-parent-narrowed": {"chain": [U, P],
                                       "entries": {P: N, W: V, L: V}, "standing": BOTH, **T0,
                                       "state": "not-yet-listed",
                                       "ceiling": {"max_amount": 5000}},
    "not-yet-listed-standing-withdrawn": {"chain": [U, P], "entries": {P: V, W: V, L: V},
                                          "standing": ALICE_OUT, **T0,
                                          "state": "standing-withdrawn", "ceiling": None},
    # The same U against a snapshot A signed after it (10:00:06.000): absent there, it is
    # unknown.
    "absent-from-a-later-snapshot": {"chain": [U, P], "entries": {P: V, W: V, L: V},
                                     "standing": BOTH, "issued_at": "2026-11-02T10:00:06.000Z",
                                     "expires_at": "2026-11-02T10:00:36.000Z",
                                     "state": "unknown", "ceiling": None},
    # L, issued at 09:59:20 and absent from the 10:00:00.250 snapshot: unknown.
    "sibling-absent-from-a-later-snapshot": {"chain": [L], "entries": {P: V, W: V},
                                             "standing": BOTH, **T0,
                                             "state": "unknown", "ceiling": None},
    # Q was issued at 10:00:00.250, the snapshot's own instant. A correct A lists a grant in
    # every snapshot it signs after issuing it, so this snapshot was signed first: not yet listed.
    "issued-in-the-same-instant": {"chain": [Q], "entries": {P: V, W: V, L: V},
                                   "standing": BOTH, **T0, "state": "not-yet-listed",
                                   "ceiling": {"max_amount": 99999}},
    # X was issued at 10:00:31.000, after the snapshot expired at 10:00:30.250. Still not yet
    # listed: whether B may use an expired snapshot is B's age limit, not the absence rule.
    "issued-after-the-snapshot-expired": {"chain": [X], "entries": {P: V, W: V, L: V},
                                          "standing": BOTH, **T0, "state": "not-yet-listed",
                                          "ceiling": {"max_amount": 99999}},
    # A snapshot with no times: absence cannot be read as not yet listed.
    "no-snapshot-times": {"chain": [U, P], "entries": {P: V, W: V, L: V}, "standing": BOTH,
                          "issued_at": None, "expires_at": None,
                          "state": "unknown", "ceiling": None},
    # KRK-M47. W and P are listed and rest on alice, whom the snapshot does not mention:
    # the source has not said alice still has standing, so the chain is unknown and refused.
    "principal-not-stated": {"chain": [W, P], "entries": {P: V, W: V, L: V},
                             "standing": {"bob@a.example": "standing"}, **T0,
                             "state": "unknown", "ceiling": None},
    # The same with no standing section at all, for the sibling L (bob).
    "sibling-principal-not-stated": {"chain": [L], "entries": {P: V, W: V, L: V},
                                     "standing": {}, **T0, "state": "unknown", "ceiling": None},
    # Only the listed parent's principal must be stated: U is not yet listed and rests on
    # alice, P is listed and rests on alice too, so alice missing makes the chain unknown.
    "not-yet-listed-parent-principal-not-stated": {"chain": [U, P],
                                                   "entries": {P: V, W: V, L: V},
                                                   "standing": {"bob@a.example": "standing"},
                                                   **T0, "state": "unknown", "ceiling": None},
    # Q (bob) was issued in the snapshot's own instant and is not yet listed; a snapshot signed
    # before Q existed need not name Q's principal. Not yet listed, as under the earlier rule.
    "not-yet-listed-principal-not-stated": {"chain": [Q], "entries": {P: V, W: V, L: V},
                                            "standing": {"alice@a.example": "standing"}, **T0,
                                            "state": "not-yet-listed",
                                            "ceiling": {"max_amount": 99999}},
}

# indices 0..2; bit for index 1 (W) set: 0b0100_0000 = 0x40, written by hand.
BITS = base64.urlsafe_b64encode(zlib.compress(bytes([0x40]), 9)).rstrip(b"=").decode("ascii")
BITSTRING = {"schema": "kirkaldy.status-bitstring/0.1", "issuer": "did:web:a.example",
             "source": SOURCE, "version": 8, "issued_at": "2026-11-02T10:00:00.250Z",
             "ttl_s": 30, "expires_at": "2026-11-02T10:00:30.250Z", "purpose": "revocation",
             "size": 8, "encoded_list": BITS}


def main() -> None:
    doc = {
        "pinned": {A_KID: A_PUBLIC},
        "grant_claims": {"P": GP, "W": GW, "L": GL, "U": GU, "Q": GQ, "X": GX},
        "grants": {k: {"token": t, "ok": ok, "reason": why} for k, (t, ok, why) in GRANTS.items()},
        "snapshots": {k: {"token": t, "ok": ok, "reason": why}
                      for k, (t, ok, why) in SNAPSHOTS.items()},
        "notices": {k: {"token": t, "ok": ok, "reason": why}
                    for k, (t, ok, why) in NOTICES.items()},
        "chains": CHAINS,
        "bitstring": {"token": jws(BITSTRING, "krk-status-bitstring+jws"), "claims": BITSTRING,
                      "set": [1], "clear": [0, 2, 3, 4, 5, 6, 7]},
    }
    assert A.public_bytes().hex() == A_PUBLIC
    (HERE / "vectors.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                                       encoding="utf-8")


if __name__ == "__main__":
    main()
