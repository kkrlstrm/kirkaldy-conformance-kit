"""Writes the KRK-17 record test vectors in this directory. Run from the repo root:

    python tests/vectors/krk17/make_vectors.py

Entry digests are computed here with `hashlib` and `json` alone, not with `books.entry_digest`,
so a bug there cannot make its own vector agree with it. Every expected chain and checkpoint
finding below is written out by hand from the rules in `conformance/books.py`'s docstrings;
none is computed by `books.chain_breaks` or `books.checkpoint_covers`. Checkpoints are signed
with fixed keys (Ed25519 is deterministic), so the tokens are byte-stable.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from conformance import receipts as r  # noqa: E402

# RFC 8032 section 7.1 TEST 1 and TEST 2 secret keys, as in the KRK-16 vectors.
SEED_B = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SEED_OTHER = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
B_KID = "b-checkpoints-2026-11"
B = r.Keypair.from_seed(B_KID, bytes.fromhex(SEED_B))
OTHER_AS_B = r.Keypair.from_seed(B_KID, bytes.fromhex(SEED_OTHER))
OTHER = r.Keypair.from_seed("b-checkpoints-unpinned", bytes.fromhex(SEED_OTHER))

A_ID, B_ID = "did:web:a.example", "did:web:b.example"
CID = "case-17:9f2c41d07a3b6e55"
RD = "sha256:" + "1" * 64
ITEMS = "sha256:" + "2" * 64
EXP = "sha256:" + "3" * 64
TOKEN_SHA = "sha256:" + "4" * 64


def digest(entry):
    """Independent of conformance.books: the canonical JSON written out with json.dumps."""
    body = {k: v for k, v in entry.items() if k != "entry_digest"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def entry(side, seq, prev, kind, body, *, cid=CID, rd=RD, raw=None, at="2026-11-01T13:02:11Z"):
    party, peer = (A_ID, B_ID) if side == "A" else (B_ID, A_ID)
    return {"schema": "kirkaldy.record-entry/0.1", "side": side, "party": party, "peer": peer,
            "pair_seq": seq, "prev_digest": prev, "kind": kind, "correlation_id": cid,
            "request_digest": rd, "answers": None, "body": body, "raw_sha256": raw,
            "recorded_at": at}


def chain(side, specs):
    """Number and link a list of (kind, body) specs."""
    out, prev = [], None
    for n, (kind, body) in enumerate(specs, 1):
        e = entry(side, n, prev, kind, body)
        out.append(e)
        prev = digest(e)
    return out


def relink(entries):
    """Re-chain after an edit: every entry names the digest of the one before it."""
    out, prev = [], None
    for e in entries:
        e = dict(e, prev_digest=prev)
        out.append(e)
        prev = digest(e)
    return out


B_SPECS = [
    ("request-received", {"operation": "crm.record.push", "container": "people", "count": 4,
                          "items_digest": ITEMS, "expected_effect_digest": EXP}),
    ("effect-committed", {"created": 4, "updated": 0, "deleted": 0, "failed": 0,
                          "items_digest": ITEMS, "log_seq": 40177}),
    ("receipt-issued", {"receipt_id": "rcpt-0000000000000001", "token_sha256": TOKEN_SHA,
                        "verdict": "executed", "log_seq": 40177,
                        "outcome": {"created": 4, "updated": 0, "deleted": 0, "failed": 0}}),
    ("effect-committed", {"created": 0, "updated": 2, "deleted": 0, "failed": 0,
                          "items_digest": ITEMS, "log_seq": 40180}),
]
A_SPECS = [
    ("request-sent", {"operation": "crm.record.push", "container": "people", "count": 4,
                      "items_digest": ITEMS, "expected_effect_digest": EXP}),
    ("receipt-received", {"receipt_id": "rcpt-0000000000000001", "verdict": "executed"}),
]


def main():
    b = chain("B", B_SPECS)
    a = chain("A", A_SPECS)
    a[1]["raw_sha256"] = TOKEN_SHA
    a = relink(a)

    entries = {"entries": [dict(e, entry_digest=digest(e)) for e in a + b],
               "invalid": [
                   {"name": "entry-1-with-prev", "entry": dict(b[0], prev_digest=digest(b[1])),
                    "problem": "entry 1 names no previous entry"},
                   {"name": "unnumbered-with-prev", "entry": dict(b[1], pair_seq=None),
                    "problem": "an unnumbered entry cannot name a previous entry"},
                   {"name": "action-without-key", "entry": dict(b[0], request_digest=None),
                    "problem": "a request-received entry names its action (correlation_id "
                               "and request_digest)"},
                   {"name": "wrong-own-digest", "entry": dict(b[0], entry_digest=digest(b[1])),
                    "problem": "entry_digest is not the digest of the entry"},
                   {"name": "member-outside-format", "entry": dict(b[0], variant="honest"),
                    "problem": "members outside the format: variant"},
                   {"name": "void-without-target",
                    "entry": entry("B", 5, None, "void", {"reason": "aborted"}),
                    "problem": "a void entry names the digest of the entry it voids "
                               "(body.voids)"},
               ]}

    # ---------------------------------------------------------------- chains
    swapped = copy.deepcopy(b)
    swapped[1]["pair_seq"], swapped[2]["pair_seq"] = 3, 2      # numbers swapped, links kept
    duplicate = copy.deepcopy(b)
    extra = entry("B", 2, digest(b[0]), "effect-committed", dict(B_SPECS[1][1], log_seq=40178))
    duplicate.insert(2, extra)
    edited = copy.deepcopy(b)
    edited[1]["body"] = dict(edited[1]["body"], created=3)      # links not redone
    chains = {"cases": [
        {"name": "honest", "entries": b + a, "breaks": [], "findings": []},
        {"name": "gap", "entries": [b[0], b[2], b[3]],
         "breaks": [{"kind": "gap", "numbers": [2], "has_key": False}], "findings": []},
        # Entry 2 is now the old entry 3, which names the old entry 2 (no longer there): torn.
        # Entry 3 is the old entry 2, which names entry 1: renumbered (3 names 1).
        # Entry 4 names the old entry 3, which no longer exists under that digest: torn.
        {"name": "swapped-numbers", "entries": swapped,
         "breaks": [{"kind": "torn", "numbers": [2], "has_key": True},
                    {"kind": "renumbered", "numbers": [3, 1], "has_key": True},
                    {"kind": "torn", "numbers": [4], "has_key": True}], "findings": []},
        {"name": "number-used-twice", "entries": duplicate,
         "breaks": [{"kind": "renumbered", "numbers": [2], "has_key": False}],
         "findings": []},
        {"name": "edited-without-relinking", "entries": edited,
         "breaks": [{"kind": "torn", "numbers": [3], "has_key": True}], "findings": []},
        {"name": "unnumbered", "entries": [dict(e, pair_seq=None, prev_digest=None) for e in b],
         "breaks": [], "findings": [{"kind": "unnumbered", "side": "B"}]},
        {"name": "re-chained-edit-looks-whole",
         "entries": relink([b[0], dict(b[1], body=dict(b[1]["body"], created=3)), b[2], b[3]]),
         "breaks": [], "findings": []},
    ]}

    # ---------------------------------------------------------------- checkpoints
    def ckpt(n, head, key=B, issuer=B_ID, peer=A_ID):
        claims = {"schema": "kirkaldy.checkpoint/0.1", "issuer": issuer, "peer": peer,
                  "pair_seq": n, "head": head, "issued_at": "2026-11-01T13:02:12Z"}
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        header = {"alg": "EdDSA", "kid": key.kid, "typ": "krk-checkpoint+jws"}
        return r.sign_payload(payload, key, header), claims

    tok3, claims3 = ckpt(3, digest(b[2]))
    rechained = relink([b[0], dict(b[1], body=dict(b[1]["body"], created=3)), b[2], b[3]])
    unsigned = (r._b64e(json.dumps({"alg": "none", "typ": "krk-checkpoint+jws"},
                                   sort_keys=True, separators=(",", ":")).encode())
                + "." + tok3.split(".")[1] + ".")
    checkpoints = {
        "pinned": {B_KID: B.public_bytes().hex()},
        "verify": [
            {"name": "honest", "token": tok3, "ok": True, "reason": None},
            {"name": "unsigned", "token": unsigned, "ok": False, "reason": "unsigned"},
            {"name": "unpinned-key", "token": ckpt(3, digest(b[2]), key=OTHER)[0], "ok": False,
             "reason": "unpinned-key"},
            {"name": "other-key-under-b-kid", "token": ckpt(3, digest(b[2]), key=OTHER_AS_B)[0],
             "ok": False, "reason": "bad-signature"},
            {"name": "receipt-typ", "token": r.sign_payload(
                json.dumps(claims3, sort_keys=True, separators=(",", ":")).encode(), B),
             "ok": False, "reason": "malformed"},
            {"name": "missing-member", "token": r.sign_payload(
                json.dumps({k: v for k, v in claims3.items() if k != "issued_at"},
                           sort_keys=True, separators=(",", ":")).encode(), B,
                {"alg": "EdDSA", "kid": B_KID, "typ": "krk-checkpoint+jws"}),
             "ok": False, "reason": "malformed"},
        ],
        "covers": [
            {"name": "reaches", "claims": claims3, "entries": b, "breaks": []},
            {"name": "later-entries-are-fine", "claims": claims3, "entries": b + [
                entry("B", 5, digest(b[3]), "receipt-issued", B_SPECS[2][1])], "breaks": []},
            {"name": "edited-and-relinked", "claims": claims3, "entries": rechained,
             "breaks": [{"kind": "changed-after-ack", "numbers": [3]}]},
            {"name": "edited-not-relinked", "claims": claims3, "entries": edited,
             "breaks": [{"kind": "changed-after-ack", "numbers": [2, 3]}]},
            {"name": "removed", "claims": claims3, "entries": [b[0], b[2], b[3]],
             "breaks": [{"kind": "removed-after-ack", "numbers": [2]}]},
            {"name": "truncated", "claims": claims3, "entries": [b[0]],
             "breaks": [{"kind": "removed-after-ack", "numbers": [2]},
                        {"kind": "removed-after-ack", "numbers": [3]}]},
        ],
    }

    for name, doc in (("entries", entries), ("chains", chains), ("checkpoints", checkpoints)):
        (HERE / f"{name}.json").write_text(json.dumps(doc, indent=1, sort_keys=True,
                                                      ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
