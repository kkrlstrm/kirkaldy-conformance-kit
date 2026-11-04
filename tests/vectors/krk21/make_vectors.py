"""Writes the KRK-21 test vectors in this directory. Run from the repo root:

    python tests/vectors/krk21/make_vectors.py

The constraint vocabulary of `X5-NO-WIDENING-DESIGN.md` §2.2, as cases whose expected answers are
written here by hand: which patterns cover which, which amounts compare and how, which hops are
wider than their parents and in which dimension, which chains allow nothing and why, and which
requests lie inside. Nothing is computed by `conformance.attenuation`, so a bug in it cannot
make its own vector agree with it (KRK-M83).
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def amt(v, cur="EUR", mu=2):
    return {"value": v, "currency": cur, "minor_units": mu}


def g(gid, parent, c, *, nb="2026-11-02T09:00:00Z", na="2026-11-02T21:00:00Z", **extra):
    out = {"schema": "kirkaldy.grant/0.2", "grant_id": gid, "issuer": "did:web:a.example",
           "subject": f"agent-{gid[-2:]}",
           "agent_key": {"kid": "k", "public_key": "ab" * 32}, "principal": "alice@a.example",
           "constraints": c, "parent": parent, "issued_at": "2026-11-02T10:00:00.000Z",
           "not_before": nb, "not_after": na,
           "status": {"source": "http://127.0.0.1:9/status/list", "index": 0}}
    out.update(extra)
    return out


R, C1, C2 = "gr-00000000000000a1", "gr-00000000000000b2", "gr-00000000000000c3"
COVERS = [  # (parent pattern, child pattern, covers?) -- by hand
    ("acct-1/*", "acct-1/x", True), ("acct-1/*", "acct-1/x/y", True),
    ("acct-1/*", "acct-1/*", True), ("acct-1/*", "acct-1/sub/*", True),
    ("acct-1/*", "acct-12/x", False), ("acct-1/*", "acct-1", False),
    ("acct/1/*", "acct/*", False), ("acct/*", "acct/1/*", True),
    ("acct-1/x", "acct-1/x", True), ("acct-1/x", "acct-1/x/y", False),
    ("acct-*", "acct-1", False), ("acct-1/*", "acct-*", False), ("*", "x", False)]
AMOUNT_LE = [  # (a, b, a <= b?: true, false or null for incomparable) -- by hand
    (amt(100), amt(100), True), (amt(101), amt(100), False),
    (amt(150, mu=0), amt(10000, mu=2), False), (amt(100, mu=0), amt(10000, mu=2), True),
    (amt(100, "USD"), amt(100), None), (amt(2 ** 53), amt(2 ** 53), None),
    (amt(100.5), amt(1000), None), (amt("100"), amt(1000), None), (amt(-1), amt(1000), None),
    (amt(True), amt(1000), None), (amt(1, mu=19), amt(1000), None)]
WIDER = [  # (child constraints, parent constraints, dims wider) -- by hand; windows equal
    ({"max_amount": amt(5000)}, {"max_amount": amt(1000)}, ["max_amount"]),
    ({"max_amount": amt(1000)}, {"max_amount": amt(5000)}, []),
    ({}, {"max_amount": amt(1000)}, []),
    ({"operations": ["a", "b"]}, {"operations": ["a"]}, ["operations"]),
    ({"operations": []}, {"operations": ["a"]}, []),
    ({"resources": ["acct/*"]}, {"resources": ["acct/1/*"]}, ["resources"]),
    ({"resources": ["acct/1/x"]}, {"resources": ["acct/*"]}, []),
    ({"audience": ["b", "c"]}, {"audience": ["b"]}, ["audience"]),
    ({"delegation": {"max_depth": 2}}, {"delegation": {"max_depth": 2}}, ["delegation"]),
    ({"delegation": {"max_depth": 1}}, {"delegation": {"max_depth": 2}}, []),
    ({}, {"delegation": {"max_depth": 0}}, ["delegation"]),
    ({"max_amount": amt(5000, "USD")}, {"max_amount": amt(5000)}, ["max_amount"]),
    ({"max_amount": amt(150, mu=0)}, {"max_amount": amt(10000)}, ["max_amount"])]
BASE = {"max_amount": amt(500000), "operations": ["op.a", "op.b"],
        "resources": ["acct-1/*"], "audience": ["did:web:b.example"]}
CHAINS = {  # name: (chain, presented first; expected refusal reason or null) -- by hand
    "honest": ([g(C1, R, BASE), g(R, None, BASE)], None),
    "self-parent": ([g(R, R, BASE)], "self-parent"),
    "cycle": ([g(C1, R, BASE), g(R, C1, BASE), g(C1, R, BASE)], "cycle"),
    "not-rooted": ([g(C1, R, BASE), g(R, C2, BASE)], "not-rooted"),
    "broken-link": ([g(C1, C2, BASE), g(R, None, BASE)], "not-rooted"),
    "two-parents": ([g(C1, [R, C2], BASE), g(R, None, BASE)], "two-parents"),
    "unknown-member": ([g(C1, R, {**BASE, "x-krk-1": 1}), g(R, None, BASE)],
                       "unknown-constraint"),
    "crit-names-unknown": ([g(C1, R, BASE, crit=["x-krk-1"]), g(R, None, BASE)],
                           "unknown-constraint"),
    "null-member": ([g(C1, R, {**BASE, "resources": None}), g(R, None, BASE)], "malformed"),
    "wildcard-operation": ([g(C1, R, {**BASE, "operations": ["*"]}), g(R, None, BASE)],
                           "malformed"),
    "glob-resource": ([g(C1, R, {**BASE, "resources": ["acct-*"]}), g(R, None, BASE)],
                      "malformed"),
    "no-window-end": ([{k: v for k, v in g(C1, R, BASE).items() if k != "not_after"},
                       g(R, None, BASE)], "malformed"),
    "float-amount": ([g(C1, R, {**BASE, "max_amount": amt(1000.4)}), g(R, None, BASE)],
                     "malformed"),
    "depth-0-has-a-child": ([g(C1, R, BASE), g(R, None, {**BASE, "delegation": {
        "max_depth": 0}})], "depth-exceeded"),
    "depth-1-two-below": ([g(C2, C1, BASE), g(C1, R, BASE), g(R, None, {**BASE, "delegation": {
        "max_depth": 1}})], "depth-exceeded"),
}
INSIDE = [  # (chain name, request, at, expected: null inside, else a word the reason contains)
    ("honest", {"operation": "op.a", "amount": amt(300000), "resources": ["acct-1/x"]},
     "2026-11-02T12:00:00Z", None),
    ("honest", {"operation": "op.c", "amount": amt(300000), "resources": ["acct-1/x"]},
     "2026-11-02T12:00:00Z", "operation"),
    ("honest", {"operation": "op.a", "amount": amt(500001), "resources": ["acct-1/x"]},
     "2026-11-02T12:00:00Z", "above"),
    ("honest", {"operation": "op.a", "amount": amt(3000, mu=0), "resources": ["acct-1/x"]},
     "2026-11-02T12:00:00Z", None),
    ("honest", {"operation": "op.a", "amount": amt(3000, "USD"), "resources": ["acct-1/x"]},
     "2026-11-02T12:00:00Z", "currency"),
    ("honest", {"operation": "op.a", "amount": amt(-1), "resources": ["acct-1/x"]},
     "2026-11-02T12:00:00Z", "exactly"),
    ("honest", {"operation": "op.a", "amount": amt(1), "resources": ["acct-2/x"]},
     "2026-11-02T12:00:00Z", "covered"),
    ("honest", {"operation": "op.a", "amount": amt(1), "resources": ["acct-1/*"]},
     "2026-11-02T12:00:00Z", "exact id"),
    ("honest", {"operation": "op.a", "amount": amt(1), "resources": ["acct-1/x"]},
     "2026-11-02T21:00:06Z", "window"),
    ("honest", {"operation": "op.a", "amount": amt(1), "resources": ["acct-1/x"]},
     "2026-11-02T21:00:05Z", None),
]
STANDING = [  # (chain name, standing classes, request, expected) -- by hand
    ("honest", {"op.a": {"max_amount": amt(1000)}},
     {"operation": "op.a", "amount": amt(3000), "resources": ["acct-1/x"]}, "standing"),
    ("honest", {"op.a": None},
     {"operation": "op.a", "amount": amt(3000), "resources": ["acct-1/x"]}, None),
    ("honest", {"op.b": None},
     {"operation": "op.a", "amount": amt(3000), "resources": ["acct-1/x"]}, "standing"),
]


def main() -> None:
    out = {"covers": COVERS, "amount_le": AMOUNT_LE, "wider": WIDER,
           "chains": {k: {"chain": v[0], "refusal": v[1]} for k, v in CHAINS.items()},
           "inside": [{"chain": c, "request": r, "at": at, "expected": e}
                      for c, r, at, e in INSIDE],
           "standing": [{"chain": c, "classes": s, "request": r, "expected": e}
                        for c, s, r, e in STANDING], "tolerance_s": 5,
           "party": "did:web:b.example"}
    (HERE / "vectors.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
