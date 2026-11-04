"""Writes the KRK-20 test vectors in this directory. Run from the repo root:

    python tests/vectors/krk20/make_vectors.py

Key statements, standing assertions and a grant 0.2 chain with holder-signed hops, signed with
keys from fixed seeds (the RFC 8032 test seeds and others written here; Ed25519 is deterministic,
so the tokens are byte-stable). Every claim is written out by hand, not built by
`conformance.standing`, and every expected answer (the verify reason, a key's state for a
signature at a time, the standing a correct B derives, a chain's verdict) is written by hand, so
a bug in the module cannot make its own vector agree with it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from conformance import receipts as r  # noqa: E402

SEEDS = {"anchor": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "a-grant": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "a-standing": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "a-retired": "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
         "a2-standing": "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
         "agent-a1": "0101010101010101010101010101010101010101010101010101010101010101",
         "agent-c1": "0202020202020202020202020202020202020202020202020202020202020202",
         "agent-c2": "0303030303030303030303030303030303030303030303030303030303030303"}
K = {name: r.Keypair.from_seed(name, bytes.fromhex(s)) for name, s in SEEDS.items()}
PUB = {name: k.public_bytes().hex() for name, k in K.items()}
A, A2 = "did:web:a.example", "did:web:a2.example"
B = "did:web:b.example"


def jws(claims, key, typ):
    return r.sign_payload(r.canonical_json(claims), key,
                          {"alg": "EdDSA", "kid": key.kid, "typ": typ})


KEYSET = {"schema": "kirkaldy.keyset/0.1", "issuer": A, "version": 3,
          "issued_at": "2026-11-02T10:00:00.000Z", "ttl_s": 60,
          "expires_at": "2026-11-02T10:01:00.000Z",
          "keys": [{"kid": "a-grant", "public_key": PUB["a-grant"],
                    "purposes": ["grant", "request", "status"], "state": "active",
                    "since": None},
                   {"kid": "a-retired", "public_key": PUB["a-retired"],
                    "purposes": ["standing"], "state": "retired",
                    "since": "2026-11-02T09:00:00.000Z"},
                   {"kid": "a-standing", "public_key": PUB["a-standing"],
                    "purposes": ["standing"], "state": "active", "since": None}]}
REVOKED = {**KEYSET, "version": 4, "keys": [
    *KEYSET["keys"][:2], {**KEYSET["keys"][2], "state": "revoked",
                          "since": "2026-11-02T10:00:30.000Z"}]}


def assertion(**patch):
    c = {"schema": "kirkaldy.standing/0.1", "issuer": A, "principal": "alice@a.example",
         "classes": {"crm.record.push": None}, "issued_at": "2026-11-02T10:00:10.000Z",
         "not_after": "2026-11-02T22:00:10.000Z", "audience": None}
    c.update(patch)
    return c


# `at` is the wall time a B judges at; T = 60 s throughout.
# (case, assertion claims, signing key, keyset, chain issuer, root principal, operation,
#  audience, at, expected state) -- the expected state is written by hand.
STANDING_CASES = [
    ("current", assertion(), "a-standing", KEYSET, A, "alice@a.example", "crm.record.push", B,
     "2026-11-02T10:00:40.000Z", "current"),
    ("stale-by-age", assertion(), "a-standing", KEYSET, A, "alice@a.example",
     "crm.record.push", B, "2026-11-02T10:01:10.001Z", "stale"),
    ("exactly-T-old", assertion(), "a-standing", KEYSET, A, "alice@a.example",
     "crm.record.push", B, "2026-11-02T10:01:10.000Z", "current"),
    ("past-its-own-not_after", assertion(not_after="2026-11-02T10:00:20.000Z"), "a-standing",
     KEYSET, A, "alice@a.example", "crm.record.push", B, "2026-11-02T10:00:30.000Z", "stale"),
    ("retired-key-after-since", assertion(), "a-retired", KEYSET, A, "alice@a.example",
     "crm.record.push", B, "2026-11-02T10:00:40.000Z", "wrong-key"),
    ("revoked-key-signed-after-since", assertion(issued_at="2026-11-02T10:00:45.000Z"),
     "a-standing", REVOKED, A, "alice@a.example", "crm.record.push", B,
     "2026-11-02T10:00:50.000Z", "wrong-key"),
    ("revoked-key-signed-before-since", assertion(), "a-standing", REVOKED, A,
     "alice@a.example", "crm.record.push", B, "2026-11-02T10:00:50.000Z", "current"),
    ("grant-key-not-designated", assertion(), "a-grant", KEYSET, A, "alice@a.example",
     "crm.record.push", B, "2026-11-02T10:00:40.000Z", "wrong-key"),
    ("key-not-in-statement", assertion(), "a2-standing", KEYSET, A, "alice@a.example",
     "crm.record.push", B, "2026-11-02T10:00:40.000Z", "wrong-key"),
    ("another-organisation", assertion(issuer=A2), "a-standing", KEYSET, A, "alice@a.example",
     "crm.record.push", B, "2026-11-02T10:00:40.000Z", "wrong-org"),
    ("another-principal", assertion(principal="bob@a.example"), "a-standing", KEYSET, A,
     "alice@a.example", "crm.record.push", B, "2026-11-02T10:00:40.000Z", "wrong-principal"),
    ("another-class", assertion(classes={"crm.record.delete": None}), "a-standing", KEYSET, A,
     "alice@a.example", "crm.record.push", B, "2026-11-02T10:00:40.000Z", "wrong-class"),
    ("another-audience", assertion(audience=["did:web:b-prime.example"]), "a-standing", KEYSET,
     A, "alice@a.example", "crm.record.push", B, "2026-11-02T10:00:40.000Z", "wrong-audience"),
    ("addressed-to-b", assertion(audience=[B, "did:web:b-prime.example"]), "a-standing", KEYSET,
     A, "alice@a.example", "crm.record.push", B, "2026-11-02T10:00:40.000Z", "current"),
    ("a-class-with-a-limit", assertion(classes={"crm.record.push": {"max_amount": {
        "value": 100000, "currency": "EUR", "minor_units": 2}}}), "a-standing", KEYSET, A,
     "alice@a.example", "crm.record.push", B, "2026-11-02T10:00:40.000Z", "current"),
]
# The same evidence judged by its kit-clock signing time rather than its claim (KRK-M74): A's
# clock ran 120 s ahead, so the claim says 10:02:10 and the signing log 10:00:10.
SKEW_CASE = {"assertion": assertion(issued_at="2026-11-02T10:02:10.000Z"),
             "signed_at": "2026-11-02T10:00:10.000Z", "at": "2026-11-02T10:01:20.000Z",
             "by_claim": "current", "by_log": "stale"}

KEY_STATE_CASES = [
    # (kid, purpose, signed_at, keyset, expected) -- written by hand
    ("a-standing", "standing", "2026-11-02T10:00:10.000Z", KEYSET, "a-key"),
    ("a-standing", "grant", "2026-11-02T10:00:10.000Z", KEYSET, "wrong-purpose"),
    ("a-retired", "standing", "2026-11-02T08:59:59.999Z", KEYSET, "a-key"),
    ("a-retired", "standing", "2026-11-02T09:00:00.000Z", KEYSET, "retired"),
    ("a-retired", "standing", None, KEYSET, "retired"),
    ("a-standing", "standing", "2026-11-02T10:00:30.000Z", REVOKED, "revoked"),
    ("a-standing", "standing", "2026-11-02T10:00:29.999Z", REVOKED, "a-key"),  # 153: also "revoked"
    ("nobody", "standing", "2026-11-02T10:00:10.000Z", KEYSET, "not-a-key"),
]


def grant2(gid, *, issuer, subject, agent, principal, parent, index, source, **patch):
    c = {"schema": "kirkaldy.grant/0.2", "grant_id": gid, "issuer": issuer, "subject": subject,
         "agent_key": {"kid": agent, "public_key": PUB[agent]}, "principal": principal,
         "constraints": {"operations": ["crm.record.push"],
                         "max_amount": {"value": 100000, "currency": "EUR",
                                        "minor_units": 2}},
         "parent": parent, "issued_at": "2026-11-02T10:00:00.000Z",
         "not_before": "2026-11-02T09:00:00Z", "not_after": "2026-11-02T21:00:00Z",
         "status": {"source": source, "index": index}}
    c.update(patch)
    return c


ROOT = grant2("gr-0000000000000a01", issuer=A, subject="a1", agent="agent-a1",
              principal="alice@a.example", parent=None, index=0,
              source="http://127.0.0.1:9/status/list")
HOP1 = grant2("gr-0000000000000a02", issuer="a1", subject="c1", agent="agent-c1",
              principal="alice@a.example", parent=ROOT["grant_id"], index=1,
              source="http://127.0.0.1:9/status/list")
HOP2 = grant2("gr-0000000000000a03", issuer="c1", subject="c2", agent="agent-c2",
              principal="carol@c.example", parent=HOP1["grant_id"], index=0,
              source="http://127.0.0.1:10/status/list")
GT = "krk-grant+jws"


def chains():
    good = [jws(HOP2, K["agent-c1"], GT), jws(HOP1, K["agent-a1"], GT), jws(ROOT, K["a-grant"], GT)]
    return {
        # (tokens, expected problem: None or a word it must contain) -- by hand
        "three-hops": (good, None),
        "hop-signed-by-a-not-the-holder": ([jws(HOP2, K["agent-c1"], GT),
                                            jws(HOP1, K["a-grant"], GT), good[2]],
                                           "unpinned-key"),
        "hop-issuer-is-not-the-parents-subject": ([jws({**HOP2, "issuer": "c9"},
                                                       K["agent-c1"], GT), good[1], good[2]],
                                                  "not by its parent's holder"),
        "root-signed-by-a-key-not-for-grants": ([good[0], good[1],
                                                 jws(ROOT, K["a-standing"], GT)],
                                                "wrong-purpose"),
        "root-issuer-not-pinned": ([good[0], good[1], jws({**ROOT, "issuer": A2},
                                                          K["a-grant"], GT)],
                                   "not an organisation B pins"),
        "a-hop-names-two-parents": ([jws({**HOP2, "parent": [HOP1["grant_id"],
                                                            ROOT["grant_id"]]},
                                         K["agent-c1"], GT), good[1], good[2]],
                                    "two-parents"),
    }


def main() -> None:
    out = {"keys": PUB, "keyset": {"claims": KEYSET, "token": jws(KEYSET, K["anchor"],
                                                                  "krk-keyset+jws"),
                                   "revoked": REVOKED},
           "verify": [], "key_state": [], "standing": [], "skew": SKEW_CASE, "chains": {}}
    tok = out["keyset"]["token"]
    h, p, s = tok.split(".")
    out["verify"] = [
        {"case": "keyset-under-anchor", "token": tok, "pinned": ["anchor"],
         "typ": "krk-keyset+jws", "reason": None},
        {"case": "keyset-under-another-key", "token": tok, "pinned": ["a-grant"],
         "typ": "krk-keyset+jws", "reason": "unpinned-key"},
        {"case": "keyset-read-as-standing", "token": tok, "pinned": ["anchor"],
         "typ": "krk-standing+jws", "reason": "malformed"},
        {"case": "keyset-signature-of-other-bytes",
         "token": f"{h}.{r._b64e(r.canonical_json({**KEYSET, 'version': 9}))}.{s}",
         "pinned": ["anchor"], "typ": "krk-keyset+jws", "reason": "bad-signature"},
        {"case": "standing-not-canonical",
         "token": r.sign_payload(json.dumps(assertion(), indent=1).encode(), K["a-standing"],
                                 {"alg": "EdDSA", "kid": "a-standing",
                                  "typ": "krk-standing+jws"}),
         "pinned": ["a-standing"], "typ": "krk-standing+jws", "reason": "malformed"},
    ]
    out["key_state"] = [{"kid": k, "purpose": p_, "signed_at": t, "keyset_version":
                         ks["version"], "expected": e} for k, p_, t, ks, e in KEY_STATE_CASES]
    # A revoked key's signature claimed before `since` may be read as A's or
    # refused; both are conformant. Written by hand, as the expected answers are.
    for v in out["key_state"]:
        if (v["kid"], v["signed_at"], v["keyset_version"]) == (
                "a-standing", "2026-11-02T10:00:29.999Z", REVOKED["version"]):
            v["also_conformant"] = ["revoked"]
    for case, claims, kid, ks, iss, pr, op, aud, at, exp in STANDING_CASES:
        out["standing"].append({"case": case, "claims": claims, "kid": kid,
                                "token": jws(claims, K[kid], "krk-standing+jws"),
                                "keyset_version": ks["version"], "issuer": iss,
                                "principal": pr, "operation": op, "audience": aud, "at": at,
                                "T": 60, "expected": exp})
    for v in out["standing"]:
        if v["case"] == "revoked-key-signed-before-since":
            v["also_conformant"] = ["wrong-key"]
    for name, (toks, exp) in chains().items():
        out["chains"][name] = {"tokens": toks, "expected_problem": exp}
    (HERE / "vectors.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
