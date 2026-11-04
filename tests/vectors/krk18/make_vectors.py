"""Writes the KRK-18 test vectors in this directory. Run from the repo root:

    python tests/vectors/krk18/make_vectors.py

Every request is written here as a byte literal, so the fixture bytes never pass through a JSON
serialiser on their way to disk (KRK-M37). Every expected answer is written out by hand:
`ambiguous()`'s answer, the canonical bytes (hashed with hashlib alone), the raw digest, and the
digest a lenient parser gives. None is computed by `conformance.authz`, so a bug there cannot
make its own vector agree with it. `tests/test_authz.py` also checks each request's bytes with
an independent JSON reader before anything depends on them.

Authorisations are signed with the RFC 8032 test keys (Ed25519 is deterministic, so the tokens
are byte-stable); their expected verify reasons are written by hand.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from conformance import receipts as r  # noqa: E402

A_KID = "a-authz-2026-11"
A = r.Keypair.from_seed(A_KID, bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
OTHER_AS_A = r.Keypair.from_seed(A_KID, bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
A_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

CANON = (b'{"amount":100,"items":["sku-1","sku-2"],"operation":"crm.record.push",'
         b'"recipient":"acct-1234@example.test","ref":"r-0001"}')
FULLWIDTH_CANON = ('{"amount":100,"items":["sku-1"],"operation":"crm.record.push",'
                   '"recipient":"ａｃｃｔ-1234@example.test","ref":"r-0007"}'
                   ).encode("utf-8")


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


# name -> (raw bytes, ambiguous() answer, canonical bytes or None, lenient-parser canonical bytes)
REQUESTS = {
    "canonical.json": (CANON, None, CANON, CANON),
    "whitespace.json": (
        b'{\n  "ref": "r-0001",\n  "recipient": "acct-1234@example.test",\n'
        b'  "operation": "crm.record.push",\n  "items": [ "sku-1", "sku-2" ],\n'
        b'  "amount": 100\n}\n', None, CANON, CANON),
    "escaped.json": (
        b'{"amount":100,"items":["sku-1","sku-2"],"operation":"crm.record.push",'
        b'"recipient":"\\u0061cct-1234@example.test","ref":"r-0001"}', None, CANON, CANON),
    "duplicate-key.json": (
        b'{"amount":100,"items":["sku-1"],"amount":9900,'
        b'"recipient":"acct-1234@example.test","ref":"r-0002"}', "duplicate-key", None,
        b'{"amount":9900,"items":["sku-1"],"recipient":"acct-1234@example.test","ref":"r-0002"}'),
    "nested-duplicate.json": (
        b'{"payee":{"id":"acct-1","id":"acct-2"},"ref":"r-0003"}', "duplicate-key", None,
        b'{"payee":{"id":"acct-2"},"ref":"r-0003"}'),
    "safe-max.json": (
        b'{"amount":9007199254740991,"ref":"r-0004"}', None,
        b'{"amount":9007199254740991,"ref":"r-0004"}',
        b'{"amount":9007199254740991,"ref":"r-0004"}'),
    "unsafe-integer.json": (
        b'{"amount":9007199254740993,"ref":"r-0005"}', "unsafe-integer", None,
        b'{"amount":9007199254740993,"ref":"r-0005"}'),
    "negative-unsafe.json": (
        b'{"amount":-9007199254740992,"ref":"r-0005"}', "unsafe-integer", None,
        b'{"amount":-9007199254740992,"ref":"r-0005"}'),
    "float.json": (b'{"amount":100.0,"ref":"r-0006"}', "float", None,
                   b'{"amount":100.0,"ref":"r-0006"}'),
    "exponent.json": (b'{"amount":1e2,"ref":"r-0006"}', "float", None,
                      b'{"amount":100.0,"ref":"r-0006"}'),
    "fullwidth.json": (FULLWIDTH_CANON, None, FULLWIDTH_CANON, FULLWIDTH_CANON),
    "duplicate-and-float.json": (b'{"a":1.5,"a":2}', "duplicate-key", None, b'{"a":2}'),
    "nan.json": (b'{"amount":NaN}', "not-json", None, None),
    "not-utf8.bin": (b'{"recipient":"\xff"}', "not-json", None, None),
    "trailing-comma.json": (b'{"amount":100,}', "not-json", None, None),
}


def authorisation(claims_patch=None, *, key=A, header=None, unsigned=False):
    claims = {
        "schema": "kirkaldy.request-authorisation/0.1",
        "authorisation_id": "az-5c1f0e9a77d2b3e4",
        "issuer": "did:web:a.example",
        "audience": {"counterparty": "did:web:b.example", "endpoint": "orders",
                     "tenant": "t-17"},
        "operation": "crm.record.push",
        "binding": {"kind": "exact", "basis": "kirkaldy.canonical-json/0.1",
                    "request_digest": sha(CANON), "parts": None, "mapping": None,
                    "summary": None, "ceiling": None},
        "max_uses": 1,
        "not_before": "2026-11-01T13:00:00Z",
        "not_after": "2026-11-01T13:15:00Z",
        "decision_digest": None,
    }
    for k, v in (claims_patch or {}).items():
        if v is _DROP:
            claims.pop(k)
        else:
            claims[k] = v
    payload = r.canonical_json(claims)
    if unsigned:
        h = r._b64e(r.canonical_json({"alg": "none", "typ": "krk-authz+jws"}))
        return f"{h}.{r._b64e(payload)}."
    hdr = header or {"alg": "EdDSA", "kid": key.kid, "typ": "krk-authz+jws"}
    return r.sign_payload(payload, key, hdr)


_DROP = object()

CLASS_BINDING = {"kind": "class", "basis": "kirkaldy.canonical-json/0.1", "request_digest": None,
                 "parts": None, "mapping": None, "summary": None,
                 "ceiling": {"operation": "notes.append", "max_count": 10}}

# name -> (token, expected ok, expected reason)
AUTHORISATIONS = {
    "exact": (authorisation(), True, None),
    "class": (authorisation({"binding": CLASS_BINDING, "operation": "notes.append"}), True, None),
    "unsigned": (authorisation(unsigned=True), False, "unsigned"),
    "unpinned-kid": (authorisation(key=r.Keypair.from_seed("a-authz-other", bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))),
        False, "unpinned-key"),
    "other-key-under-a-kid": (authorisation(key=OTHER_AS_A), False, "bad-signature"),
    "receipt-typ": (authorisation(header={"alg": "EdDSA", "kid": A_KID,
                                          "typ": "krk-receipt+jws"}), False, "malformed"),
    "no-binding": (authorisation({"binding": _DROP}), False, "malformed"),
    "window-inverted": (authorisation({"not_after": "2026-11-01T12:59:59Z"}), False, "malformed"),
    "parts-without-uses": (authorisation({"binding": {
        "kind": "exact", "basis": "kirkaldy.canonical-json/0.1", "request_digest": sha(CANON),
        "parts": [sha(b"1"), sha(b"2")], "mapping": None, "summary": None, "ceiling": None}}),
        False, "malformed"),
    "seed-shaped-id": (authorisation({"authorisation_id": "p18-control-7"}), False, "malformed"),
}


def main() -> None:
    req_dir = HERE / "requests"
    req_dir.mkdir(exist_ok=True)
    out = {}
    for name, (raw, amb, canon, lenient) in REQUESTS.items():
        (req_dir / name).write_bytes(raw)
        out[name] = {"raw_sha256": sha(raw), "ambiguous": amb,
                     "canonical_digest": sha(canon) if canon is not None else None,
                     "canonical_bytes": canon.decode("utf-8") if canon is not None else None,
                     "lenient_digest": sha(lenient) if lenient is not None else None}
    (HERE / "requests.json").write_text(json.dumps(out, indent=2, sort_keys=True,
                                                   ensure_ascii=False) + "\n")
    auth = {"pinned": {A_KID: A_PUBLIC},
            "vectors": {n: {"token": t, "ok": ok, "reason": why}
                        for n, (t, ok, why) in AUTHORISATIONS.items()}}
    (HERE / "authorisations.json").write_text(json.dumps(auth, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
