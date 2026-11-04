"""`conformance/bissuer.py`: JCS against fixed vectors, the kit's own JOSE verifier, RFC 7638
thumbprints, the restatement comparison of rule 8, and the authority block's default. These run
before anything depends on them (design §4.3)."""
import json
import struct
from pathlib import Path

import pytest

from conformance import bissuer

VECTORS = json.loads((Path(__file__).parent / "vectors" / "bissuer" / "jcs.json").read_text())


@pytest.mark.parametrize("v", VECTORS["numbers"], ids=lambda v: v["ieee754"])
def test_jcs_numbers_match_the_rfc_table(v):
    x = struct.unpack(">d", bytes.fromhex(v["ieee754"]))[0]
    assert bissuer.jcs(x).decode() == v["jcs"]


def test_jcs_object_example():
    o = VECTORS["objects"][0]
    assert bissuer.jcs(json.loads(o["input_json"])).decode() == o["jcs"]


def test_jcs_sorts_members_by_utf16_code_units():
    o = VECTORS["objects"][1]
    out = json.loads(bissuer.jcs(json.loads(o["input_json"])))
    assert list(out) == o["keys_in_order"]


def test_jcs_refuses_what_is_not_ijson():
    for v in VECTORS["not_ijson"]:
        with pytest.raises(bissuer.NotIJSON):
            bissuer.jcs(json.loads(v["input_json"]))
    for bad in (float("nan"), float("inf"), "\ud800"):
        with pytest.raises(bissuer.NotIJSON):
            bissuer.jcs(bad)


def test_jcs_differs_from_the_receipts_canonicaliser():
    """`receipts.canonical_json` refuses floats; JCS serialises them (design §4.3)."""
    from conformance import receipts
    with pytest.raises(Exception):
        receipts.canonical_json({"a": 1.5})
    assert bissuer.jcs({"a": 1.5}) == b'{"a":1.5}'


@pytest.mark.parametrize("v", VECTORS["thumbprints"], ids=lambda v: v["name"])
def test_thumbprints_match_the_rfcs(v):
    assert bissuer.thumbprint(v["jwk"]) == v["thumbprint"]


def test_the_rfc8037_signature_verifies():
    v = VECTORS["jws"][0]
    got = bissuer.verify_signature(v["jws"], v["jwks"])
    assert got.ok and got.payload.decode() == v["payload"]
    assert got.thumbprint == VECTORS["thumbprints"][1]["thumbprint"]


def _ed25519_jws(claims, header=None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    x = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    h = bissuer.b64e(json.dumps(header or {"alg": "EdDSA", "kid": "k1"}).encode())
    p = bissuer.b64e(json.dumps(claims).encode())
    sig = k.sign(f"{h}.{p}".encode())
    jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": bissuer.b64e(x), "kid": "k1"}]}
    return f"{h}.{p}.{bissuer.b64e(sig)}", jwks


def test_verify_b_object_refusals():
    tok, jwks = _ed25519_jws({"id": "rev-1", "terms": {"amount": 5}})
    ok = bissuer.verify_b_object(tok, jwks)
    assert ok.ok and ok.claims["id"] == "rev-1"
    h, p, s = tok.split(".")
    assert bissuer.verify_b_object(f"{h}.{p}.", jwks).reason == "unsigned"
    other = bissuer.b64e(json.dumps({"id": "rev-2", "terms": {"amount": 5}}).encode())
    assert bissuer.verify_b_object(f"{h}.{other}.{s}", jwks).reason == "bad-signature"
    _, other_keys = _ed25519_jws({})
    assert bissuer.verify_b_object(tok, other_keys).reason == "bad-signature"
    assert bissuer.verify_b_object(tok, {"keys": []}).reason == "unknown-key"
    none = bissuer.b64e(json.dumps({"alg": "none"}).encode())
    assert bissuer.verify_b_object(f"{none}.{p}.{s}", jwks).reason == "unsigned"
    hs = bissuer.b64e(json.dumps({"alg": "HS256", "kid": "k1"}).encode())
    assert bissuer.verify_b_object(f"{hs}.{p}.{s}", jwks).reason == "alg"
    dup, jw2 = _ed25519_jws({})
    hh, _, _ = dup.split(".")
    raw = b'{"id":"a","id":"b"}'
    assert not bissuer.verify_b_object(f"{hh}.{bissuer.b64e(raw)}.{s}", jw2).ok


def test_es256_verifies_with_the_kits_own_code():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    k = ec.generate_private_key(ec.SECP256R1())
    n = k.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": "e1", "x": bissuer.b64e(n.x.to_bytes(32, "big")),
           "y": bissuer.b64e(n.y.to_bytes(32, "big"))}
    h = bissuer.b64e(b'{"alg":"ES256","kid":"e1"}')
    p = bissuer.b64e(b'{"id":"cns-1"}')
    r, s = decode_dss_signature(k.sign(f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256())))
    sig = bissuer.b64e(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    assert bissuer.verify_b_object(f"{h}.{p}.{sig}", {"keys": [jwk]}).ok
    assert len(bissuer.thumbprint(jwk)) == 43


def test_restatement():
    asked = {"ref": "r-1", "amount": 5, "items": ["a", "b"], "recipient": "x"}
    assert bissuer.restatement(asked, dict(asked, id="B's own member")) is None
    d = bissuer.restatement(asked, dict(asked, amount=6))
    assert set(d) == {"amount"} and d["amount"] == {"asked": 5, "signed": 6}
    assert set(bissuer.restatement(asked, {k: v for k, v in asked.items() if k != "items"})) == \
        {"items"}
    assert bissuer.restatement({"amount": 2 ** 53 + 1}, {"amount": 2 ** 53}) is not None
    assert bissuer.restatement({"amount": 2 ** 53 + 1}, {"amount": 2 ** 53 + 1}) is None
    assert bissuer.restatement({"amount": 1}, {"amount": True}) is not None
    assert bissuer.restatement({"recipient": "ａ"}, {"recipient": "a"}) is not None


def test_digest_matches():
    terms = {"amount": 5, "ref": "r"}
    d = bissuer.terms_digest(terms)
    assert bissuer.digest_matches(d, terms) is True
    assert bissuer.digest_matches(d, dict(terms, amount=6)) is False
    assert bissuer.digest_matches(None, terms) is None
    assert bissuer.digest_matches(d, {"amount": 2 ** 53 + 1}) is None


class _NoAuthority:
    def agreement(self):
        return {"counterparty": "x"}


class _AgreementAuthority:
    def agreement(self):
        return {"authority": {"issuer": "B", "shape": "revision",
                              "hook": {"kind": "driven-page"}}}


class _Raises:
    def authority(self):
        raise RuntimeError("boom")


def test_authority_defaults_to_a():
    assert bissuer.authority_of(_NoAuthority()).issuer == "A"
    assert bissuer.authority_of(object()).issuer == "A"
    assert bissuer.authority_of(_Raises()).issuer == "A"
    got = bissuer.authority_of(_AgreementAuthority())
    assert got.issuer == "B" and got.source == "agreement()" and got.problem() is None
    assert bissuer.declared_authority(_AgreementAuthority()).issuer == "A"


def test_authority_problems():
    assert "shape" in bissuer.Authority("B", shape="ledger", hook={"kind": "driven-page"}).problem()
    assert "hook" in bissuer.Authority("B", shape="revision", hook={"kind": "db-write"}).problem()
    assert bissuer.Authority("C").problem()
