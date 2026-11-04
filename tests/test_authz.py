"""KRK-18 authorisations (`conformance/authz.py`) against the vectors in tests/vectors/krk18/.

The first test reads every request vector with a JSON reader written here, which shares no code
with `authz` or Python's `json` module, and checks that the vector's stated ambiguity and
canonical bytes agree with it. Everything after depends on the vectors, so that check comes
first (KRK-M37: a fixture normalised before it reached anything)."""
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import authz, receipts  # noqa: E402

HERE = Path(__file__).resolve().parent / "vectors" / "krk18"
REQ = json.loads((HERE / "requests.json").read_text(encoding="utf-8"))
AUTH = json.loads((HERE / "authorisations.json").read_text())
SAFE = 2 ** 53 - 1


# ----------------------------------------------------------------------- an independent reader


class Reader:
    """A strict JSON reader (RFC 8259) that notes duplicate members, integers outside the safe
    range and numbers with a fraction or exponent, and keeps every number as its text."""

    def __init__(self, data: bytes) -> None:
        self.s = data.decode("utf-8")       # the codec only; no JSON parsing
        self.i = 0
        self.notes = set()

    def fail(self, why):
        raise ValueError(f"at {self.i}: {why}")

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] in " \t\n\r":
            self.i += 1

    def value(self):
        self.ws()
        if self.i >= len(self.s):
            self.fail("end of input")
        c = self.s[self.i]
        if c == "{":
            return self.obj()
        if c == "[":
            return self.arr()
        if c == '"':
            return self.string()
        if c == "-" or c.isdigit():
            return self.number()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(word, self.i):
                self.i += len(word)
                return val
        self.fail(f"unexpected {c!r}")

    def obj(self):
        self.i += 1
        out, keys = [], set()
        self.ws()
        if self.s[self.i:self.i + 1] == "}":
            self.i += 1
            return ("obj", out)
        while True:
            self.ws()
            if self.s[self.i:self.i + 1] != '"':
                self.fail("member name expected")
            k = self.string()
            if k in keys:
                self.notes.add("duplicate-key")
            keys.add(k)
            self.ws()
            if self.s[self.i:self.i + 1] != ":":
                self.fail("colon expected")
            self.i += 1
            out.append((k, self.value()))
            self.ws()
            c = self.s[self.i:self.i + 1]
            self.i += 1
            if c == "}":
                return ("obj", out)
            if c != ",":
                self.fail("comma or } expected")

    def arr(self):
        self.i += 1
        out = []
        self.ws()
        if self.s[self.i:self.i + 1] == "]":
            self.i += 1
            return ("arr", out)
        while True:
            out.append(self.value())
            self.ws()
            c = self.s[self.i:self.i + 1]
            self.i += 1
            if c == "]":
                return ("arr", out)
            if c != ",":
                self.fail("comma or ] expected")

    def string(self):
        self.i += 1
        out = []
        while True:
            if self.i >= len(self.s):
                self.fail("unterminated string")
            c = self.s[self.i]
            self.i += 1
            if c == '"':
                return "".join(out)
            if ord(c) < 0x20:
                self.fail("control character in string")
            if c != "\\":
                out.append(c)
                continue
            e = self.s[self.i]
            self.i += 1
            simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n",
                      "r": "\r", "t": "\t"}
            if e in simple:
                out.append(simple[e])
            elif e == "u":
                cp = int(self.s[self.i:self.i + 4], 16)
                self.i += 4
                if 0xD800 <= cp < 0xDC00 and self.s[self.i:self.i + 2] == "\\u":
                    lo = int(self.s[self.i + 2:self.i + 6], 16)
                    self.i += 6
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                out.append(chr(cp))
            else:
                self.fail(f"bad escape \\{e}")

    def number(self):
        start = self.i
        if self.s[self.i] == "-":
            self.i += 1
        if self.s[self.i:self.i + 1] == "0":
            self.i += 1
        elif self.s[self.i:self.i + 1].isdigit():
            while self.i < len(self.s) and self.s[self.i].isdigit():
                self.i += 1
        else:
            self.fail("digit expected")
        frac = False
        if self.s[self.i:self.i + 1] == ".":
            frac = True
            self.i += 1
            if not self.s[self.i:self.i + 1].isdigit():
                self.fail("digit expected after .")
            while self.i < len(self.s) and self.s[self.i].isdigit():
                self.i += 1
        if self.s[self.i:self.i + 1] in ("e", "E"):
            frac = True
            self.i += 1
            if self.s[self.i:self.i + 1] in ("+", "-"):
                self.i += 1
            if not self.s[self.i:self.i + 1].isdigit():
                self.fail("digit expected in exponent")
            while self.i < len(self.s) and self.s[self.i].isdigit():
                self.i += 1
        text = self.s[start:self.i]
        if frac:
            self.notes.add("float")
        elif abs(int(text)) > SAFE:
            self.notes.add("unsafe-integer")
        return ("num", text)

    def read(self):
        v = self.value()
        self.ws()
        if self.i != len(self.s):
            self.fail("trailing data")
        return v


def _esc(s):
    out = ['"']
    short = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r",
             "\t": "\\t"}
    for ch in s:
        if ch in short:
            out.append(short[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def write_canonical(v):
    """RFC 8785 for the values the vectors use (ASCII keys, integers, strings, nesting)."""
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, str):
        return _esc(v)
    kind, body = v
    if kind == "num":
        return str(int(body))
    if kind == "arr":
        return "[" + ",".join(write_canonical(x) for x in body) + "]"
    return "{" + ",".join(f"{_esc(k)}:{write_canonical(x)}"
                          for k, x in sorted(body, key=lambda kv: kv[0])) + "}"


def independent(raw: bytes):
    """(the reader's verdict in authz's vocabulary, canonical bytes or None)."""
    try:
        rd = Reader(raw)
        v = rd.read()
    except (ValueError, UnicodeDecodeError, IndexError):
        return "not-json", None
    for kind in ("duplicate-key", "unsafe-integer", "float"):
        if kind in rd.notes:
            return kind, None
    return None, write_canonical(v).encode("utf-8")


# ----------------------------------------------------------------------- the vectors first


@pytest.mark.parametrize("name", sorted(REQ))
def test_each_request_vector_agrees_with_an_independent_reader(name):
    raw = (HERE / "requests" / name).read_bytes()
    v = REQ[name]
    assert receipts.sha256_ref(raw) == v["raw_sha256"], "the file on disk is not the vector"
    amb, canon = independent(raw)
    assert amb == v["ambiguous"], (name, amb)
    if canon is not None:
        assert canon.decode("utf-8") == v["canonical_bytes"]
        assert receipts.sha256_ref(canon) == v["canonical_digest"]
    else:
        assert v["canonical_digest"] is None


def test_the_vectors_cover_each_ambiguity_and_each_equivalence():
    kinds = {v["ambiguous"] for v in REQ.values()}
    assert set(authz.AMBIGUITIES) | {None} <= kinds
    canon = REQ["canonical.json"]["canonical_digest"]
    same = [n for n, v in REQ.items() if v["canonical_digest"] == canon]
    assert {"canonical.json", "whitespace.json", "escaped.json"} <= set(same)
    assert len({REQ[n]["raw_sha256"] for n in same}) == len(same), "equivalents differ in bytes"


# ----------------------------------------------------------------------- authz against them


@pytest.mark.parametrize("name", sorted(REQ))
def test_ambiguous_and_binding_digest_match_the_vectors(name):
    raw = (HERE / "requests" / name).read_bytes()
    v = REQ[name]
    assert authz.ambiguous(raw) == v["ambiguous"]
    assert authz.binding_digest(raw, authz.RAW) == v["raw_sha256"]
    if v["ambiguous"] is None:
        assert authz.binding_digest(raw, authz.CANONICAL) == v["canonical_digest"]
        assert authz.canonical_bytes(raw).decode("utf-8") == v["canonical_bytes"]
    else:
        with pytest.raises(authz.NotBindable) as e:
            authz.binding_digest(raw, authz.CANONICAL)
        assert e.value.reason == v["ambiguous"]
    if v["lenient_digest"] is not None:
        assert authz.lenient_digest(raw) == v["lenient_digest"]


def test_the_lenient_digest_of_an_ambiguous_request_is_one_reading_of_it():
    """What a sloppy A signs for the duplicate-key fixture is the last member's reading; a B
    that parses the same way agrees with it, which is why only refusing the input is safe."""
    raw = (HERE / "requests" / "duplicate-key.json").read_bytes()
    last = b'{"amount":9900,"items":["sku-1"],"recipient":"acct-1234@example.test","ref":"r-0002"}'
    assert authz.lenient_digest(raw) == receipts.sha256_ref(last)


@pytest.mark.parametrize("name", sorted(AUTH["vectors"]))
def test_verify_authorisation_matches_the_vectors(name):
    pinned = {k: bytes.fromhex(v) for k, v in AUTH["pinned"].items()}
    v = AUTH["vectors"][name]
    got = authz.verify_authorisation(v["token"], pinned)
    assert (got.ok, got.reason) == (v["ok"], v["reason"]), got.detail


def test_round_trip_and_claims_shape():
    key = receipts.Keypair.generate("a-authz-test")
    raw = (HERE / "requests" / "canonical.json").read_bytes()
    claims = authz.authorisation_claims(
        issuer="did:web:a.example",
        audience={"counterparty": "did:web:b.example", "endpoint": "orders", "tenant": None},
        operation="crm.record.push", binding=authz.exact_binding(raw), max_uses=1,
        not_before=authz.utc(1_700_000_000), not_after=authz.utc(1_700_000_900),
        decision_digest=None)
    tok = authz.sign_authorisation(claims, key)
    got = authz.verify_authorisation(tok, {key.kid: key.public_bytes()})
    assert got.ok and got.claims == claims
    assert got.claims["binding"]["request_digest"] == REQ["canonical.json"]["canonical_digest"]
    assert authz.claims_of(tok) == claims
    unsigned = authz.verify_authorisation(authz.unsigned_authorisation(claims),
                                          {key.kid: key.public_bytes()})
    assert unsigned.reason == "unsigned"


def test_authorisation_ids_come_from_the_operating_system_not_a_seed():
    """KRK-M36: two runs with one seed must never present the same id. The id is drawn by
    `secrets`, so seeding Python's `random` changes nothing."""
    import random
    random.seed(7)
    a = authz.new_authorisation_id()
    random.seed(7)
    b = authz.new_authorisation_id()
    assert a != b and a.startswith("az-")


def test_extra_members_cannot_set_base_members():
    with pytest.raises(ValueError):
        authz.authorisation_claims(
            issuer="i", audience={"counterparty": "c"}, operation="o",
            binding=authz.class_binding({"x": 1}), max_uses=1, not_before=authz.utc(0),
            not_after=authz.utc(60), decision_digest=None, extra={"max_uses": 9})


def test_a_presentation_keeps_the_bytes_it_was_given():
    raw = (HERE / "requests" / "whitespace.json").read_bytes()
    p = authz.Presentation(pid="p1", endpoint="orders", tenant=None, request=bytearray(raw),
                           authorisation=None)
    assert p.request == raw and isinstance(p.request, bytes)
    with pytest.raises(TypeError):
        authz.Presentation(pid="p2", endpoint="orders", tenant=None, request="{}",
                           authorisation=None)
