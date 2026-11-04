"""KRK-16 receipts and the stub counterparty, checked against fixed vectors and an independent
JWS implementation (PyJWT), and the counterparty's receipts checked against its own store."""
import base64
import hashlib
import json
import random
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from conformance import counterparty as cp
from conformance import receipts as r

VEC = Path(__file__).resolve().parent / "vectors" / "krk16"
KEYS = json.loads((VEC / "keys.json").read_text())
CANON = json.loads((VEC / "canonical.json").read_text())
VERIFY = json.loads((VEC / "verify.json").read_text())
JUDGE = json.loads((VEC / "judge.json").read_text())
PINNED = {k: bytes.fromhex(v) for k, v in VERIFY["pinned"].items()}
B = r.Keypair.from_seed(KEYS["b"]["kid"], bytes.fromhex(KEYS["b"]["seed"]))
SALT = bytes.fromhex(KEYS["salt"])


def _expected(doc):
    return r.ExpectedEffect(**{**doc, "verbs": tuple(doc["verbs"])})


def _payload(token):
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def _header(token):
    seg = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


# --------------------------------------------------------------------------- keys


@pytest.mark.parametrize("t", KEYS["rfc8032"], ids=lambda t: t["name"])
def test_keypair_from_seed_matches_rfc8032(t):
    k = r.Keypair.from_seed("x", bytes.fromhex(t["secret"]))
    assert k.public_bytes().hex() == t["public"]
    assert k.private.sign(bytes.fromhex(t["message"])).hex() == t["signature"]


def test_generated_keys_differ_and_are_32_bytes():
    a, b = r.Keypair.generate("a"), r.Keypair.generate("b")
    assert len(a.public_bytes()) == 32 and a.public_bytes() != b.public_bytes()
    assert "private" not in repr(a)


# --------------------------------------------------------------------------- canonical JSON


@pytest.mark.parametrize("v", CANON, ids=lambda v: v["name"])
def test_canonical_json_matches_hand_written_jcs(v):
    out = r.canonical_json(v["value"])
    assert out == v["canonical"].encode("utf-8")
    assert r.sha256_ref(out) == v["sha256"] == "sha256:" + hashlib.sha256(out).hexdigest()


def test_canonical_json_ignores_insertion_order():
    a = {"z": 1, "a": {"y": 2, "b": [1, {"d": 1, "c": 2}]}}
    b = {"a": {"b": [1, {"c": 2, "d": 1}], "y": 2}, "z": 1}
    assert r.canonical_json(a) == r.canonical_json(b)
    assert r.canonical_json([1, 2]) != r.canonical_json([2, 1])  # list order is meaning


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 1.5, 1.0,
                                   2 ** 53, -(2 ** 53), {1: "a"}, {"é": 1}, {"a": {1, 2}},
                                   b"bytes", {"s": "\ud800"}],
                         ids=["nan", "inf", "-inf", "float", "float-integral", "2^53", "-2^53",
                              "int-key", "non-ascii-key", "set", "bytes", "lone-surrogate"])
def test_canonical_json_refuses_values_jcs_cannot_reproduce(value):
    with pytest.raises((ValueError, TypeError)):
        r.canonical_json(value)


# --------------------------------------------------------------------------- digests


def test_digests_are_stable_against_the_vectors():
    exp = _expected(JUDGE["expected_effect"])
    assert r.request_digest(JUDGE["envelope"]) == JUDGE["request_digest"]
    assert exp.digest() == JUDGE["expected_effect_digest"]
    assert r.items_digest(SALT, JUDGE["items"]) == JUDGE["expected_effect"]["items_digest"]


def test_items_digest_is_order_independent_and_salted():
    keys = JUDGE["items"]
    assert r.items_digest(SALT, keys) == r.items_digest(SALT, list(reversed(keys)))
    assert r.items_digest(SALT, keys) != r.items_digest(b"\x01" * 16, keys)
    assert r.items_digest(SALT, keys) != r.items_digest(SALT, keys[:-1])
    plain = "sha256:" + hashlib.sha256(keys[0].encode()).hexdigest()
    assert r.item_key_hash(SALT, keys[0]) != plain
    assert r.item_key_hash(SALT, keys[0]) == "sha256:" + hashlib.sha256(SALT + keys[0].encode()).hexdigest()


def test_items_digest_refuses_short_salt_and_duplicate_keys():
    with pytest.raises(ValueError):
        r.item_key_hash(b"short", "a")
    with pytest.raises(ValueError):
        r.items_digest(SALT, ["a", "b", "a"])


def test_expected_effect_normalises_verbs_and_validates():
    d = JUDGE["expected_effect"]
    a = r.ExpectedEffect(**{**d, "verbs": ("update", "create")})
    b = r.ExpectedEffect(**{**d, "verbs": ["create", "update", "create"]})
    assert a.verbs == ("create", "update") and a.digest() == b.digest()
    assert a.digest() != r.ExpectedEffect(**{**d, "verbs": ("create",)}).digest()
    assert a.digest() != r.ExpectedEffect(**{**d, "verbs": ("create", "update"), "count": 5}).digest()
    for bad in ({"verbs": ("send",)}, {"verbs": ()}, {"verbs": "create"}, {"count": -1},
                {"count": True}, {"items_digest": "abc"}, {"container": ""}):
        with pytest.raises((ValueError, TypeError)):
            r.ExpectedEffect(**{**d, "verbs": ("upsert",), **bad})


# --------------------------------------------------------------------------- verify


@pytest.mark.parametrize("case", VERIFY["cases"], ids=lambda c: c["name"])
def test_verify_vectors(case):
    v = r.verify_receipt(case["token"], PINNED)
    assert {"ok": v.ok, "reason": v.reason, "kid": v.kid} == case["expect"], v.detail
    assert (v.claims is not None) == v.ok


def test_every_verify_reason_has_a_vector():
    reasons = {c["expect"]["reason"] for c in VERIFY["cases"]}
    assert reasons == {None, *r.VERIFY_REASONS}


def test_signing_is_byte_stable():
    good = next(c["token"] for c in VERIFY["cases"] if c["name"] == "ok")
    assert r.sign_receipt(_payload(good), B) == good


def test_verify_never_accepts_a_token_that_is_not_a_string():
    for t in (None, b"a.b.c", 1, ["a", "b", "c"]):
        assert r.verify_receipt(t, PINNED).reason == "malformed"


def test_verify_refuses_a_misconfigured_pin_instead_of_failing_the_token():
    good = next(c["token"] for c in VERIFY["cases"] if c["name"] == "ok")
    with pytest.raises(ValueError):
        r.verify_receipt(good, {KEYS["b"]["kid"]: b"\x00" * 31})


def test_verify_with_nothing_pinned_refuses():
    good = next(c["token"] for c in VERIFY["cases"] if c["name"] == "ok")
    assert r.verify_receipt(good, {}).reason == "unpinned-key"


def test_pyjwt_verifies_what_we_sign():
    good = next(c["token"] for c in VERIFY["cases"] if c["name"] == "ok")
    pub = Ed25519PublicKey.from_public_bytes(PINNED[KEYS["b"]["kid"]])
    out = jwt.api_jws.PyJWS().decode_complete(good, key=pub, algorithms=["EdDSA"])
    assert out["header"] == {"alg": "EdDSA", "kid": KEYS["b"]["kid"], "typ": r.TYP}
    assert out["payload"] == r.canonical_json(_payload(good))


def test_we_verify_what_pyjwt_signs_and_refuse_what_pyjwt_refuses():
    good = next(c["token"] for c in VERIFY["cases"] if c["name"] == "ok")
    claims = _payload(good)
    tok = jwt.api_jws.PyJWS().encode(r.canonical_json(claims), B.private, algorithm="EdDSA",
                                     headers={"kid": B.kid, "typ": r.TYP})
    v = r.verify_receipt(tok, PINNED)
    assert v.ok and v.claims == claims
    pub = Ed25519PublicKey.from_public_bytes(PINNED[B.kid])
    for case in VERIFY["cases"]:
        if case["expect"]["reason"] in ("bad-signature", "unsigned"):
            with pytest.raises(jwt.exceptions.PyJWTError):
                jwt.api_jws.PyJWS().decode_complete(case["token"], key=pub, algorithms=["EdDSA"])


# --------------------------------------------------------------------------- judge


@pytest.mark.parametrize("case", JUDGE["cases"], ids=lambda c: c["name"])
def test_judge_vectors(case):
    j = r.judge(case["token"], pinned=PINNED, envelope=JUDGE["envelope"],
                expected=_expected(JUDGE["expected_effect"]), executor_report=case["executor_report"])
    assert {"accept": j.accept, "status": j.status, "grade": j.grade, "reason": j.reason} == \
        case["expect"], j.detail


def test_every_judge_outcome_has_a_vector():
    seen = {(c["expect"]["status"], c["expect"]["reason"]) for c in JUDGE["cases"]}
    for reason in ("wrong-request", "expected-mismatch", "count-mismatch", "partial",
                   "items-mismatch", *r.VERIFY_REASONS):
        assert ("blocked", reason) in seen, reason
    assert {("done", None), ("refused", "refused"), ("awaiting-receipt", "no-receipt"),
            ("awaiting-receipt", "executor-report-only"), ("not-executed", "no-record"),
            ("blocked", "no-record-disputed")} <= seen


def test_only_done_is_accepted_and_only_with_signed_grade():
    for c in JUDGE["cases"]:
        e = c["expect"]
        assert e["accept"] == (e["status"] == "done")
        assert (e["grade"] == "signed-by-B") == e["accept"]


# --------------------------------------------------------------------------- counterparty


N_CASES = 40


def _fixture(tmp_path, seed, verbs=("upsert",), name="b.db", n=None):
    rng = random.Random(seed)
    n = rng.randint(50, 400) if n is None else n
    items = [f"person-{i}-{rng.getrandbits(32):08x}@a.example" for i in range(n)]
    exp = r.ExpectedEffect("crm.record.push", "did:web:b.example", "people", verbs, n,
                           r.items_digest(SALT, items))
    env = cp.make_envelope(f"case-{seed}:{rng.getrandbits(32):08x}", exp, items)
    b = cp.StubCounterparty(str(tmp_path / name), B, SALT)
    return rng, b, env, exp


EXPECT_JUDGE = {  # variant -> (status, reason) that judge gives
    "honest": ("done", None),
    "wrong_request": ("blocked", "wrong-request"),
    "unsigned": ("blocked", "unsigned"),
    "unpinned_key": ("blocked", "unpinned-key"),
    "count_mismatch": ("blocked", "count-mismatch"),
    "honest_partial": ("blocked", "partial"),
    "missing": ("awaiting-receipt", "no-receipt"),
    "agent_report": ("awaiting-receipt", "executor-report-only"),
    "signed_refusal": ("refused", "refused"),
    "signed_no_record": ("not-executed", "no-record"),
    "disputed_no_record": ("blocked", "no-record-disputed"),
    "sibling_request": ("blocked", "wrong-request"),
}


def _earlier(env, exp, variant):
    """A's own earlier request for `sibling_request`: same items and expectation."""
    if variant not in cp.REPLAYS:
        return None
    return cp.make_envelope(env["correlation_id"] + "/earlier", exp, env["items"])


def test_variant_table_covers_every_variant():
    assert set(EXPECT_JUDGE) == set(cp.VARIANTS)


@pytest.mark.parametrize("variant", cp.VARIANTS)
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_variant_store_against_receipt(tmp_path, variant, seed):
    rng, b, env, exp = _fixture(tmp_path, seed)
    n = exp.count
    pinned = dict([b.public_key()])
    earlier = _earlier(env, exp, variant)
    token, report = b.execute(env, exp, variant, rng=rng, earlier=earlier)
    store = b.store_counts(env["correlation_id"])
    want_status, reason = EXPECT_JUDGE[variant]

    j = r.judge(token, pinned=pinned, envelope=env, expected=exp, executor_report=report)
    assert (j.status, j.reason) == (want_status, reason), j.detail
    assert j.accept == (variant == "honest")
    assert (report is not None) == (variant in ("agent_report", "signed_no_record",
                                                "disputed_no_record"))
    if variant in ("agent_report", "disputed_no_record"):
        assert r.report_claims_success(report) and r.report_claims_sent(report)
    if variant == "signed_no_record":
        assert not r.report_claims_sent(report) and report["sent"] is False
    assert b.issued()[-1]["receipt"] == token

    if token is not None:
        # Whatever B signed, it signed genuinely: the token verifies under the key that made it,
        # so no signed byte was altered.
        own = {b.key.kid: b.key.public_bytes(), b.other_key.kid: b.other_key.public_bytes()}
        v = r.verify_receipt(token, own)
        assert v.ok == (variant != "unsigned")
        claims = _payload(token)
        assert r.claims_problem(claims) is None
        assert claims["counterparty"] == "did:web:b.example"
        assert claims["expected_effect_digest"] == exp.digest()
        # The receipt names the request's item set; counts carry what B committed.
        assert claims["items_digest"] == exp.items_digest

    if variant in ("honest", "unsigned", "unpinned_key", "missing", "agent_report",
                   "wrong_request", "sibling_request"):
        assert store["total"] == store["written"] == n and store["items_digest"] == exp.items_digest
    if variant in ("honest", "unsigned", "unpinned_key"):
        o = _payload(token)["outcome"]
        assert o == {"created": store["created"], "updated": store["updated"],
                     "deleted": store["deleted"], "failed": 0}
        assert _payload(token)["request_digest"] == r.request_digest(env)
        assert _payload(token)["correlation_id"] == env["correlation_id"]
    if variant == "unsigned":
        assert _header(token)["alg"] == "none" and token.endswith(".")
    if variant == "unpinned_key":
        assert _header(token)["kid"] not in pinned
        assert r.verify_receipt(token, {b.other_key.kid: b.other_key.public_bytes()}).ok
    if variant == "wrong_request":
        c = _payload(token)
        assert c["request_digest"] != r.request_digest(env)
        assert c["correlation_id"] != env["correlation_id"]
        sib = b.store_counts(c["correlation_id"])
        assert sib["total"] == n and sib["requests_logged"] == 1
        assert sum(c["outcome"][f] for f in ("created", "updated", "deleted")) == n
        assert c["outcome"] == {"created": sib["created"], "updated": sib["updated"],
                                "deleted": sib["deleted"], "failed": 0}
    if variant == "sibling_request":
        # B's genuine receipt for A's earlier request, sent as the answer to this one.
        c = _payload(token)
        assert c["correlation_id"] == earlier["correlation_id"]
        assert c["request_digest"] == r.request_digest(earlier) != r.request_digest(env)
        assert r.verify_receipt(token, pinned).ok
        assert r.judge(token, pinned=pinned, envelope=earlier, expected=exp,
                       executor_report=None).accept
        before = b.store_counts(earlier["correlation_id"])
        assert before["total"] == n and before["requests_logged"] == 1
        assert store["requests_logged"] == 1
        assert [e["variant"] for e in b.issued()] == ["honest", "sibling_request"]
        assert b.issued()[0]["receipt"] == token          # replayed exactly as signed
    if variant in ("count_mismatch", "honest_partial"):
        c = _payload(token)
        k = n - store["total"]
        assert 1 <= k <= cp.K_MAX
        assert store["items_digest"] != exp.items_digest
        assert c["outcome"]["created"] + c["outcome"]["updated"] + c["outcome"]["deleted"] == \
            store["total"]
        assert c["outcome"]["failed"] == (k if variant == "honest_partial" else 0)
        assert c["request_digest"] == r.request_digest(env)
    if variant in ("missing", "agent_report"):
        assert token is None
    if variant in ("signed_no_record", "disputed_no_record"):
        c = _payload(token)
        assert store["total"] == 0 and store["requests_logged"] == 1
        assert c["verdict"] == "no-record" and c["refuses_permanently"] is True
        assert c["refusal_reason"] is None and c["request_digest"] == r.request_digest(env)
        assert c["outcome"] == {"created": 0, "updated": 0, "deleted": 0, "failed": 0}
    if variant == "signed_refusal":
        c = _payload(token)
        assert store["total"] == 0 and store["requests_logged"] == 1
        assert c["verdict"] == "refused" and c["refusal_reason"]
        assert c["outcome"] == {"created": 0, "updated": 0, "deleted": 0, "failed": 0}


def _run_all(tmp_path, name, seed):
    out = {}
    for variant in cp.VARIANTS:
        rng, b, env, exp = _fixture(tmp_path, seed, name=f"{name}-{variant}.db")
        token, report = b.execute(env, exp, variant, rng=rng, earlier=_earlier(env, exp, variant))
        claims = _payload(token) if token else None
        if claims:
            claims.pop("executed_at")
        out[variant] = (b.store_counts(env["correlation_id"]), claims, report)
    return out


def test_same_seed_gives_same_counts(tmp_path):
    assert _run_all(tmp_path, "a", 11) == _run_all(tmp_path, "b", 11)


def test_k_is_drawn_not_fixed(tmp_path):
    ks = set()
    for seed in range(N_CASES):
        rng, b, env, exp = _fixture(tmp_path, seed, name=f"k-{seed}.db")
        b.execute(env, exp, "count_mismatch", rng=rng)
        ks.add(exp.count - b.store_counts(env["correlation_id"])["total"])
    assert len(ks) > 3 and ks <= set(range(1, cp.K_MAX + 1))


def test_upsert_updates_what_already_exists(tmp_path):
    rng, b, env, exp = _fixture(tmp_path, 5)
    first, _ = b.execute(env, exp, "honest", rng=rng)
    again = cp.make_envelope(env["correlation_id"] + "-again", exp, env["items"])
    second, _ = b.execute(again, exp, "honest", rng=rng)
    assert _payload(first)["outcome"]["created"] == exp.count
    assert _payload(second)["outcome"] == {"created": 0, "updated": exp.count, "deleted": 0,
                                           "failed": 0}
    assert _payload(second)["log_seq"] > _payload(first)["log_seq"]
    pinned = dict([b.public_key()])
    assert r.judge(second, pinned=pinned, envelope=again, expected=exp,
                   executor_report=None).status == "done"


@pytest.mark.parametrize("verbs,field", [(("create",), "created"), (("update",), "updated"),
                                         (("delete",), "deleted")])
def test_single_verbs(tmp_path, verbs, field):
    rng, b, env, exp = _fixture(tmp_path, 9, verbs=verbs)
    token, _ = b.execute(env, exp, "honest", rng=rng)
    assert _payload(token)["outcome"][field] == exp.count
    assert b.store_counts(env["correlation_id"])[field] == exp.count
    assert r.judge(token, pinned=dict([b.public_key()]), envelope=env, expected=exp,
                   executor_report=None).status == "done"


def test_none_verb_with_no_items(tmp_path):
    rng, b, env, exp = _fixture(tmp_path, 9, verbs=("none",), n=0)
    token, _ = b.execute(env, exp, "honest", rng=rng)
    assert b.store_counts(env["correlation_id"])["total"] == 0
    assert r.judge(token, pinned=dict([b.public_key()]), envelope=env, expected=exp,
                   executor_report=None).status == "done"


def test_stub_refuses_an_inconsistent_fixture(tmp_path):
    rng, b, env, exp = _fixture(tmp_path, 4)
    with pytest.raises(ValueError):
        b.execute({**env, "items": env["items"][:-1]}, exp, rng=rng)
    other = r.ExpectedEffect(exp.operation, exp.counterparty, exp.container, exp.verbs, exp.count,
                             r.items_digest(SALT, [i + "x" for i in env["items"]]))
    with pytest.raises(ValueError):
        b.execute(env, other, rng=rng)
    with pytest.raises(ValueError):
        b.execute({**env, "expected_effect_digest": "sha256:" + "0" * 64}, exp, rng=rng)
    with pytest.raises(ValueError):
        b.execute(env, exp, "forged", rng=rng)
    with pytest.raises(TypeError):
        b.execute(env, exp, rng=None)
    with pytest.raises(ValueError):
        b.execute({k: v for k, v in env.items() if k != "items"}, exp, rng=rng)
    assert b.store_counts(env["correlation_id"])["total"] == 0  # nothing written by a refusal


def test_sibling_request_needs_one_of_as_own_earlier_requests(tmp_path):
    rng, b, env, exp = _fixture(tmp_path, 7)
    earlier = _earlier(env, exp, "sibling_request")
    with pytest.raises(ValueError):                   # sibling_request without the earlier one
        b.execute(env, exp, "sibling_request", rng=rng)
    with pytest.raises(ValueError):                   # earlier= on a variant that replays nothing
        b.execute(env, exp, "wrong_request", rng=rng, earlier=earlier)
    with pytest.raises(ValueError):                   # the same request is not an earlier one
        b.execute(env, exp, "sibling_request", rng=rng, earlier=dict(env))
    with pytest.raises(ValueError):                   # other items: it would differ in more
        b.execute(env, exp, "sibling_request", rng=rng,
                  earlier={**earlier, "items": env["items"][:-1] + ["z@a.example"]})
    assert b.issued() == []


def test_sibling_request_replays_the_receipt_b_already_sent(tmp_path):
    """When B has already answered the earlier request, the replay is that token, unchanged,
    and B does not execute the earlier request again."""
    rng, b, env, exp = _fixture(tmp_path, 8)
    earlier = _earlier(env, exp, "sibling_request")
    first, _ = b.execute(earlier, exp, "honest", rng=rng)
    token, report = b.execute(env, exp, "sibling_request", rng=rng, earlier=earlier)
    assert token == first and report is None
    assert b.store_counts(earlier["correlation_id"])["requests_logged"] == 1


def test_the_sibling_vector_separates_binding_from_membership():
    """The fixed vector: a genuine receipt for A's earlier request. It is a matching receipt for
    that request and the wrong one for the current request; both are requests A made."""
    v = json.loads((VEC / "sibling.json").read_text())
    exp = _expected(v["expected_effect"])
    pinned = {k: bytes.fromhex(x) for k, x in v["pinned"].items()}
    for name, env in v["envelopes"].items():
        j = r.judge(v["token"], pinned=pinned, envelope=env, expected=exp, executor_report=None)
        assert {"accept": j.accept, "status": j.status, "grade": j.grade, "reason": j.reason} == \
            v["expect"][name], (name, j.detail)
    assert r.request_digest(v["envelopes"]["earlier"]) == v["request_digests"]["earlier"]
    assert r.request_digest(v["envelopes"]["current"]) == v["request_digests"]["current"]
    claims = _payload(v["token"])
    # Membership holds: the receipt names a request A made. Binding does not.
    assert claims["request_digest"] in v["request_digests"].values()
    assert claims["request_digest"] != v["request_digests"]["current"]
    # The stranger (wrong_request) vector's request is one A never made.
    stranger = next(c for c in JUDGE["cases"] if c["name"] == "wrong-request-sibling-digest")
    assert _payload(stranger["token"])["request_digest"] not in v["request_digests"].values()


def test_stub_reads_items_from_payload(tmp_path):
    rng, b, env, exp = _fixture(tmp_path, 6)
    env = {k: v for k, v in env.items() if k != "items"}
    env["payload"] = {"items": _fixture(tmp_path, 6, name="x.db")[2]["items"]}
    token, _ = b.execute(env, exp, rng=rng)
    assert r.judge(token, pinned=dict([b.public_key()]), envelope=env, expected=exp,
                   executor_report=None).accept
