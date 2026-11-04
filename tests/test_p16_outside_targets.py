"""P16's two hooks for outside targets: a wire profile in which B also states its receipt in
another format, and variants an adapter declares not applicable. No product is needed: these run
the kit's own toys and stub B, under a made-up example profile."""
import random

import pytest

pytest.importorskip("cryptography")

from conformance import counterparty, receipts  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import ALL  # noqa: E402
from conformance.properties.p16_effect_receipt import (  # noqa: E402
    B_KID, COUNTERPARTY, NA_FORBIDDEN, VARIANTS, build_case)
from conformance.result import Status  # noqa: E402
from known_bad.receipts_toys import make  # noqa: E402

SEED = 515151
EX = "example-receipt"
EX_MEMBERS = {"request_ref", "outcome_code", "outcome_items", "outcome_reason"}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _probe(toy, tag):
    toy.start()
    try:
        return ALL["P16"].probe(toy, Evidence("t", toy.name, "P16", tag), run_tag=tag, seed=SEED)
    finally:
        toy.stop()


def _answer(tmp_path, variant, profile):
    rng = random.Random(SEED)
    salt = rng.getrandbits(128).to_bytes(16, "big")
    key = receipts.Keypair.generate(B_KID)
    env, exp = build_case(receipts, rng, salt, variant, "t")
    b = counterparty.StubCounterparty(str(tmp_path / f"b-{variant}-{profile}.sqlite"), key, salt,
                                      counterparty_id=COUNTERPARTY, profile=profile)
    token, report = b.execute(env, exp, variant, rng=rng)
    return env, exp, key, token, report


def _claims(token):
    return receipts.verify_receipt(token, {}).claims or receipts._strict_json(
        receipts._b64d(token.split(".")[1]))


def test_without_a_profile_b_signs_only_the_kit_claims(tmp_path):
    _, _, _, token, _ = _answer(tmp_path, "honest", None)
    assert not EX_MEMBERS & set(_claims(token))


@pytest.mark.parametrize("variant,code", [("honest", "done"), ("count_mismatch", "done"),
                                          ("honest_partial", "done"),
                                          ("signed_refusal", "refused")])
def test_the_example_profile_states_what_b_logged(tmp_path, variant, code):
    env, exp, key, token, report = _answer(tmp_path, variant, EX)
    c = _claims(token)
    assert c["outcome_code"] == code
    # The reference is B's digest of the request it answered, in the profile's encoding.
    assert c["request_ref"] == counterparty.example_reference(c["request_digest"])
    if code == "refused":
        assert c["outcome_reason"] == c["refusal_reason"]
    else:
        o = c["outcome"]
        assert c["outcome_items"] == o["created"] + o["updated"] + o["deleted"]
    # The kit's own verdict on the same token is what it is without the profile.
    j = receipts.judge(token, pinned={key.kid: key.public_bytes()}, envelope=env, expected=exp,
                       executor_report=report)
    env2, exp2, key2, plain, report2 = _answer(tmp_path, variant, None)
    assert env2 == env
    k = receipts.judge(plain, pinned={key2.kid: key2.public_bytes()}, envelope=env2,
                       expected=exp2, executor_report=report2)
    assert (j.accept, j.status, j.reason) == (k.accept, k.status, k.reason)


def test_the_example_reference_is_the_request_digest_reencoded(tmp_path):
    env, _, _, token, _ = _answer(tmp_path, "honest", EX)
    import base64
    import hashlib
    want = base64.urlsafe_b64encode(hashlib.sha256(receipts.canonical_json(env)).digest())
    assert _claims(token)["request_ref"] == want.rstrip(b"=").decode()


def test_a_wrong_request_receipt_names_the_sibling_in_both_formats(tmp_path):
    env, _, _, token, _ = _answer(tmp_path, "wrong_request", EX)
    c = _claims(token)
    assert c["request_digest"] != receipts.request_digest(env)
    assert c["request_ref"] == counterparty.example_reference(c["request_digest"])


@pytest.mark.parametrize("variant", ["signed_no_record", "disputed_no_record"])
def test_a_no_record_has_no_example_form(tmp_path, variant):
    _, _, _, token, _ = _answer(tmp_path, variant, EX)
    assert not EX_MEMBERS & set(_claims(token))


def test_an_unknown_profile_is_refused(tmp_path):
    with pytest.raises(ValueError):
        counterparty.StubCounterparty(str(tmp_path / "b.sqlite"), receipts.Keypair.generate("k"),
                                      b"\0" * 16, profile="no-such-format")


def test_a_profile_may_not_overwrite_a_kit_claim(tmp_path, monkeypatch):
    monkeypatch.setitem(counterparty.PROFILES, "clash", lambda c: {"verdict": "executed"})
    with pytest.raises(ValueError, match="overwrite"):
        _answer(tmp_path, "honest", "clash")


def _adds_a_marker(claims):
    """A profile registered by a test: one member, from B's own verdict."""
    return {"test_marker": claims["verdict"]}


def test_an_adapter_registers_a_profile_and_b_signs_in_it(tmp_path, monkeypatch):
    """`register_profile` is how an adapter outside the kit adds the format its product reads;
    B then signs the added members exactly as for the kit's own example."""
    monkeypatch.setattr(counterparty, "PROFILES", dict(counterparty.PROFILES))
    counterparty.register_profile("test-marker", _adds_a_marker)
    counterparty.register_profile("test-marker", _adds_a_marker)      # imported twice: a no-op
    _, _, _, token, _ = _answer(tmp_path, "honest", "test-marker")
    c = _claims(token)
    assert c["test_marker"] == c["verdict"] == "executed"
    toy = make()
    toy.receipt_profile = lambda: "test-marker"
    r = _probe(toy, "registered")
    assert r.status is Status.PASS, r.summary
    assert r.extra["receipt_profile"] == "test-marker"


def test_register_profile_refuses_a_taken_name_a_blank_name_and_a_non_function(monkeypatch):
    monkeypatch.setattr(counterparty, "PROFILES", dict(counterparty.PROFILES))
    with pytest.raises(ValueError, match="already registered"):
        counterparty.register_profile(EX, _adds_a_marker)
    with pytest.raises(ValueError, match="name"):
        counterparty.register_profile("", _adds_a_marker)
    with pytest.raises(ValueError, match="not callable"):
        counterparty.register_profile("test-x", {"a": 1})
    assert counterparty.PROFILES[EX] is counterparty._example_receipt


def test_the_correct_toy_still_passes_under_a_profile():
    toy = make()
    toy.receipt_profile = lambda: EX
    r = _probe(toy, "profile")
    assert r.status is Status.PASS, r.summary
    assert r.extra["receipt_profile"] == EX


def test_a_declared_variant_is_recorded_not_applicable_and_not_driven():
    toy = make()
    toy.variants_not_applicable = lambda: {"signed_no_record": "the product has no such verdict"}
    r = _probe(toy, "na")
    assert r.status is Status.PASS
    c = {c.name: c for c in r.checks}["signed_no_record"]
    assert (c.outcome, c.ok) == ("not_applicable", None)
    assert "signed_no_record" not in r.extra["counts"]


def test_not_applicable_can_hide_a_fail_so_it_is_information_only():
    """The reason this hook is restricted: declaring both count variants away turns a target that
    ignores counts into one that passes. A declaration is never a pass for that variant."""
    toy = make("ignores_counts")
    assert _probe(toy, "plain").status is Status.FAIL
    toy = make("ignores_counts")
    toy.variants_not_applicable = lambda: {v: "no counts" for v in ("count_mismatch",
                                                                    "honest_partial")}
    r = _probe(toy, "hidden")
    assert r.status is Status.PASS
    assert {c.name for c in r.checks if c.outcome == "not_applicable"} == {"count_mismatch",
                                                                            "honest_partial"}
    assert all(c.ok is None for c in r.checks if c.outcome == "not_applicable")


@pytest.mark.parametrize("variant", NA_FORBIDDEN)
def test_the_control_and_the_verification_variants_cannot_be_declared_away(variant):
    toy = make("no_receipt_check")
    toy.variants_not_applicable = lambda: {variant: "said to be absent"}
    r = _probe(toy, f"forbidden-{variant}")
    assert r.status is Status.INCONCLUSIVE
    assert "may not be" in r.summary


def test_a_declaration_needs_a_reason_and_a_real_variant():
    toy = make()
    toy.variants_not_applicable = lambda: {"signed_refusal": "  "}
    assert _probe(toy, "blank").status is Status.INCONCLUSIVE
    toy = make()
    toy.variants_not_applicable = lambda: {"no_such_variant": "x"}
    assert _probe(toy, "unknown").status is Status.INCONCLUSIVE
    assert set(NA_FORBIDDEN) <= set(VARIANTS) | {"honest"}


def test_an_unknown_profile_gives_no_verdict():
    toy = make()
    toy.receipt_profile = lambda: "no-such-format"
    assert _probe(toy, "badprofile").status is Status.INCONCLUSIVE
