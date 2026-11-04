"""P18 (KRK-18) against its known-bad fixtures: the correct B passes, each flawed B fails on
exactly the variants its flaw is about, ``no_check`` (which executes whatever arrives) fails
rather than giving no verdict, and a B whose executor never reaches the recorder gives no
verdict. The role-A family the same way. This is the `make test` gate for P18 and the required
outcomes the known-bad gate records."""
import pytest

pytest.importorskip("cryptography")

from conformance import authz, counterparty, receipts, requester  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import ALL  # noqa: E402
from conformance.properties import p18_payload_bound as p18  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad.binding_toys import (A_FLAWS, FLAWS, ToyBinding, ToyRequesterA,  # noqa: E402
                                    make, make_a)

SEED = 515151

FAILS = {
    "signature_only": {"body_changed", "split_undeclared", "duplicate_key", "number_precision",
                       "unicode_fold"},
    "header_recipient": {"unbound_member"},
    "last_key_wins": {"duplicate_key"},
    "float_amounts": {"number_precision"},
    "nfkc_before_check": {"unicode_fold"},
    "accepts_scope": {"class_for_exact"},
    "no_memory": {"replay_after_answer", "retry_after_lost_answer", "replay_new_key",
                  "replay_after_restart", "replay_after_failover", "race_same",
                  "crash_between_use_and_effect"},
    "duplicate_as_refusal": {"replay_after_answer", "retry_after_lost_answer", "replay_new_key",
                             "replay_after_restart", "replay_after_failover", "race_same"},
    "dedupes_on_client_key": {"replay_new_key"},
    "memory_only": {"replay_after_restart", "replay_after_failover"},
    "per_replica_memory": {"replay_after_failover"},
    "per_endpoint_memory": {"replay_other_endpoint"},
    "ignores_tenant": {"replay_other_tenant"},
    "ignores_audience": {"replay_other_counterparty"},
    "check_then_set": {"race_same", "crash_between_use_and_effect"},
    "accepts_subset": {"split_undeclared"},
    "parts_and_whole": {"split_declared"},
    "ignores_not_after": {"expired"},
    "forgets_before_expiry": {"validity_beyond_memory"},
    "consumes_on_refusal": {"refused_then_retry"},
    "effect_before_mark": {"crash_between_use_and_effect"},
    "mark_before_effect_says_done": {"crash_between_use_and_effect"},
    "matches_by_shape": {"mapping_undeclared"},
}
"""The variants each role-B flaw fails, and no others."""
OUTCOME = {"duplicate_as_refusal": "denied_done", "mark_before_effect_says_done": "claims_done",
           "consumes_on_refusal": "consumed_by_refusal", "per_endpoint_memory":
           "ran_wrong_audience", "ignores_not_after": "ran_expired", "accepts_scope":
           "ran_under_class", "last_key_wins": "ran_ambiguous", "matches_by_shape":
           "ran_without_basis"}
"""For flaws with one characteristic outcome: the outcome of every check they fail."""
A_FAILS = {"no_authorisation": {"authorisation_present"}, "rebuilds_on_retry": {"retry_same"},
           "reuses_id": {"fresh_per_decision", "one_audience"},
           "any_audience": {"one_audience"},
           "duplicate_as_not_executed": {"honours_duplicate"},
           "refusal_as_outcome": {"retry_same", "record_matches_effect"}}

_CACHE = {}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(toy, tag="t", seed=SEED):
    toy.start()
    try:
        return ALL["P18"].probe(toy, Evidence("t", toy.name, "P18", tag), run_tag=tag, seed=seed)
    finally:
        toy.stop()


def _cached(key, build, seed=SEED):
    if (key, seed) not in _CACHE:
        _CACHE[(key, seed)] = _run(build(), tag=str(key), seed=seed)
    return _CACHE[(key, seed)]


def _failed(r):
    return {c.name for c in r.checks if c.ok is False}


def test_p18_is_registered_and_declares_its_fixtures():
    assert ALL["P18"] is p18 and p18.ID == "P18"
    assert "known_bad/binding_toys.py" in p18.FIXTURES
    assert set(FAILS) == set(FLAWS) and set(A_FAILS) == set(A_FLAWS)
    assert p18.VARIANTS == requester.VARIANTS
    assert set(p18.NA_FORBIDDEN) - {p18.CONTROL} <= set(p18.VARIANTS)


def test_every_variant_has_a_toy_that_fails_it():
    failed = set().union(*FAILS.values())
    honest = {"noncanonical_equivalent", "translated_declared"}
    assert failed | honest == set(p18.VARIANTS), set(p18.VARIANTS) - failed - honest


@pytest.mark.parametrize("seed", [SEED, 1, 2])
def test_the_correct_b_passes_every_variant(seed):
    r = _cached("good", make, seed)
    assert r.status is Status.PASS, (r.summary, _failed(r))
    names = {c.name: c for c in r.checks}
    assert set(p18.VARIANTS) == set(names)
    assert all(c.ok is True for c in r.checks if c.name != "crash_between_use_and_effect"), \
        [(c.name, c.outcome) for c in r.checks if c.ok is not True]
    # A careful B that crashes between its use record and its effect cannot know whether the
    # effect went out; it answers in-progress and never says done (liveness, not safety).
    assert names["crash_between_use_and_effect"].outcome == "stuck"
    assert r.extra["evidence_grade"] == "recorder" and r.extra["disclosure"] == "conformance"


@pytest.mark.parametrize("flaw", sorted(FAILS))
def test_each_flaw_fails_exactly_its_variants(flaw):
    r = _cached(flaw, lambda: make(flaw))
    assert r.status is Status.FAIL and r.control_held is True, r.summary
    assert _failed(r) == FAILS[flaw], sorted(_failed(r))
    if flaw in OUTCOME:
        assert {c.outcome for c in r.checks if c.ok is False} == {OUTCOME[flaw]}
    assert r.extra["disclosure"] in ("vulnerability", "conformance")


def test_a_b_that_executes_whatever_arrives_fails_and_is_not_inconclusive():
    """The control demands nothing the guarantee demands (KRK-M19): a B with no checks at all
    passes it, then fails the variants."""
    r = _cached("bad", lambda: ToyBinding("bad"))
    assert r.status is Status.FAIL and r.control_held is True, r.summary
    assert {"body_changed", "replay_after_answer", "race_same", "expired",
            "replay_other_counterparty", "duplicate_key"} <= _failed(r)
    assert r.extra["disclosure"] == "vulnerability"


def test_a_b_whose_executor_never_reaches_the_recorder_gives_no_verdict():
    r = _cached("no-control", lambda: ToyBinding("no-control"))
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary


def test_a_variant_that_may_not_be_declared_not_applicable_gives_no_verdict():
    toy = make()
    toy.variants_not_applicable = lambda: {"race_same": "our product is single-threaded"}
    r = _run(toy, "na")
    assert r.status is Status.INCONCLUSIVE and "may not be" in r.summary


def test_an_allowed_not_applicable_is_information_never_a_pass():
    toy = make()
    toy.variants_not_applicable = lambda: {"replay_after_failover": "one instance; no failover "
                                                                    "is documented"}
    r = _run(toy, "na-ok")
    c = next(c for c in r.checks if c.name == "replay_after_failover")
    assert c.outcome == "not_applicable" and c.ok is None and r.status is Status.PASS


def test_no_restart_hook_leaves_replay_after_restart_not_driven_and_no_pass():
    r = _run(_NoRestart(), "norestart")
    c = next(c for c in r.checks if c.name == "replay_after_restart")
    assert c.outcome == "not_driven" and r.status is Status.INCONCLUSIVE
    assert "replay_after_restart" in r.summary


class _NoRestart(ToyBinding):
    """The correct toy with no restart hook at all."""

    def __getattribute__(self, name):
        if name == "restart":
            raise AttributeError(name)
        return super().__getattribute__(name)


def test_at_the_b_answer_grade_counting_variants_get_no_verdict():
    """B's answer alone gives verdicts on refusal variants only."""
    r = _run(make(grade="B-answer"), "answer")
    by = {c.name: c for c in r.checks}
    for v in p18.COUNTING:
        assert by[v].outcome == "not_driven" and by[v].ok is None, v
    assert by["body_changed"].ok is not None
    assert r.status is Status.INCONCLUSIVE, r.summary   # race_same and friends must land


# ----------------------------------------------------------------------- the role-A family


def test_the_correct_a_passes_every_role_a_check():
    r = _cached("a-good", make_a)
    assert r.status is Status.PASS, (r.summary, _failed(r))
    assert [c.name for c in r.checks] == list(p18.A_CHECKS)
    assert r.extra["role"] == "A"


@pytest.mark.parametrize("flaw", sorted(A_FAILS))
def test_each_role_a_flaw_fails_exactly_its_checks(flaw):
    r = _cached(f"a-{flaw}", lambda: make_a(flaw))
    assert r.status is Status.FAIL and r.control_held is True, r.summary
    assert _failed(r) == A_FAILS[flaw]


def test_a_role_a_target_that_never_reaches_b_gives_no_verdict():
    r = _cached("a-no-control", lambda: ToyRequesterA("no-control"))
    assert r.status is Status.INCONCLUSIVE


# ----------------------------------------------------------------------- the strict stub B


def _strict(tmp_path, repeat="original", requester_keys=None):
    key = receipts.Keypair.generate("b")
    b = counterparty.StubCounterparty(str(tmp_path / "b.sqlite"), key, bytes(16),
                                      single_use=True, repeat_answer=repeat,
                                      requester_keys=requester_keys)
    items = ["a@x.test", "b@x.test"]
    exp = receipts.ExpectedEffect(operation="crm.record.push", counterparty="did:web:b.example",
                                  container="people", verbs=("upsert",), count=2,
                                  items_digest=receipts.items_digest(bytes(16), items))
    env = counterparty.make_envelope("c-1", exp, items, requester="did:web:a.example")
    b.expect("c-1", exp)
    return b, env, exp, key


def test_the_strict_stub_b_answers_a_repeat_once_and_refuses_another_body(tmp_path):
    import random
    rng = random.Random(1)
    b, env, exp, key = _strict(tmp_path)
    raw = receipts.canonical_json(env)
    first = b.receive(raw, None, {}, rng=rng)
    again = b.receive(raw, None, {}, rng=rng)
    assert first["answer"] == "executed" and again == {**again, "answer": "original"}
    assert again["receipt"] == first["receipt"]
    other = receipts.canonical_json(dict(env, extra=1))
    refused = b.receive(other, None, {}, rng=rng)
    assert refused["answer"] == "refused" and refused["code"] == "authorisation-reused"
    v = receipts.verify_receipt(refused["receipt"], {key.kid: key.public_bytes()})
    assert v.claims["verdict"] == "refused" and v.claims["refusal_reason"] == "authorisation-reused"
    assert b.store_counts("c-1")["written"] == 2
    assert [r["answer"] for r in b.received_requests] == ["executed", "original", "refused"]


def test_the_strict_stub_b_keys_on_the_authorisation_id_when_one_is_presented(tmp_path):
    import random
    a = receipts.Keypair.generate("a")
    b, env, exp, _ = _strict(tmp_path, repeat="duplicate",
                             requester_keys={a.kid: a.public_bytes()})
    raw = receipts.canonical_json(env)

    def tok():
        c = authz.authorisation_claims(
            issuer="did:web:a.example", audience={"counterparty": "did:web:b.example"},
            operation="crm.record.push", binding=authz.exact_binding(raw), max_uses=1,
            not_before=authz.utc(0), not_after=authz.utc(4_000_000_000), decision_digest=None)
        return authz.sign_authorisation(c, a)
    t1, t2 = tok(), tok()
    rng = random.Random(2)
    assert b.receive(raw, t1, {}, rng=rng)["answer"] == "executed"
    assert b.receive(raw, t1, {}, rng=rng)["answer"] == "duplicate"
    assert b.receive(raw, t2, {}, rng=rng)["answer"] == "executed"   # a new authorisation
    assert b.received_requests[0]["authorisation_verified"] is True


def test_strict_mode_is_off_by_default_and_changes_nothing_for_p16(tmp_path):
    key = receipts.Keypair.generate("b")
    b = counterparty.StubCounterparty(str(tmp_path / "b.sqlite"), key, bytes(16))
    with pytest.raises(RuntimeError):
        b.receive(b"{}", rng=__import__("random").Random(0))


# ----------------------------------------------------------------------- record_matches_effect


def test_a_record_that_reads_a_repeat_refusal_as_the_outcome_fails_and_a_disputed_one_passes():
    r = _cached("a-careful", lambda: _careful())
    got = {c.name: (c.outcome, c.ok) for c in r.checks}
    assert got["record_matches_effect"] == ("disputed_held", True)
    assert _failed(r) == {"retry_same"}             # the bytes still change; the record is honest
    bad = {c.name: c for c in _cached("a-refusal_as_outcome",
                                      lambda: make_a("refusal_as_outcome")).checks}
    assert bad["record_matches_effect"].outcome == "contradicts_effect"
    assert _cached("a-refusal_as_outcome",
                   lambda: make_a("refusal_as_outcome")).extra["disclosure"] == "conformance"
    assert "refusal of a repeat was read as the outcome" in bad["record_matches_effect"].detail


def _careful():
    toy = make_a("refusal_as_outcome")
    toy.careful_reading = True
    return toy


def test_a_requester_without_an_outcome_reading_is_information_never_a_pass():
    toy = make_a()
    toy.outcome = None
    r = _run(toy, tag="a-no-outcome")
    c = next(c for c in r.checks if c.name == "record_matches_effect")
    assert (c.outcome, c.ok) == ("not_readable", None)
    assert r.control_held is True                   # the control asks nothing of it (KRK-M19)


@pytest.mark.parametrize("said,did,answers,want", [
    ("done", True, ["original"], ("agrees", True)),
    ("not-done", False, ["refused"], ("agrees", True)),
    ("not-done", True, ["refused"], ("contradicts_effect", False)),
    ("done", False, ["executed"], ("contradicts_effect", False)),       # the reverse
    ("disputed", True, ["refused"], ("disputed_held", True)),
    ("disputed", False, ["original"], ("disputed_held", True)),
    ("disputed", True, ["original"], ("disputed_without_conflict", None)),
    ("open", True, ["duplicate"], ("left_open", None)),
    ({"outcome": "done", "product": {"effect": "executed"}}, True, ["original"],
     ("agrees", True)),
    ("refused", True, ["refused"], ("unreadable", None)),
    (None, True, ["refused"], ("not_readable", None)),
    ({"error": "outcome raised KeyError"}, True, [], ("not_readable", None)),
])
def test_record_check_grades_each_reading(said, did, answers, want):
    c = p18.record_check(said, {"performed": did, "executed_requests": int(did),
                                "written": 3 * int(did)}, answers)
    assert (c.outcome, c.ok) == want, c.detail
