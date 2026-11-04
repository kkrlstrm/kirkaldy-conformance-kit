"""P17 (KRK-17) against its known-bad fixtures: the correct toy passes, each flawed toy fails on
exactly the checks its flaw is about, and a toy whose control cannot hold gives no verdict. This
is the `make test` gate for P17, and the required outcomes the known-bad gate records."""
import pytest

pytest.importorskip("cryptography")

from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import ALL  # noqa: E402
from conformance.properties import p17_reconcilable_record as p17  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad.records_toys import FLAWS, ToyRecords, make  # noqa: E402

SEED = 515151

FAILS = {
    "reconciles_against_receipts": {"c:receipt_contradicts_log", "c:seq_duplicate"},
    "no_state_read": {"c:receipt_contradicts_state"},
    "walks_own_entries": {"c:unbacked_on_b", "c:compensating_pair"},
    "trusts_own_done": {"c:unbacked_on_a"},
    "counts_only": {"c:compensating_pair"},
    "joins_on_correlation_only": {"c:join_collision"},
    "incremental_only": {"c:b_edit_after_ack", "c:b_delete_after_ack", "c:seq_reorder"},
    "ignores_sequence": {"c:b_delete_after_ack", "c:seq_reorder"},
    "trusts_void": {"c:void_over_receipt"},
    "dedups_by_request": {"c:seq_duplicate"},
    "mutable_record": {"a_edit_after_ack"},
    "loses_entry_on_crash": {"torn_write", "c:torn_write"},
    "joins_by_time_window": {"c:clock_skew"},
    "settles_and_forgets": {"c:late_entry"},
    "matches_by_shape": {"c:basis_undeclared"},
    "record_settles_effect": {"e:b_edit_after_ack", "e:join_collision", "e:late_entry",
                              "e:receipt_contradicts_log", "e:receipt_contradicts_state",
                              "e:seq_duplicate", "e:unbacked_on_a", "e:void_over_receipt"},
}
"""The checks each flaw fails, and no others. The last two flaws fail every break variant.
`record_settles_effect` passes `e:compensating_pair`: there B never answered A's request, so the
case is not done whatever the toy makes of the settled break."""
BREAK_VARIANTS = {f"c:{v}" for v in p17.EXPECT if v not in p17.TAMPER_A}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(toy, tag="t", seed=SEED):
    toy.start()
    try:
        return ALL["P17"].probe(toy, Evidence("t", toy.name, "P17", tag), run_tag=tag, seed=seed)
    finally:
        toy.stop()


def _failed(r):
    return {c.name for c in r.checks if c.ok is False}


def test_p17_is_registered_and_declares_its_fixtures():
    assert ALL["P17"] is p17 and p17.ID == "P17"
    assert "known_bad/records_toys.py" in p17.FIXTURES
    assert set(FAILS) | {"overwrite_loser", "silent_break"} == set(FLAWS)


@pytest.mark.parametrize("seed", [SEED, 1, 2])
def test_the_correct_target_passes_every_check(seed):
    r = _run(make(), seed=seed)
    assert r.status is Status.PASS, (r.summary, _failed(r))
    names = {c.name for c in r.checks}
    assert {"join", "complete", "order"} <= names
    assert set(p17.VARIANTS) <= names and {f"c:{v}" for v in p17.VARIANTS} <= names
    assert (r.extra["grade_a"], r.extra["grade_b"]) == ("cross-held", "cross-held")
    assert all(c.ok is not None for c in r.checks if not c.name.startswith("c:a_"))


@pytest.mark.parametrize("flaw", sorted(FAILS))
def test_each_flaw_fails_exactly_its_checks(flaw):
    r = _run(make(flaw), tag=flaw)
    assert r.status is Status.FAIL and r.control_held is True, r.summary
    assert _failed(r) == FAILS[flaw], sorted(_failed(r))


@pytest.mark.parametrize("flaw, outcome", [("overwrite_loser", "overwrote"),
                                           ("silent_break", "found_silent")])
def test_a_flaw_in_settling_fails_every_break_variant(flaw, outcome):
    r = _run(make(flaw), tag=flaw)
    assert r.status is Status.FAIL
    got = {c.name: c.outcome for c in r.checks if c.name in BREAK_VARIANTS}
    # A break about B's numbering alone (a gap) names no entry of either side to overwrite, and
    # `late_entry` / `basis_undeclared` are read from states, so those three are not asked.
    asked = BREAK_VARIANTS - {"c:late_entry", "c:b_delete_after_ack", "c:basis_undeclared"}
    assert {n for n, o in got.items() if o == outcome} >= asked, got


def test_no_verdict_when_the_target_has_no_readable_record():
    r = _run(ToyRecords("no-control"))
    assert r.status is Status.INCONCLUSIVE and "control" in r.summary


def test_records_alone_pass_and_say_the_target_does_not_reconcile():
    """A target that keeps a reconcilable record and does not reconcile
    passes on the record checks, and its result says it does not reconcile."""
    toy = make()
    toy.reconciles = lambda: False
    r = _run(toy, tag="records-only")
    assert r.status is Status.PASS, (r.summary, _failed(r))
    assert "target does not reconcile" in r.summary and r.extra["reconciles"] is False
    assert not [c for c in r.checks if c.name.startswith("c:")]


def test_a_record_with_no_numbering_fails_order_and_nothing_held_fails_the_own_side_edit():
    """A target whose entries carry no per-peer number and that sends B nothing to hold: the
    control's order check fails, and an insider's edit of its own entry is hidden."""
    from conformance import books

    class Unnumbered(ToyRecords):
        def export(self, peer):
            out = []
            self.numbered = {}
            for e in super().export(peer):
                u = dict(e, pair_seq=None, prev_digest=None)
                self.numbered[books.entry_digest(u)] = books.entry_digest(e)
                out.append(u)
            return out

        def operator_write(self, peer, digest, change):
            return super().operator_write(peer, self.numbered[digest], change)

    toy = Unnumbered("bad", "mutable_record")
    toy.reconciles = lambda: False
    r = _run(toy, tag="unnumbered")
    got = {c.name: c.outcome for c in r.checks}
    assert got["order"] == "unordered" and got["join"] == "joined"
    assert got["a_edit_after_ack"] == got["a_delete_after_ack"] == "hidden"
    assert r.extra["grade_a"] == "state-only"


def test_a_refused_operator_write_is_prevented():
    toy = make("mutable_record")
    toy.operator_write = lambda peer, digest, change: "refused: the store is append-only"
    got = {c.name: c.outcome for c in _run(toy, tag="refuses").checks}
    assert got["a_edit_after_ack"] == got["a_delete_after_ack"] == "prevented"


def test_no_operator_write_path_is_never_a_pass():
    toy = make()
    toy.operator_write = None
    got = {c.name: (c.outcome, c.ok) for c in _run(toy, tag="no-hook").checks}
    assert got["a_edit_after_ack"] == ("fixture_not_landed", None)


def test_an_adapter_cannot_declare_the_core_variants_not_applicable():
    toy = make()
    toy.variants_not_applicable = lambda: {"a_edit_after_ack": "our adapter has no hook"}
    r = _run(toy, tag="na")
    assert r.status is Status.INCONCLUSIVE and "may not be" in r.summary
    toy = make()
    toy.variants_not_applicable = lambda: {"clock_skew": "the product has one clock"}
    got = {c.name: c.outcome for c in _run(toy, tag="na-ok").checks}
    assert got["clock_skew"] == "not_applicable" and "c:clock_skew" not in got


def test_counts_and_positions_are_reproducible_for_a_seed():
    a, b = _run(make(), seed=5), _run(make(), seed=5)
    assert a.extra["series"] == b.extra["series"]
    assert _run(make(), seed=6).extra["series"] != a.extra["series"]


# --------------------------------------------------------------------------- the effect checks


def test_the_effect_kinds_are_the_effect_kinds_but_join_ambiguous():
    from conformance import books
    from known_bad import records_toys
    assert set(p17.HOLDS_EFFECT) == set(books.EFFECT_KINDS) - {"join-ambiguous"}
    assert records_toys.HOLDS_EFFECT == p17.HOLDS_EFFECT
    assert p17.NO_OUTCOME not in p17.OUTCOMES


def test_the_correct_target_holds_every_effect_then_follows_the_outcome():
    r = _run(make(), tag="effect")
    got = {c.name: c.outcome for c in r.checks if c.name.startswith("e:")}
    assert got and set(got.values()) == {"held_then_followed"}, got
    assert "effect_checks" not in r.extra


def test_a_record_settled_read_as_the_effect_settled_fails():
    r = _run(make("record_settles_effect"), tag="settles-effect")
    bad = {c.name: c for c in r.checks if c.ok is False}
    assert set(bad) == FAILS["record_settles_effect"]
    assert {c.outcome for c in bad.values()} == {"closed_without_outcome"}
    assert "the record settled, read as the effect settled" in bad["e:late_entry"].detail
    # Every record and reconciliation check still passes: only the effect check sees it.
    assert all(c.ok is not False for c in r.checks if not c.name.startswith("e:"))


def test_no_effect_state_reads_inconclusive_never_pass():
    toy = make("record_settles_effect")
    toy.effect_state = None
    r = _run(toy, tag="no-effect-state")
    got = {c.name: (c.outcome, c.ok) for c in r.checks if c.name.startswith("e:")}
    assert got and set(got.values()) == {("effect_unread", None)}, got
    assert r.status is Status.PASS and r.control_held is True
    assert "no effect state" in r.extra["effect_checks"] and "no effect state" in r.summary


def test_an_effect_reading_outside_the_vocabulary_is_unread():
    toy = make()
    toy.effect_state = lambda case_ref: {"effect": "executed", "closed": True}
    got = {c.outcome for c in _run(toy, tag="vocab").checks if c.name.startswith("e:")}
    assert got == {"effect_unread"}


def test_a_target_that_reads_honest_actions_as_open_gives_no_effect_verdict():
    """The guard: an open reading proves nothing from a target that reads every effect open.
    The control still holds (KRK-M19): only the effect checks give no verdict."""
    toy = make()
    toy.effect_state = lambda case_ref: {"effect": "open", "closed": False, "product": "always"}
    r = _run(toy, tag="always-open")
    assert r.control_held is True and r.status is Status.PASS
    got = {c.outcome for c in r.checks if c.name.startswith("e:")}
    assert got == {"no_verdict"} and "honest action" in r.extra["effect_checks"]


def test_an_effect_that_ignores_the_persons_outcome_fails():
    class Ignores(ToyRecords):
        def effect_state(self, case_ref):
            got = super().effect_state(case_ref)
            c = self.cases[case_ref]
            from conformance import books
            key = books.key_str((self.me, c["peer"], c["cid"], c["rd"]))
            if any(b["key"] == key for b in self.peers[c["peer"]]["breaks"].values()):
                return {"effect": "open", "closed": False, "product": "held for ever"}
            return got

    got = {c.outcome for c in _run(Ignores("good"), tag="ignores").checks
           if c.name.startswith("e:")}
    assert got == {"outcome_not_followed"}


def test_no_path_for_a_persons_outcome_is_never_a_pass():
    class NoOutcome(ToyRecords):
        def settle_as_person(self, peer, ref, decision, by):
            if decision in p17.OUTCOMES:
                return "refused: this product takes no outcome on a settled break"
            return super().settle_as_person(peer, ref, decision, by)

    toy = NoOutcome("good")
    toy.reconcile_attempt_as_person = None
    r = _run(toy, tag="no-outcome")
    got = {c.name: (c.outcome, c.ok) for c in r.checks if c.name.startswith("e:")}
    # late_entry needs a person's not-executed before B acts, which this toy refuses; every other
    # effect check is held and gets no verdict.
    assert {v for k, v in got.items() if k != "e:late_entry"} == {("no_outcome_path", None)}, got
    assert got.get("e:late_entry", ("no_outcome_path", None))[1] is not True
