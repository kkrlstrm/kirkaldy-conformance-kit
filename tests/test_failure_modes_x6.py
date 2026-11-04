"""The measurement errors of P25 (X6, KRK-M170 to KRK-M189), each pinned to a
test that shows the reading its guard prevents (`docs/FAILURE-MODES.md`). Kept apart from the
other failure-mode files and from P25's fixture test, so these tests can change without moving any
hash."""
import inspect

import pytest

pytest.importorskip("cryptography")

from conformance import disclosure as dz  # noqa: E402
from conformance.discloser import StubDiscloser  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p25_counterparty_disclosure as p25  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad import disclosure_toys as dt  # noqa: E402


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, variants=None, seed=5, trials="dev"):
    plan = {"trials": trials}
    if variants:
        plan["variants"] = list(variants)
    ev = Evidence("pins", t.name, "P25", t.config.replace(":", "-"))
    t.start()
    try:
        return p25.probe(t, ev, run_tag="pin", seed=seed, plan=plan)
    finally:
        t.stop()


def _form(r, variant, form):
    return r.extra["forms"][variant][form]


def test_KRK_M170_a_record_is_read_by_bs_operation_id_only(monkeypatch):
    """KRK-M170: an answer with no operation id gives the kit no row to read; the control does
    not hold, rather than reading a neighbouring row."""
    monkeypatch.setattr(p25, "READ_WAIT_S", 0.3)
    r = _run(dt.toy("good", no_op_id=True), ["principal_shown"])
    assert r.status is Status.INCONCLUSIVE and "KRK-M170" in r.summary


def test_KRK_M171_request_content_echoed_back_is_not_attribution(monkeypatch):
    """KRK-M171: B stores the body verbatim; the asserted principal is in it. The field holds W's
    own ref, so it is echo, not B's attribution."""
    t = dt.toy("good", stores_body=True)
    r = _run(t, ["asserted_principal"])
    assert _form(r, "asserted_principal", "body_member")["reading"] == "attributed"
    monkeypatch.setattr(p25.dz, "echo_paths", lambda flat, toks: [])
    r2 = _run(dt.toy("good", stores_body=True), ["asserted_principal"])
    assert _form(r2, "asserted_principal", "body_member")["reading"] == "misattributed"


def test_KRK_M172_the_resource_owner_is_not_the_disclosed_principal(monkeypatch):
    """KRK-M172: every resource is neutral, so a B that records the account touched records
    nobody the kit drew; and a request naming the principal is never presented."""
    r = _run(dt.toy("bad", records_owner=True), ["principal_shown"])
    assert _form(r, "principal_shown", "named")["reading"] == "unattributed"
    real = p25._Run.values

    def owned(self, op, like=None):
        v = real(self, op, like=like)
        if getattr(self, "_p1", None):
            v["recipient"] = self._p1
        return v
    seen = {}
    orig = p25._AIssued.principal

    def remember(self, label, org=None):
        pr = orig(self, label, org)
        if label == "P1":
            self.run._p1 = pr.named
            seen["p1"] = pr.named
        return pr
    monkeypatch.setattr(p25._Run, "values", owned)
    monkeypatch.setattr(p25._AIssued, "principal", remember)
    r2 = _run(dt.toy("bad", records_owner=True), ["principal_shown"])
    assert r2.status is Status.INCONCLUSIVE and "KRK-M171" in r2.summary


def test_KRK_M173_a_level_the_format_cannot_carry_is_a_format_gap():
    """KRK-M173: a B whose operations carry only named principals is never read as keeping the
    pairwise or organisation level."""
    r = _run(dt.toy("good", levels_only_named=True), ["principal_shown"])
    for lv in ("pairwise", "organisation"):
        d = _form(r, "principal_shown", lv)
        assert d["reading"] == "format_gap" and d["ok"] is None


def test_KRK_M174_a_refusal_of_the_shape_is_not_a_refusal_of_the_disclosure():
    """KRK-M174: B refuses every agent request for the operation, L included."""
    r = _run(dt.toy("good", refuses_required_for_agents=True), ["missing_disclosure"])
    d = _form(r, "missing_disclosure", "required_absent")
    assert d["reading"] == "collateral_refusal" and d["ok"] is None


def test_KRK_M175_a_member_that_changes_the_effect_is_x3s(monkeypatch):
    """KRK-M175: the executor took the recipient from the asserted member, so W's effect is not
    L's; the form is not landed here, never a reading of X6."""
    r = _run(dt.toy("bad:trusts_body_member", executes_member=True), ["asserted_principal"])
    assert _form(r, "asserted_principal", "body_member")["reading"] == "not_landed"
    monkeypatch.setattr(p25._Run, "same_effect", lambda self, w, l: True)
    r2 = _run(dt.toy("bad:trusts_body_member", executes_member=True), ["asserted_principal"])
    assert _form(r2, "asserted_principal", "body_member")["reading"] == "misattributed"


def test_KRK_M176_the_adapter_never_names_the_attribution_field():
    """KRK-M176: the toy offers a field that differs between runs; the probe never reads it and
    infers the fields itself, so the impersonation toy still fails."""
    t = dt.toy("bad:records_principal_as_actor")
    assert callable(getattr(t, "attribution_field", None))
    assert "attribution_field" not in inspect.getsource(p25)
    r = _run(t, ["actor_shown"])
    assert _form(r, "actor_shown", "agent")["ok"] is False


def test_KRK_M177_two_counterparties_with_one_key_are_not_two():
    """KRK-M177: tenants that share a signing key may be one counterparty."""
    r = _run(dt.toy("b-held-good", tenants_share_key=True), ["level_exceeded"])
    d = _form(r, "level_exceeded", "pseudonym_linkable")
    assert d["reading"] == "not_landed" and "KRK-M177" in d["detail"]


def test_KRK_M178_a_direct_request_with_an_agent_credential_is_not_sent():
    """KRK-M178: the adapter's direct request carries a disclosure header; it is not presented
    as the person's own, so the control (which includes the person's own request) does not hold."""
    r = _run(dt.toy("good", direct_with_disclosure=True), ["actor_shown"])
    assert r.status is Status.INCONCLUSIVE and "KRK-M178" in r.summary


def test_KRK_M179_a_record_written_late_is_waited_for(monkeypatch):
    """KRK-M179: B writes the record after it answers. The kit waits; past its limit the form
    reads record_late, never unattributed."""
    r = _run(dt.toy("good", record_delay_s=0.2), ["principal_shown"])
    assert _form(r, "principal_shown", "named")["reading"] == "attributed"
    run = p25._Run.__new__(p25._Run)
    run.profile, run.norm = "a-issued", None
    pr = p25.Principal("P1", "Pr-X@a.example")
    assert run.principal_reading(None, "Pr-X@a.example", "named", pr)[0] == "record_late"
    assert "record_late" in p25.INFO and "record_late" not in p25.FAIL
    monkeypatch.setattr(p25, "READ_WAIT_S", 0.0)
    r2 = _run(dt.toy("good", record_delay_s=5.0), ["principal_shown"])
    assert r2.status is Status.INCONCLUSIVE and r2.status is not Status.FAIL


def test_KRK_M180_an_end_b_never_learned_of_is_not_a_reading():
    """KRK-M180: B still accepts the agent after A retired its key, so the live delegation still
    resolves; the re-read is not taken as outliving the end."""
    r = _run(dt.toy("bad:attribution_via_live_delegation", learns_end_late=True),
             ["outlives_delegation"])
    d = _form(r, "outlives_delegation", "grant_ended")
    assert d["reading"] == "not_landed" and d["ok"] is None


def test_KRK_M181_the_kits_own_bytes_are_never_searched():
    """KRK-M181: what the kit sent carries the principal (inside A's disclosure); searching it
    would fail every B. The probe searches B's answers only, and good passes."""
    A = StubDiscloser("did:web:a-pin.example", audience="did:web:b.example")
    p1 = A.principal()
    raw = A.request_raw({"operation": "crm.record.push", "ref": "r-x"})
    d = A.disclose(raw, agent="agent-q", principal=p1, level="named",
                   audience="did:web:b.example")
    sent = dz.flatten({"headers": {dz.HEADER: d.token}})
    assert dz.over_level(sent, "none", {"P1": ("named", p1)}) == ["P1"]
    r = _run(dt.toy("good"), ["level_exceeded"])
    assert all(x["ok"] is True for x in r.extra["forms"]["level_exceeded"].values())


def test_KRK_M182_a_disclosure_the_adapter_dropped_is_not_bs_basis(monkeypatch):
    """KRK-M182: the adapter drops the agent's own statement before B sees it; B received other
    headers than the kit sent, so the form has not landed."""
    r = _run(dt.toy("good", adapter_drops_unattested=True), ["self_asserted"])
    for f in ("agent_signed", "unsigned"):
        assert _form(r, "self_asserted", f)["reading"] == "not_landed"
    monkeypatch.setattr(dt.ToyDisclosureB, "received", lambda self, pid: None)
    r2 = _run(dt.toy("good", adapter_drops_unattested=True), ["self_asserted"])
    assert _form(r2, "self_asserted", "agent_signed")["reading"] == "attributed"


def test_KRK_M183_a_reused_authorisation_is_not_presented(monkeypatch):
    """KRK-M183: W under R1's own authorisation would be refused for single use, and a B that
    never checks the request digest would read as refusing the foreign disclosure."""
    r = _run(dt.toy("bad:disclosure_unbound"), ["foreign_disclosure"])
    assert _form(r, "foreign_disclosure", "other_request")["reading"] == "misattributed"
    monkeypatch.setattr(p25, "REUSE_AUTHORISATION", True)
    r2 = _run(dt.toy("bad:disclosure_unbound"), ["foreign_disclosure"])
    d = _form(r2, "foreign_disclosure", "other_request")
    assert d["reading"] == "not_landed" and "KRK-M183" in d["detail"]


def test_KRK_M184_a_hash_of_the_name_is_not_a_pseudonym():
    """KRK-M184: B's pseudonym is SHA-256 of the customer id: the same at every counterparty,
    and recomputable."""
    r = _run(dt.toy("b-held-good", pseudonym_is_hash=True), ["level_exceeded"])
    d = _form(r, "level_exceeded", "pseudonym_linkable")
    assert d["ok"] is False and d["reading"] == "over_disclosed"


def test_KRK_M185_a_bar_that_refuses_everyone_is_not_a_bar():
    """KRK-M185: the person's own request for the barred operation is refused too."""
    r = _run(dt.toy("good", bars_everyone=True), ["missing_disclosure"])
    d = _form(r, "missing_disclosure", "agent_barred")
    assert d["reading"] == "collateral_refusal" and d["ok"] is None


def test_KRK_M186_identifiers_are_fresh_whatever_the_seed(monkeypatch):
    """KRK-M186: a B that remembers principals across runs refuses one it has seen. Two runs with
    one seed against one B both pass; with principals drawn from the seed the second does not."""
    t = dt.toy("good", remembers_principals=True)
    assert _run(t, ["principal_shown"], seed=9).status is Status.PASS
    assert _run(t, ["principal_shown"], seed=9).status is Status.PASS
    import random
    rng = random.Random(0)

    def seeded(self):
        return f"Pr-{rng.getrandbits(40):010X}x@a.example"
    t2 = dt.toy("good", remembers_principals=True)
    monkeypatch.setattr(StubDiscloser, "principal", seeded)
    assert _run(t2, ["principal_shown"], seed=9).status is Status.PASS
    rng.seed(0)
    assert _run(t2, ["principal_shown"], seed=9).status is not Status.PASS


def test_KRK_M187_an_undeclared_normalisation_is_information():
    """KRK-M187: B folds case. Undeclared, the identifier read only after folding is
    information; declared before the run, it is compared under B's normalisation."""
    r = _run(dt.toy("good", fold_case=True), ["principal_shown"])
    assert _form(r, "principal_shown", "named")["reading"] == "undeclared_normalisation"
    r2 = _run(dt.toy("good", fold_case=True, declares_fold=True), ["principal_shown"])
    assert _form(r2, "principal_shown", "named")["reading"] == "attributed"


def test_KRK_M188_a_stored_token_is_not_an_attribution(monkeypatch):
    """KRK-M188: B keeps the raw disclosure on the row. The principal is inside the token only."""
    r = _run(dt.toy("info:stores_token"), ["principal_shown"])
    assert _form(r, "principal_shown", "named")["reading"] == "stored_token"
    monkeypatch.setattr(p25.dz, "in_token", lambda path: False)
    r2 = _run(dt.toy("info:stores_token"), ["principal_shown"])
    assert _form(r2, "principal_shown", "named")["reading"] == "attributed"


class _Uniform(dt.ToyDisclosureB):
    """Records every row alike, the principal only, plus the endpoint the request came in on."""

    def _store(self, op_id, row):
        pr = row.get("principal") or {}
        super()._store(op_id, {"op_id": op_id, "request_ref": row.get("request_ref"),
                               "principal": {"value": pr.get("value")},
                               "channel": row.get("channel")})


def test_KRK_M189_a_field_that_tracks_the_transport_is_not_identity(monkeypatch):
    """KRK-M189: the only field that differs between the person's rows and the agent's is the
    endpoint each came in on."""
    r = _run(_Uniform("good", records_channel=True), ["actor_shown"])
    assert _form(r, "actor_shown", "person_direct")["reading"] == "actor_not_shown"
    monkeypatch.setattr(p25.dz, "transport_paths", lambda rows: [])
    r2 = _run(_Uniform("good", records_channel=True), ["actor_shown"])
    assert _form(r2, "actor_shown", "person_direct")["reading"] == "attributed"
