"""P25 (KRK-25, X6 counterparty disclosure): vectors, the stub A's statements, and every toy's
required outcome and exact set of failing forms (`X6-COUNTERPARTY-DISCLOSURE-DESIGN.md` §6.5).
This file is in P25's hashed fixture set; the measurement-error pins are in
`test_failure_modes_x6.py`, which no hash covers."""
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import authz, claim_basis, disclosure as dz, knownbad, standing  # noqa: E402
from conformance.discloser import StubDiscloser  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p25_counterparty_disclosure as p25  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad import disclosure_toys as dt  # noqa: E402

VEC = json.loads((Path(__file__).parent / "vectors" / "krk25" / "vectors.json").read_text())


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, plan=None, seed=3):
    ev = Evidence("t", t.name, "P25", t.config.replace(":", "-"))
    t.start()
    try:
        return p25.probe(t, ev, run_tag="t", seed=seed, plan=plan)
    finally:
        t.stop()


def _failing(r):
    return {f"{v}/{k}" for v, fr in r.extra.get("forms", {}).items() for k, d in fr.items()
            if d["ok"] is False}


# ----------------------------------------------------------------------------- vectors


@pytest.mark.parametrize("v", VEC["pairwise"])
def test_pairwise_vectors(v):
    assert dz.pairwise(bytes.fromhex(v["secret_hex"]), v["principal"], v["audience"]) == \
        v["expected"]


def test_pairwise_differs_per_counterparty():
    a, b = VEC["pairwise"]
    assert a["expected"] != b["expected"]


@pytest.mark.parametrize("v", VEC["commitment"])
def test_commitment_vectors(v):
    assert dz.commitment(v["principal"], bytes.fromhex(v["salt_hex"])) == v["expected"]


@pytest.mark.parametrize("v", VEC["plain_hash"])
def test_plain_hash_vectors(v):
    assert dz.plain_hash(v["identifier"]) == v["expected"]


@pytest.mark.parametrize("v", VEC["principal_shapes"])
def test_principal_shapes(v):
    claims = dz.disclosure_claims(issuer="did:web:a.example", audience="did:web:b.example",
                                  actor={"kind": "agent", "id": "agent-1", "org": "did:web:a"},
                                  principal={"level": "named", "id": "x"},
                                  request_digest="sha256:" + "0" * 64, authorisation_id=None,
                                  agent_key="k1", issued_at=1, not_after=2)
    claims["principal"] = v["principal"]
    assert (dz.claims_problem(claims) is None) is v["ok"], dz.claims_problem(claims)


@pytest.mark.parametrize("v", VEC["bases"])
def test_bases(v):
    assert dz.basis_of(v["claims"], verified_by=v["verified_by"]) == v["expected"]
    assert dz.stronger("a-attested", "agent-asserted") and not dz.stronger("unattested",
                                                                            "b-consent")


@pytest.mark.parametrize("v", VEC["flatten"])
def test_flatten(v):
    assert dz.flatten(v["input"]) == v["expected"]
    assert all(dz.in_token(p) == ("#jws" in p) for p in v["expected"])


@pytest.mark.parametrize("v", VEC["find"])
def test_find(v):
    assert dz.find(v["flat"], v["needles"]) == v["expected"]
    if "folded" in v:
        assert dz.find_folded(v["flat"], v["needles"]) == v["folded"]


@pytest.mark.parametrize("v", VEC["infer_fields"])
def test_infer_fields(v):
    rows = [(lab, flat) for lab, flat in v["rows"]]
    assert dz.infer_fields(rows, exclude=v["exclude"]) == v["expected"]


@pytest.mark.parametrize("v", VEC["over_level"])
def test_over_level(v):
    needles = {"P1:named": ("named", "Pr-ALICE@a.example"),
               "P1:pairwise": ("pairwise", VEC["pairwise"][0]["expected"]),
               "P1:commitment": ("commitment", VEC["commitment"][0]["expected"]),
               "P1:hash": ("hash", VEC["plain_hash"][0]["expected"])}
    assert dz.over_level(v["flat"], v["level"], needles) == v["expected"]


# ----------------------------------------------------------------------------- the stub A


def test_a_disclosure_is_signed_under_a_standing_key_and_binds_the_request():
    """A's standing key; `standing.PURPOSES` is unchanged."""
    assert standing.PURPOSES == ("grant", "status", "standing", "request")
    A = StubDiscloser("did:web:a-test.example", audience="did:web:b.example")
    p1 = A.principal()
    raw = A.request_raw({"operation": "crm.record.push", "ref": "r-1"})
    d = A.disclose(raw, agent="agent-x", principal=p1, level="named",
                   audience="did:web:b.example")
    ks = A.keyset()["claims"]
    kid = standing.header_of(d.token)["kid"]
    assert standing.key_state(ks, kid, "standing", A.now())[0] == "a-key"
    v = dz.verify(d.token, standing.keys_of(ks))
    assert v.ok and v.claims["request_digest"] == authz.binding_digest(raw)
    assert v.claims["agent_key"] == A.agent("agent-x").kid
    assert v.claims["principal"] == {"level": "named", "id": p1}


def test_the_agents_own_and_the_unsigned_statement_are_what_they_say():
    A = StubDiscloser("did:web:a-test.example", audience="did:web:b.example")
    raw = A.request_raw({"operation": "crm.record.push", "ref": "r-2"})
    d = A.disclose(raw, agent="agent-y", principal=A.principal(), level="pairwise",
                   audience="did:web:b.example", signer="agent")
    ks = A.keyset()["claims"]
    kid = standing.header_of(d.token)["kid"]
    assert kid == A.agent("agent-y").kid
    assert standing.key_state(ks, kid, "standing", A.now())[0] == "wrong-purpose"
    u = A.disclose(raw, agent="agent-y", principal=A.principal(), level="organisation",
                   audience="did:web:b.example", signer="none")
    assert dz.verify(u.token, standing.keys_of(ks)).reason == "unsigned"
    assert [x.signer for x in A.disclosure_log()] == ["agent", "none"]


def test_principals_are_fresh_mixed_case_and_never_in_the_key_statement():
    A = StubDiscloser("did:web:a-test.example", audience="did:web:b.example")
    a, b = A.principal(), A.principal()
    assert a != b and a != a.casefold()
    kid = A.person(a).kid
    assert kid not in {k["kid"] for k in A.keyset()["claims"]["keys"]}


def test_pseudonyms_differ_per_audience_and_commitments_hide():
    A = StubDiscloser("did:web:a-test.example", audience="did:web:b.example")
    p = A.principal()
    assert A.pseudonym(p, "did:web:b.example") != A.pseudonym(p, "did:web:c.example")
    assert A.commit(p) == A.commit(p) and A.commit(p) != "sha256:" + dz.plain_hash(p)


def test_act_token_names_subject_and_actor_and_no_request():
    A = StubDiscloser("did:web:a-test.example", audience="did:web:b.example")
    tok = A.act_token(agent="agent-z", principal="Pr-X@a", audience="did:web:b.example")
    c = standing.peek(tok)
    assert c["sub"] == "Pr-X@a" and c["act"]["sub"] == "agent-z" and "request_digest" not in c
    assert standing.header_of(tok)["typ"] == dz.ACT_TYP


# ----------------------------------------------------------------------------- the toys


@pytest.mark.parametrize("config", ["good", "good-strict", "b-held-good"])
def test_correct_toys_pass_at_published_counts(config):
    r = _run(dt.toy(config))
    assert r.status is Status.PASS, (r.summary, r.extra.get("must_land_missing"))
    assert not _failing(r)
    assert all(d["trials"] == p25.TRIALS["*"] for fr in r.extra["forms"].values()
               for d in fr.values() if d["reading"] not in ("format_gap",))


def test_good_strict_states_its_stricter_rule_before_the_run():
    r = _run(dt.toy("good-strict"))
    assert r.extra["statements"]["strict_rules"]["stated"].startswith("in the toy's config")


@pytest.mark.parametrize("flaw", dt.FLAWS)
def test_each_a_issued_flaw_fails_exactly_its_forms(flaw):
    r = _run(dt.toy(f"bad:{flaw}"))
    assert r.status is Status.FAIL and r.control_held is True
    assert _failing(r) == dt.FAILS[flaw]


@pytest.mark.parametrize("flaw", dt.HELD_FLAWS)
def test_each_b_held_flaw_fails_exactly_its_forms(flaw):
    r = _run(dt.toy(f"b-held-bad:{flaw}"))
    assert r.status is Status.FAIL and r.control_held is True
    assert _failing(r) == dt.HELD_FAILS[flaw]


def test_one_flaw_per_form():
    """Every form of each profile has a toy built to fail it."""
    a = set().union(*dt.FAILS.values())
    b = set().union(*dt.HELD_FAILS.values())
    want_a = {f"{v}/{f}" for v, f in p25._profile_pairs("a-issued")}
    want_b = {f"{v}/{f}" for v, f in p25._profile_pairs("b-held")}
    assert a == want_a
    assert b == want_b - {"principal_shown/organisation"}   # the b-held toy states no such level


@pytest.mark.parametrize("config", ["bad", "b-held-bad"])
def test_bad_is_records_caller_only_and_fails_principal_shown(config):
    r = _run(dt.toy(config))
    assert r.status is Status.FAIL
    assert "principal_shown/named" in _failing(r)


@pytest.mark.parametrize("config", ["no-control", "b-held-no-control"])
def test_no_control_gives_no_verdict(config, monkeypatch):
    monkeypatch.setattr(p25, "READ_WAIT_S", 0.5)
    r = _run(dt.toy(config))
    assert r.status is Status.INCONCLUSIVE and r.control_held is False
    assert "effects at the recorder" in r.summary


def test_stores_token_reads_stored_token_and_gives_no_verdict():
    r = _run(dt.toy("info:stores_token"))
    assert r.status is Status.INCONCLUSIVE
    assert r.extra["forms"]["principal_shown"]["named"]["reading"] == "stored_token"
    assert "principal_shown/named" in r.extra["must_land_missing"]


def test_the_attribution_forms_keep_the_effect_equal_to_the_siblings():
    """§0 item 7: in good's run every asserted form landed with W's effect equal to L's."""
    r = _run(dt.toy("good"), plan={"variants": ["asserted_principal"]})
    for d in r.extra["forms"]["asserted_principal"].values():
        assert d["reading"] == "attributed" and d["ok"] is True


def test_clauses_are_reported_apart():
    r = _run(dt.toy("bad:trusts_header_member"))
    assert r.extra["clauses"]["basis"] == "fail"
    assert r.extra["clauses"]["actor"] == "pass" and r.extra["clauses"]["level"] == "pass"
    assert r.extra["disclosure_forms"]["asserted_principal/header"]["class"] == "vulnerability"


def test_a_caller_only_record_is_conformance_class():
    r = _run(dt.toy("bad"))
    assert r.extra["disclosure"] == "conformance"


def test_gate_cases_cover_every_toy_once():
    got = knownbad.cases("P25")
    names = [c for c, _s in got]
    assert len(names) == len(set(names)) == 8 + len(dt.FLAWS) + len(dt.HELD_FLAWS)
    d = dict(got)
    assert d["good"] is Status.PASS and d["bad"] is Status.FAIL
    assert d["no-control"] is Status.INCONCLUSIVE and d["info:stores_token"] is \
        Status.INCONCLUSIVE
    assert all(d[f"bad:{f}"] is Status.FAIL for f in dt.FLAWS)


def test_claim_basis_on_a_p25_result_keeps_unclaimed_forms_as_information():
    """The runner's rule applied to a P25 result. A flaw stated not claimed on its one form
    reads pass on the rest; the probe is unchanged."""
    r = _run(dt.toy("bad:trusts_query_member"))
    st = claim_basis.Statement("P25", not_claimed={"asserted_principal/query": "not claimed"})
    got = claim_basis.apply(r, st)
    assert r.status is Status.FAIL and got.status is Status.PASS
    assert got.extra["forms"]["asserted_principal"]["query"]["ok_as_read"] is False
