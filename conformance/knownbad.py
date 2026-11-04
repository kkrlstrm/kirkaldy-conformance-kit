"""The known-bad gate (spec §3.5): after any change to a probe or its fixtures, the known-bad
fixtures are re-run, and give their required outcomes, before the probe is used again.

    python -m conformance known-bad --record            # every property; skips current ones
    python -m conformance known-bad --record -p P16     # one property
    python -m conformance known-bad --status            # current, stale, failed or missing

A known-bad run of one property runs its probe against each of its toys (`known_bad/`):

- ``good`` MUST pass, ``bad`` MUST fail, ``no-control`` MUST give no verdict (inconclusive);
- P16 also has one ``bad`` toy per flaw in `known_bad.receipts_toys.FLAWS`, and P17 one per
  flaw in `known_bad.records_toys.FLAWS`; each MUST fail;
- P18 has one ``bad`` toy per role-B flaw in `known_bad.binding_toys.FLAWS` (each MUST fail), and
  its role-A family's toys: ``a-good`` (MUST pass), one ``a-bad`` toy per flaw in
  `known_bad.binding_toys.A_FLAWS` (each MUST fail) and ``a-no-control`` (MUST give no verdict).
- P19 has one ``bad`` toy per flaw in `known_bad.withdrawal_toys.FLAWS`; each MUST fail. Its
  ``slow-good`` toy (the correct B, answering slowly) MUST pass. Its toys run on a
  virtual clock, so the gate runs the published trial counts at T = 60 s in seconds.
- P20 has one ``bad`` toy per flaw in `known_bad.standing_toys.FLAWS` (each MUST fail), its
  ``slow-good`` toy (MUST pass), ``pull-good``, the correct B that reads standing only by
  fetching it (MUST pass; KRK-M95b), and the X4-status profile's ``x4-good`` (MUST pass) and
  ``x4-bad:pinned_once`` (MUST fail).
- P21 has one ``bad`` toy per flaw in `known_bad.attenuation_toys.FLAWS` (each MUST fail),
  ``good-strict``, the correct B that refuses a chain with a wider hop whole, and ``pull-good``,
  the correct B that reads standing only by fetching it (each MUST pass; KRK-M95b), and the
  example delegation format's ``example-good`` (MUST pass) and one ``example-bad`` toy per flaw
  in `known_bad.attenuation_toys.EXAMPLE_FLAWS` (each MUST fail).
- P22 has two families, one per role (`known_bad.ceiling_toys.cases`): every ``a-good*`` and
  ``b-good*`` toy MUST pass, ``a-bad`` / ``b-bad`` and one ``bad:<flaw>`` per flaw in
  `FLAWS_A` / `FLAWS_B` MUST fail, ``a-no-control`` / ``b-no-control`` MUST give no verdict, and
  ``info:charges_retries`` (over-counting) MUST pass. P22 has no plain ``good``,
  ``bad`` or ``no-control`` case of its own.
- P23 has one ``bad`` toy per flaw in `known_bad.reversal_toys.FLAWS` (each MUST fail) and three
  more correct toys that MUST pass: ``good-deferred`` (holds an effect until its window ends),
  ``good-conservative`` (declares operations with a downstream consequence irreversible and
  refuses their reversal) and ``slow-good`` (answers ``accepted``, completes
  within R). Its toys run on a virtual clock.
- P25 has its case list in `known_bad.disclosure_toys.cases`: ``good``, ``good-strict`` and
  ``b-held-good`` MUST pass; ``bad`` (``records_caller_only``), ``b-held-bad`` and one
  ``bad:<flaw>`` / ``b-held-bad:<flaw>`` per flaw in `FLAWS` / `HELD_FLAWS` MUST fail;
  ``no-control``, ``b-held-no-control`` and ``info:stores_token`` (KRK-M188) MUST give no verdict.
- P26 has its own case list, `known_bad.translation_toys.cases`: in each topology (T, R, TR)
  ``good@<t>`` and ``good-strict@<t>`` (MUST pass), ``no-control@<t>`` (MUST give no verdict) and
  one ``bad:<flaw>@<t>`` per flaw in `known_bad.translation_toys.FLAWS` whose variant runs in that
  topology (each MUST fail). P26 has no plain ``good``, ``bad`` or ``no-control`` case.
- P18B (the B-issuer profile, kept in `properties.ALL_BISSUER`) has its own case
  list, `known_bad.bissuer_binding_toys.cases`: in each of the three shapes ``good`` and
  ``slow-good`` (MUST pass), ``bad`` (MUST fail), ``no-control`` (MUST give no verdict), one
  ``bad:<flaw>`` per flaw that applies in the shape (each MUST fail), and
  ``finding:restates_silently`` (MUST give no verdict). It is gated only when named
  (``-p P18B``): the full gate (no ``-p``) runs `properties.ALL`, P1 to P26.
- P24 has its own case list (`known_bad.mandate_toys.cases`): ``good``, ``good-hold`` (holds a
  conditioned or unreadable action, never performs it) and ``good-clamp`` (performs only the
  goal's items) MUST pass; ``bad`` (``limits_only``) and one ``bad:<flaw>`` per other flaw in
  `known_bad.mandate_toys.FLAWS`, ``late_executor`` among them, MUST fail; ``info:hold_forever``
  (holds the control's confirmed action too, KRK-M157) and ``no-control`` MUST give no verdict.

Every property's run also checks the claim-basis rule (`conformance.claim_basis`, spec §3.4)
against its own toys' results, as cases named ``claims:...`` (`claim_basis.gate_cases`), and the
record carries the rule's version (``claim_rule_version``). A run whose adapter states a claim
basis relies only on a record made with the current rule. ``known-bad --record`` and
``--status`` read a record made under another claim-basis rule as stale, so ``--record`` makes a
new one without ``--force``.

The run is recorded with the property's `probe_version` and `fixture_version`
(`conformance.versions`), which are content hashes, so a record names exactly the code it
checked. The runner refuses to probe a property that has no successful record for its current
versions, and stamps each result with the record it relied on (`Result.known_bad`).
`conformance.validity` reads a `pass` or `fail` without such a record as no verdict.

The record store is `results/known-bad/records.jsonl`, one JSON record per line, appended and
never rewritten; the evidence of each run is beside it in `results/known-bad/<record_id>/`. It
lives under `results/`, which is not committed, because the rule is about the tree a probe is
about to run from: a committed record would let a clone, or a branch merged later, use a probe
on the strength of a run made elsewhere, and would change with every probe edit. A fresh
checkout therefore has no records, and its first run records them (the Makefile flows do).

Toy waits. Toys release held requests at once, so P1's late-arrival wait (`LATE_S`) and P8's
hold (`HOLD_S`) are dead time against them. A known-bad run sets both to zero while it runs, as
the test suite does (`tests/conftest.py`), and records that it did (`toy_waits`).
"""
from __future__ import annotations

import json
import os
import platform
import traceback
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import evidence, versions
from .result import Status

SCHEMA = "kirkaldy.known-bad/0.1"
REQUIRED = (("good", Status.PASS), ("bad", Status.FAIL), ("no-control", Status.INCONCLUSIVE))
TOY_WAITS = {"conformance.properties.p1_failure_direction": "LATE_S",
             "conformance.properties.p8_wait_cost": "HOLD_S"}
CURRENT, STALE, FAILED, MISSING = "current", "stale", "failed", "missing"


def store_dir() -> Path:
    return evidence.RESULTS / "known-bad"


def store_path() -> Path:
    return store_dir() / "records.jsonl"


def cases(pid: str) -> List[Tuple[str, Status]]:
    """Each toy configuration of `pid` and the outcome it is required to give."""
    if pid == "P18B":
        from known_bad.bissuer_binding_toys import cases as bissuer_cases
        return [(config, Status(required)) for config, required in bissuer_cases()]
    out = list(REQUIRED)
    if pid == "P16":
        from known_bad.receipts_toys import FLAWS
        out += [(f"bad:{flaw}", Status.FAIL) for flaw in FLAWS]
    if pid == "P17":
        from known_bad.records_toys import FLAWS as RECORD_FLAWS
        out += [(f"bad:{flaw}", Status.FAIL) for flaw in RECORD_FLAWS]
    if pid == "P18":
        from known_bad.binding_toys import A_FLAWS, FLAWS as BINDING_FLAWS
        out += [(f"bad:{flaw}", Status.FAIL) for flaw in BINDING_FLAWS]
        out += [("a-good", Status.PASS)]
        out += [(f"a-bad:{flaw}", Status.FAIL) for flaw in A_FLAWS]
        out += [("a-no-control", Status.INCONCLUSIVE)]
    if pid == "P19":
        from known_bad.withdrawal_toys import FLAWS as WITHDRAWAL_FLAWS
        out += [(f"bad:{flaw}", Status.FAIL) for flaw in WITHDRAWAL_FLAWS]
        out += [("slow-good", Status.PASS)]
    if pid == "P20":
        from known_bad.standing_toys import FLAWS as STANDING_FLAWS
        out += [(f"bad:{flaw}", Status.FAIL) for flaw in STANDING_FLAWS]
        out += [("slow-good", Status.PASS), ("pull-good", Status.PASS),
                ("x4-good", Status.PASS), ("x4-bad:pinned_once", Status.FAIL)]
    if pid == "P21":
        from known_bad.attenuation_toys import FLAWS as ATTENUATION_FLAWS
        out += [(f"bad:{flaw}", Status.FAIL) for flaw in ATTENUATION_FLAWS]
        out += [("good-strict", Status.PASS), ("pull-good", Status.PASS)]
        from known_bad.attenuation_toys import EXAMPLE_FLAWS
        out += [("example-good", Status.PASS)]
        out += [(f"example-bad:{flaw}", Status.FAIL) for flaw in EXAMPLE_FLAWS]
    if pid == "P22":
        from known_bad.ceiling_toys import cases as ceiling_cases
        out = [(c, Status(s)) for c, s in ceiling_cases()]
    if pid == "P24":
        from known_bad.mandate_toys import cases as mandate_cases
        out = [(c, Status(s)) for c, s in mandate_cases()]
    if pid == "P25":
        from known_bad.disclosure_toys import cases as disclosure_cases
        out = [(c, Status(s)) for c, s in disclosure_cases()]
    if pid == "P26":
        from known_bad.translation_toys import cases as translation_cases
        return [(c, Status(s)) for c, s in translation_cases()]
    if pid == "P23":
        from known_bad.reversal_toys import FLAWS as REVERSAL_FLAWS
        out += [(f"bad:{flaw}", Status.FAIL) for flaw in REVERSAL_FLAWS]
        out += [("good-deferred", Status.PASS), ("good-conservative", Status.PASS),
                ("slow-good", Status.PASS)]
    return out


def _toy(pid: str, config: str):
    if pid == "P18B":
        from known_bad.bissuer_binding_toys import toy as bissuer_toy
        return bissuer_toy(config)
    from known_bad.toys import TOYS
    if pid == "P20":
        from known_bad.standing_toys import toy
        return toy(config)
    if pid == "P21":
        from known_bad.attenuation_toys import toy as attenuation_toy
        return attenuation_toy(config)
    if pid == "P22":
        from known_bad.ceiling_toys import toy as ceiling_toy
        return ceiling_toy(config)
    if pid == "P23":
        from known_bad.reversal_toys import toy as reversal_toy
        return reversal_toy(config)
    if pid == "P24":
        from known_bad.mandate_toys import toy as mandate_toy
        return mandate_toy(config)
    if pid == "P25":
        from known_bad.disclosure_toys import toy as disclosure_toy
        return disclosure_toy(config)
    if pid == "P26":
        from known_bad.translation_toys import toy as translation_toy
        return translation_toy(config)
    if pid == "P19":
        from known_bad.withdrawal_toys import ToyWithdrawal
        if config.startswith("bad:"):
            return ToyWithdrawal("bad", config.split(":", 1)[1])
        return ToyWithdrawal(config)
    if pid == "P18":
        from known_bad.binding_toys import ToyBinding, ToyRequesterA
        if config.startswith("a-bad:"):
            return ToyRequesterA("bad", config.split(":", 1)[1])
        if config.startswith("a-"):
            return ToyRequesterA(config[2:])
        if config.startswith("bad:"):
            return ToyBinding("bad", config.split(":", 1)[1])
    if config.startswith("bad:") and pid == "P17":
        from known_bad.records_toys import ToyRecords
        return ToyRecords("bad", config.split(":", 1)[1])
    if config.startswith("bad:"):
        from known_bad.receipts_toys import ToyEffectReceipts
        return ToyEffectReceipts("bad", config.split(":", 1)[1])
    return TOYS[pid](config)


def current_versions(pid: str) -> Tuple[str, str]:
    return (versions.digest(versions.probe_files(pid)),
            versions.digest(versions.fixture_files(pid)))


def load() -> List[Dict[str, Any]]:
    """Every readable record, oldest first. A line that is not a record is skipped: it can
    never satisfy the gate, so skipping it fails closed."""
    path = store_path()
    if not path.is_file():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("schema") == SCHEMA:
            out.append(rec)
    return out


def lookup(pid: str, probe_version: str, fixture_version: str, *,
           before: Optional[datetime] = None,
           claim_rule: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The latest successful record of `pid` for exactly these versions, recorded no later
    than `before` if given; None if there is none. With `claim_rule` (a run whose adapter states
    a claim basis), only a record made with that claim-basis rule counts: its ``claims:`` cases
    checked the rule the run will apply."""
    from .validity import parse_time
    hits = []
    for rec in load():
        if (rec.get("property_id") == pid and rec.get("ok") is True
                and rec.get("probe_version") == probe_version
                and rec.get("fixture_version") == fixture_version
                and (claim_rule is None or rec.get("claim_rule_version") == claim_rule)):
            at = parse_time(rec.get("recorded_at"))
            if at is None or (before is not None and at > before):
                continue
            hits.append((at, rec))
    return max(hits, key=lambda h: h[0])[1] if hits else None


def reference(rec: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """What a result carries about the record it relied on; {} when there is none."""
    if not rec:
        return {}
    return {"schema": SCHEMA, "record_id": rec["record_id"], "recorded_at": rec["recorded_at"],
            "probe_version": rec["probe_version"], "fixture_version": rec["fixture_version"],
            "ok": rec["ok"], "cases": len(rec.get("cases") or []),
            "store": os.path.relpath(store_path(), versions.ROOT),
            **({"claim_rule_version": rec["claim_rule_version"]}
               if rec.get("claim_rule_version") else {})}


def status(pid: str, claim_rule: Optional[str] = None) -> Dict[str, Any]:
    """The gate's answer for `pid` against this tree:

    - ``current``: a successful record exists for the current probe and fixture versions;
    - ``failed``: the latest record for the current versions is a failed run;
    - ``stale``: records exist, but none for the current versions (the probe or its fixtures
      changed since); ``changed`` names which;
    - ``missing``: no record of `pid` at all.

    With `claim_rule`, a record counts only if it was made with that claim-basis rule; one made
    with another reads ``stale`` with ``claim_rule_version`` in ``changed``."""
    probe, fixture = current_versions(pid)
    mine = [r for r in load() if r.get("property_id") == pid]
    now_v = [r for r in mine if r.get("probe_version") == probe
             and r.get("fixture_version") == fixture
             and (claim_rule is None or r.get("claim_rule_version") == claim_rule)]
    ans: Dict[str, Any] = {"property_id": pid, "probe_version": probe,
                           "fixture_version": fixture, "record": None, "last": None,
                           "changed": []}
    ok = lookup(pid, probe, fixture, claim_rule=claim_rule)
    if ok:
        ans.update(state=CURRENT, record=ok)
    elif now_v:
        ans.update(state=FAILED, last=now_v[-1])
    elif mine:
        last = mine[-1]
        pairs = [("probe_version", probe), ("fixture_version", fixture)]
        if claim_rule is not None:
            pairs.append(("claim_rule_version", claim_rule))
            ans["claim_rule_version"] = claim_rule
        ans.update(state=STALE, last=last,
                   changed=[k for k, v in pairs if last.get(k) != v])
    else:
        ans.update(state=MISSING)
    return ans


def command(pids: List[str]) -> str:
    return f"python -m conformance known-bad --record -p {','.join(pids)}"


def explain(ans: Dict[str, Any]) -> str:
    """One line on why `ans` does not satisfy the gate (or that it does)."""
    pid, state = ans["property_id"], ans["state"]
    if state == CURRENT:
        r = ans["record"]
        return f"{pid} current: known-bad run {r['record_id']} at {r['recorded_at']}"
    if state == FAILED:
        r = ans["last"]
        bad = [c["config"] for c in r.get("cases", []) if not c.get("ok")]
        return (f"{pid} failed: the latest known-bad run for this probe and fixture version "
                f"({r['record_id']}) did not give its required outcomes ({', '.join(bad) or r.get('error', '?')})")
    if state == STALE:
        r = ans["last"]
        diffs = "; ".join(f"{k} recorded {(r.get(k) or '')[:19]}…, now {ans[k][:19]}…"
                          for k in ans["changed"])
        return (f"{pid} stale: the last known-bad run ({r['record_id']} at {r['recorded_at']}) "
                f"was for another version ({diffs})")
    return f"{pid} missing: no known-bad run recorded"


class KnownBadMissing(RuntimeError):
    """Raised by the runner when a property it is asked to probe has no successful known-bad
    run for its current probe and fixture versions."""

    def __init__(self, answers: List[Dict[str, Any]]) -> None:
        self.answers = answers
        pids = [a["property_id"] for a in answers]
        super().__init__("refusing to probe until the known-bad fixtures have been re-run "
                         "(spec §3.5):\n" + "\n".join(f"  {explain(a)}" for a in answers)
                         + f"\nrun: {command(pids)}")


@contextmanager
def toy_waits() -> Iterator[Dict[str, float]]:
    import importlib
    saved = {}
    for mod, name in TOY_WAITS.items():
        m = importlib.import_module(mod)
        saved[(m, name)] = getattr(m, name)
        setattr(m, name, 0)
    try:
        yield {f"{mod.rsplit('.', 1)[1]}.{name}": 0 for mod, name in TOY_WAITS.items()}
    finally:
        for (m, name), v in saved.items():
            setattr(m, name, v)


def run_one(pid: str, *, seed: Optional[int] = None, record: bool = False) -> Dict[str, Any]:
    """Run `pid`'s probe against each of its toys and return the record; append it to the
    store when `record` is true. Never raises for a probe failure: a probe that raises is a
    case that did not give its required outcome."""
    from .evidence import Evidence
    from .properties import known, module
    from .runner import _takes_seed
    from .validity import fmt, new_seed, utcnow

    if not known(pid):
        raise KeyError(f"no property {pid}")
    prop = module(pid)
    seed = new_seed() if seed is None else seed
    started = utcnow()
    probe_v, fixture_v = current_versions(pid)
    record_id = f"{pid}-{started.strftime('%Y%m%dT%H%M%SZ')}-{probe_v[7:15]}{fixture_v[7:15]}"
    run_dir = f"known-bad/{record_id}"
    out: List[Dict[str, Any]] = []
    runs: List[Tuple[str, Status, Any]] = []
    with toy_waits() as waits:
        for config, required in cases(pid):
            case: Dict[str, Any] = {"config": config, "required": required.value}
            try:
                toy = _toy(pid, config)
                ev = Evidence(run_dir, toy.name, pid, config)
                case["evidence_dir"] = ev.relpath()
                kw: Dict[str, Any] = {"run_tag": f"kb-{config.replace(':', '-')}"}
                if _takes_seed(prop.probe):
                    kw["seed"] = seed
                toy.start()
                try:
                    r = prop.probe(toy, ev, **kw)
                finally:
                    toy.stop()
                case.update(got=r.status.value, summary=r.summary[:300],
                            ok=r.status is required
                            and (r.status not in (Status.PASS, Status.FAIL)
                                 or r.control_held is True))
                if pid == "P18B" and case["ok"]:
                    from known_bad.bissuer_binding_toys import expected
                    need = expected(config).get("finding")
                    if need:
                        got = [f.get("finding") for f in (r.extra.get("findings") or [])]
                        case["findings"] = got
                        case["ok"] = need in got
                (ev.dir / "result.json").write_text(r.to_json())
                runs.append((config, required, r))
            except Exception as e:
                case.update(got="raised", summary=f"{type(e).__name__}: {e}"[:300], ok=False,
                            traceback=traceback.format_exc()[-2000:])
            out.append(case)
    from . import claim_basis
    out += claim_basis.gate_cases(pid, runs)
    after = current_versions(pid)
    rec: Dict[str, Any] = {
        "schema": SCHEMA, "record_id": record_id, "property_id": pid,
        "recorded_at": fmt(utcnow()), "started_at": fmt(started),
        "probe_version": probe_v, "fixture_version": fixture_v,
        "ok": all(c["ok"] for c in out) and after == (probe_v, fixture_v),
        "seed": seed, "cases": out, "toy_waits": waits,
        "claim_rule_version": claim_basis.rule_version(),
        "environment": {"python": platform.python_version(),
                        "platform": f"{platform.system()} {platform.machine()}"},
        "evidence_dir": os.path.relpath(evidence.RESULTS / run_dir, versions.ROOT)}
    if after != (probe_v, fixture_v):
        rec["error"] = "the probe or fixture files changed during the run"
    if record:
        store_dir().mkdir(parents=True, exist_ok=True)
        with store_path().open("a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def gate(pids: List[str], claim_rule: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """The answers for `pids` that do not satisfy the gate (empty when all are current).
    `claim_rule` maps a property whose adapter states a claim basis to the current claim-basis
    rule version, which its record must have been made with."""
    rule = claim_rule or {}
    return [a for a in (status(p, rule.get(p)) for p in pids) if a["state"] != CURRENT]


def main(pids: Optional[List[str]], *, record: bool, force: bool, show_status: bool,
         seed: Optional[int], as_json: bool) -> int:
    from .properties import ALL, known, ordered
    pids = ordered(pids or list(ALL))        # the full gate is P1 to P26; P18B only when named
    unknown = [p for p in pids if not known(p)]
    if unknown:
        print(f"no such property: {', '.join(unknown)}")
        return 2
    from . import claim_basis
    rule = claim_basis.rule_version()       # a record made under another rule is stale
    if show_status:
        answers = [status(p, rule) for p in pids]
        if as_json:
            print(json.dumps(answers, indent=2, sort_keys=True, default=str))
        else:
            for a in answers:
                print(explain(a))
            todo = [a["property_id"] for a in answers if a["state"] != CURRENT]
            if todo:
                print(f"run: {command(todo)}")
        return 0 if all(a["state"] == CURRENT for a in answers) else 1
    worst, recs = 0, []
    for pid in pids:
        if record and not force:
            ans = status(pid, rule)
            if ans["state"] == CURRENT:
                if not as_json:
                    print(explain(ans))
                continue
        rec = run_one(pid, seed=seed, record=record)
        recs.append(rec)
        if not rec["ok"]:
            worst = 1
        if not as_json:
            word = "recorded" if record else "ran (not recorded)"
            print(f"{pid} {'ok' if rec['ok'] else 'FAILED'}: {len(rec['cases'])} toys, "
                  f"{word} as {rec['record_id']}")
            for c in rec["cases"]:
                if not c["ok"]:
                    print(f"  - {c['config']}: required {c['required']}, got {c['got']}: "
                          f"{c['summary'][:160]}")
    if as_json:
        print(json.dumps(recs, indent=2, sort_keys=True))
    return worst
