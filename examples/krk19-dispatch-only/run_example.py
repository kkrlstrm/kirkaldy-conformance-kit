"""Record one execution of P19's in-flight variant against the dispatch-only receiver, save it,
and grade that one saved trace against two claims.

    .venv/bin/python examples/krk19-dispatch-only/run_example.py               # record, then grade
    .venv/bin/python examples/krk19-dispatch-only/run_example.py --grade-only  # grade the saved trace

The two claims (`claims`), both quoted from the receiver's adapter (`adapters/dispatch_only/`):

- **stated-bound**: no effect under a withdrawn authorisation later than T = 10 s after the
  withdrawal is served. Graded with P19's own trial rule (`conformance.timing.classify_trial`)
  and variant rule (`conformance.timing.aggregate`), applied read-only to the saved trace.
- **commit-time**: no effect commits under an authorisation that is not valid at the moment it
  commits. P19 cannot take this claim (it refuses a zero bound), so it is graded by this
  example's own rule (`grade_commit_time`): every effect under the withdrawn authorisation that
  the recorder committed after the withdrawal is a violation; one within the method's resolution
  of the withdrawal is unresolved and gets no verdict.

What it does, in order (without ``--grade-only``):

1. Hashes every property's probe and fixture versions and the claim-basis rule
   (`conformance.versions`), and reads the kit's own `known-bad --status`.
2. Records P19's known-bad gate in this example's own results directory (about two minutes).
   `run` refuses a property without one.
3. Runs P19 **once**, on the ``stated-bound`` configuration, with a development plan of one
   variant, ``in_flight``, at the method's 5 trials (three to four minutes on the real clock).
4. Copies that run's in-flight evidence, unchanged, with the run's header (the bound as stated,
   the grade, the control, the probe's own reading) into ``results/one-trace.json``.
5. Grades ``results/one-trace.json`` against each claim. Each verdict carries the SHA-256 of the
   trace file it read, so both can be checked to come from the same bytes. Output:
   ``results/verdicts.json``, and the same as tables on stdout.
6. Hashes and reads `known-bad --status` again, and fails if anything moved.

``--grade-only`` does step 5 alone, on the committed trace, in about a second. It
rewrites ``results/verdicts.json`` and keeps the version check of the run that recorded the trace.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
ADAPTERS = HERE / "adapters"
TARGET = "dispatch_only"
NAME = "dispatch-only"
CONFIG = "stated-bound"
RUN_ID = "one-trace"
VARIANT = "in_flight"
PLAN = {"variants": [VARIANT]}

RECORDER_NOTE = (
    "The recorder is a controlled stand-in for the real mutation. It is the kit's own HTTP "
    "endpoint, placed where B's effect lands, and an effect's time is when the recorder wrote "
    "it, on the kit's clock. In a deployed integration the consequential mutation is whatever "
    "B's call changes downstream (a row, a message, a file), and it can sit behind further "
    "queues, retries or services and commit later than the call that requested it. The "
    "`recorder` grade means the effect was timed at this stand-in, downstream of B and outside "
    "B's own account of itself. It is not the time of a mutation in another organisation's "
    "system. In this example both ends are synthetic: the receiver is written for it, and the "
    "recorder is the kit's.")


def _adapter() -> Any:
    import importlib.util
    spec = importlib.util.spec_from_file_location("_dispatch_only_adapter",
                                                  ADAPTERS / TARGET / "adapter.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def claims() -> List[Dict[str, Any]]:
    """The two claims the one trace is graded against, quoted from the adapter."""
    bounds = _adapter().BOUNDS
    return [
        {"id": "stated-bound", "bound_s": bounds["stated-bound"][0],
         "quote": bounds["stated-bound"][1],
         "rule": "P19's own trial rule (conformance.timing.classify_trial) and variant rule "
                 "(conformance.timing.aggregate), applied to the saved trace with T = 10 s"},
        {"id": "commit-time", "bound_s": 0.0, "quote": bounds["valid-at-commit-zero"][1],
         "rule": "this example's rule (grade_commit_time): every effect under the withdrawn "
                 "authorisation committed at the recorder more than the method's resolution "
                 "after the withdrawal is a violation; one inside that resolution is unresolved"},
    ]


# --------------------------------------------------------------------------- the kit

def _env(results: Path, *, own_store: bool = False) -> Dict[str, str]:
    env = dict(os.environ)
    env.pop("ACK_P19_PLAN", None)
    env["KIRKALDY_TARGETS_PATH"] = str(ADAPTERS)
    if own_store:
        env.pop("KIRKALDY_RESULTS_DIR", None)     # the kit's own results/, read only
    else:
        env["KIRKALDY_RESULTS_DIR"] = str(results)
    return env


def _kit(args: List[str], env: Dict[str, str], *, extra: Optional[Dict[str, str]] = None
         ) -> subprocess.CompletedProcess:
    e = dict(env, **(extra or {}))
    return subprocess.run([sys.executable, "-m", "conformance", *args], cwd=KIT, env=e,
                          text=True, capture_output=True)


def versions_now() -> Dict[str, Any]:
    """Every property's probe and fixture version and the claim-basis rule, hashed now."""
    code = (
        "import json\n"
        "from conformance import versions\n"
        "from conformance.claim_basis import rule_version\n"
        "out = {'claim_rule_version': rule_version()}\n"
        "for pid in [f'P{i}' for i in range(1, 27)] + ['P18B']:\n"
        "    out[pid] = {'probe': versions.digest(versions.probe_files(pid)),\n"
        "                'fixture': versions.digest(versions.fixture_files(pid))}\n"
        "print(json.dumps(out, sort_keys=True))\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=KIT, text=True, capture_output=True,
                       env=_env(HERE / "results", own_store=True))
    if r.returncode != 0:
        raise SystemExit(f"hashing failed:\n{r.stderr}")
    return json.loads(r.stdout)


def kit_status() -> str:
    r = _kit(["known-bad", "--status"], _env(HERE / "results", own_store=True))
    return r.stdout + r.stderr


def _one(d: Path, name: str) -> Optional[Path]:
    hits = sorted(d.glob(f"[0-9][0-9]-{name}"))
    return hits[0] if hits else None


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------- the one trace

def save_trace(results: Path, out: Path) -> None:
    """Copy the run's in-flight evidence, unchanged, with the run's header, into `out`."""
    d = results / RUN_ID / f"{NAME}@{CONFIG}" / "P19"
    res = json.loads((d / "result.json").read_text(encoding="utf-8"))
    run_path, var_path, prog_path = (_one(d, "run.json"), _one(d, f"{VARIANT}.json"),
                                     _one(d, "progress.jsonl"))
    if run_path is None or var_path is None or prog_path is None:
        raise SystemExit(f"the run left no in-flight evidence in {d}: {res.get('summary')}")
    run_doc = json.loads(run_path.read_text(encoding="utf-8"))
    control = None
    for line in prog_path.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        if rec.get("kind") == "control":
            control = {"held": rec.get("held"), "why": rec.get("why")}
    extra = res.get("extra") or {}
    checks = {c["name"]: c for c in res.get("checks") or []}
    trace = {
        "what": "One execution of P19's in_flight variant against the dispatch-only receiver: "
                "5 trials, the method's count for the variant. 'trials' is the probe's own "
                "in-flight evidence file, unchanged; every time in it is seconds on the kit's "
                "clock from t_w, the stub A's commit of the snapshot that shows the withdrawal.",
        "recorded": {
            "target": f"{NAME}@{CONFIG}", "run_id": RUN_ID, "seed": run_doc.get("seed"),
            "plan": run_doc.get("plan"), "clock": run_doc.get("clock"),
            "bound_as_stated": run_doc.get("bound"), "window_s": run_doc.get("window_s"),
            "stability_s": run_doc.get("stability_s"),
            "evidence_grade": run_doc.get("evidence_grade"),
            "rtt_s": extra.get("rtt_s"), "measurement_floor_s": extra.get("measurement_floor_s"),
            "probe_version": res.get("probe_version"),
            "fixture_version": res.get("fixture_version"),
            "source_files": {p.name: _sha256(p) for p in (run_path, var_path)}},
        "control": control,
        "probe_reading": {"status": res.get("status"), "summary": res.get("summary"),
                          VARIANT: checks.get(VARIANT)},
        "trials": json.loads(var_path.read_text(encoding="utf-8"))["trials"],
    }
    out.write_text(json.dumps(trace, indent=1, sort_keys=True) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- grading

def _effects(trial: Dict[str, Any], bound_s: float, eps: float) -> List[Dict[str, Any]]:
    """Every effect under the withdrawn authorisation that committed after t_w, with its time
    and where it falls against `bound_s`. The trace keeps one commit per request (the
    earliest), as the probe's evidence does."""
    out = []
    for p in trial["presentations"]:
        e = p.get("effect_t")
        if p["under"] != "W" or e is None or e <= 0:
            continue
        where = ("unresolved" if bound_s == 0 and e <= eps else
                 "inside_bound" if e <= bound_s else "after_bound")
        out.append({"trial": trial["k"], "ref": p["ref"], "tag": p.get("tag") or "",
                    "sent_s": p["t_sent"], "committed_s": e, "where": where,
                    "grade": "recorder"})
    return out


def _refused_from(trial: Dict[str, Any]) -> Optional[float]:
    r = [p["t_sent"] for p in trial["presentations"]
         if p["under"] == "W" and p["t_sent"] >= 0 and p["cls"] == "refused" and not p["accepted"]]
    return min(r) if r else None


def _recorded_info(recorded: Dict[str, Any]) -> bool:
    """A trial the probe recorded as information (the fixture did not land, and the like)."""
    return recorded.get("ok") is None and recorded["outcome"] != "inconclusive"


def grade_stated_bound(trace: Dict[str, Any], claim: Dict[str, Any]) -> Dict[str, Any]:
    """P19's own rules, read only: each trial rebuilt from the saved trace and classified with
    `timing.classify_trial` at T = the claim's bound, the variant with `timing.aggregate`."""
    from conformance import timing
    rec = trace["recorded"]
    T = claim["bound_s"]
    res_s = (rec["bound_as_stated"] or {}).get("resolution_s")
    trials, outcomes = [], []
    for t in trace["trials"]:
        pres = [timing.Pres(under=p["under"], t_sent=p["t_sent"], t_answered=p["t_answered"],
                            cls=p["cls"], effect_t=p["effect_t"], accepted=p["accepted"],
                            reached=p["reached"], endpoint=p.get("endpoint") or "",
                            session=p.get("session") or "", tag=p.get("tag") or "",
                            ref=p.get("ref") or "", answered=p.get("answered", True),
                            timed_out=p.get("timed_out", False), in_flight=p.get("in_flight", 0))
                for p in t["presentations"]]
        recorded = t["outcome"]
        info = recorded["outcome"] if _recorded_info(recorded) else None
        log = timing.TrialLog(VARIANT, t["form"], 0.0, T, rec["window_s"], rec["stability_s"],
                              presentations=pres,
                              w_effects=[p.effect_t for p in pres
                                         if p.under == "W" and p.effect_t is not None],
                              info=info, info_detail=recorded.get("detail", ""),
                              phase_s=t.get("phase_s"), resolution_s=res_s)
        o = timing.classify_trial(log)
        outcomes.append(o)
        same = (o.outcome == recorded["outcome"]
                and round(o.last_effect_s or 0.0, 3) == round(recorded.get("last_effect_s")
                                                               or 0.0, 3))
        trials.append({"k": t["k"], "outcome": o.outcome, "ok": o.ok, "detail": o.detail,
                       "refused_from_s": _refused_from(t), "same_as_probe_at_run_time": same,
                       "effects_after_withdrawal": _effects(t, T, 0.0)})
    label, ok = timing.aggregate(outcomes, T, need=len(outcomes))
    return {"reading": label, "ok": ok, "trials": trials}


def grade_commit_time(trace: Dict[str, Any], claim: Dict[str, Any]) -> Dict[str, Any]:
    """This example's rule for a commit-time claim, which P19 cannot take. The authorisation is
    no longer valid from t_w. An effect under it that the recorder committed later than ε after
    t_w is a violation; one in (0, ε] is unresolved, ε being the method's resolution (the larger
    of 50 ms and B's stated timestamp resolution, `timing.epsilon_s`). A trial with a violation
    is ``late``; one with only unresolved effects has no verdict; one with neither is
    ``within``. The variant fails if any trial is late, has no verdict if any trial has none,
    and passes otherwise. Like P19, it does not count a trial the probe recorded as
    information."""
    from conformance import timing
    rec = trace["recorded"]
    eps = timing.epsilon_s((rec["bound_as_stated"] or {}).get("resolution_s"))
    trials = []
    for t in trace["trials"]:
        recorded = t["outcome"]
        effects = _effects(t, 0.0, eps)
        if _recorded_info(recorded):
            outcome, ok, detail = recorded["outcome"], None, recorded.get("detail", "")
        elif any(e["where"] == "after_bound" for e in effects):
            worst = max(e["committed_s"] for e in effects if e["where"] == "after_bound")
            outcome, ok = "late", False
            detail = (f"an effect under the withdrawn authorisation committed {worst:.3f} s "
                      f"after the withdrawal; the claim allows none after it (resolution "
                      f"{eps:g} s)")
        elif effects:
            outcome, ok = "unresolved", None
            detail = f"effects within {eps:g} s of the withdrawal, below the method's resolution"
        else:
            outcome, ok, detail = "within", True, "no effect under it after the withdrawal"
        trials.append({"k": t["k"], "outcome": outcome, "ok": ok, "detail": detail,
                       "refused_from_s": _refused_from(t), "effects_after_withdrawal": effects})
    oks = [t["ok"] for t in trials]
    if False in oks:
        label, ok = "refused_late", False
    elif any(t["outcome"] == "unresolved" for t in trials) or True not in oks:
        label, ok = "no_verdict", None
    else:
        label, ok = "refused_within_T", True
    return {"reading": label, "ok": ok, "resolution_s": eps, "trials": trials}


def _span(xs: List[float]) -> str:
    return f"{min(xs):.3f}" if min(xs) == max(xs) else f"{min(xs):.3f} to {max(xs):.3f}"


def notes(claim_id: str, v: Dict[str, Any], trace: Dict[str, Any]) -> Dict[str, List[str]]:
    """What this verdict shows and does not show. Every number is read from the verdict."""
    held = [e["committed_s"] for t in v["trials"] for e in t["effects_after_withdrawal"]
            if e["tag"] == "in-flight"]
    refused = [t["refused_from_s"] for t in v["trials"] if t["refused_from_s"] is not None]
    others = [e for t in v["trials"] for e in t["effects_after_withdrawal"]
              if e["tag"] != "in-flight"]
    span = _span(held) if held else "none"
    retry = sorted({t["extra"].get("retry_after_s") for t in trace["trials"]})
    if claim_id == "stated-bound":
        agree = all(t.get("same_as_probe_at_run_time") for t in v["trials"])
        shows = [
            f"The receiver refused every new request under the withdrawn authorisation from "
            f"{_span(refused)} s after the withdrawal. The one request it had accepted for "
            f"dispatch just before the withdrawal committed {span} s after it, inside 10 s, in "
            f"each of {len(v['trials'])} trials. KRK-19 as written allows that effect, so the "
            f"claim reads {v['verdict']}." + ("" if not others else
                                             f" {len(others)} other effect(s) under it "
                                             f"committed after the withdrawal; see the list."),
            "The verdict is P19's own trial and variant rule applied to the saved file. "
            + ("It agrees, trial by trial, with the reading the probe wrote when it ran."
               if agree else "It does NOT agree in every trial with the reading the probe "
                             "wrote when it ran; see same_as_probe_at_run_time."),
            "The effect inside T is listed with its time. P19's result today carries it only "
            "as the trial's time (the larger of the refusal onset and the latest effect), not "
            "as an effect committed after the withdrawal.",
        ]
        not_shown = [
            "It does not show the receiver's worst case. Its constants allow an effect up to 7 s "
            "after the dispatch check; this trace exercised a hold of about 2 s, because the "
            "receiver caps its wait at 2 s and the recorder accepted the retry.",
            "It covers one variant under a development plan of 5 trials. It is not a published "
            "run and says nothing about the other KRK-19 variants.",
            "The commit time is the recorder's (see the recorder note).",
        ]
    else:
        eps = v.get("resolution_s")
        shows = [
            f"The same bytes fail a commit-time claim: the effect accepted for dispatch before "
            f"the withdrawal committed {span} s after it, when the authorisation was no longer "
            f"valid. Nothing in the receiver or the trace changed between the two verdicts; "
            f"only the claim did.",
            f"The violation is far from the method's resolution: about {min(held or [0]):.1f} s "
            f"after the withdrawal, against {eps:g} s. "
            + ("No effect fell inside that resolution." if not v["effects_unresolved"] else
               f"{len(v['effects_unresolved'])} effect(s) fell inside it and have no verdict."),
        ]
        not_shown = [
            "The rule is this example's, not a kit property. P19 refuses a zero bound, and the "
            "spec does not yet say how a commit-time claim is read; version 0.3 is planned to.",
            f"The trace was recorded under the stated-bound configuration, so the probe held the "
            f"in-flight effect with Retry-After {', '.join(f'{r:g}' for r in retry)} s (T + 5 s) "
            f"and spaced its presentations for T = 10 s. For this receiver that does not change "
            f"the effect's time, since it waits at most 2 s whatever Retry-After asks. For a "
            f"receiver that honours Retry-After, a trace recorded under one bound is not the "
            f"trace another bound would produce.",
            "It does not show what a downstream system would do if it checked authority again "
            "before applying the effect. The recorder applies everything it is sent.",
        ]
    return {"shows": shows, "does_not_show": not_shown}


def grade(trace_path: Path) -> Dict[str, Any]:
    """Both verdicts, from the one saved trace file."""
    if str(KIT) not in sys.path:
        sys.path.insert(0, str(KIT))
    digest = _sha256(trace_path)
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    ctl = trace.get("control") or {}
    out = {"trace": trace_path.name, "trace_sha256": digest,
           "evidence_grade": trace["recorded"]["evidence_grade"],
           "control_held": ctl.get("held"), "recorder_note": RECORDER_NOTE, "verdicts": []}
    for c in claims():
        if not ctl.get("held"):
            v = {"reading": "no_verdict", "ok": None, "trials": [],
                 "why": f"the control did not hold: {ctl.get('why')}"}
        elif c["id"] == "stated-bound":
            v = grade_stated_bound(trace, c)
        else:
            v = grade_commit_time(trace, c)
        effects = [e for t in v["trials"] for e in t["effects_after_withdrawal"]]
        v.update(claim=c, trace_sha256=digest,
                 verdict={True: "pass", False: "fail", None: "no verdict"}[v["ok"]],
                 effects_inside_bound=[e for e in effects if e["where"] == "inside_bound"],
                 effects_after_bound=[e for e in effects if e["where"] == "after_bound"],
                 effects_unresolved=[e for e in effects if e["where"] == "unresolved"])
        if v["trials"]:
            v.update(notes(c["id"], v, trace))
        out["verdicts"].append(v)
    return out


# --------------------------------------------------------------------------- output

def _fmt(x: Any) -> str:
    return "-" if x is None else (f"{x:.3f}" if isinstance(x, float) else str(x))


def table(doc: Dict[str, Any]) -> str:
    lines = [f"Trace: {doc['trace']} ({doc['trace_sha256']})",
             f"Control held: {doc['control_held']}; evidence grade: {doc['evidence_grade']}"]
    for v in doc["verdicts"]:
        c = v["claim"]
        lines += ["", f"### Claim: {c['id']} (bound {c['bound_s']:g} s)", "",
                  f"> {c['quote']}", "", f"Verdict: **{v['verdict']}** ({v['reading']}), "
                  f"graded from {v['trace_sha256'][:23]}...", ""]
        if not v["trials"]:
            lines.append(v.get("why", ""))
            continue
        lines += ["| Trial | Held request sent | Held effect committed | Inside the bound | "
                  "After the bound | New requests refused from | Trial reads |",
                  "|---|---|---|---|---|---|---|"]
        for t in v["trials"]:
            eff = t["effects_after_withdrawal"]
            held = next((e for e in eff if e["tag"] == "in-flight"), None)
            ins = ", ".join(_fmt(e["committed_s"]) for e in eff if e["where"] == "inside_bound")
            aft = ", ".join(_fmt(e["committed_s"]) for e in eff if e["where"] == "after_bound")
            lines.append(f"| {t['k']} | {_fmt(held and held['sent_s'])} | "
                         f"{_fmt(held and held['committed_s'])} | {ins or 'none'} | "
                         f"{aft or 'none'} | {_fmt(t['refused_from_s'])} | {t['outcome']} |")
        lines += ["", f"Effects inside the bound: {len(v['effects_inside_bound'])}; after it: "
                      f"{len(v['effects_after_bound'])}; unresolved: "
                      f"{len(v['effects_unresolved'])}; every one at the recorder grade.", "",
                  "What this shows:"] + [f"- {s}" for s in v["shows"]] + \
                 ["", "What it does not show:"] + [f"- {s}" for s in v["does_not_show"]]
    lines += ["", "Recorder note: " + doc["recorder_note"]]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed", type=int, default=19)
    ap.add_argument("--results", default=str(HERE / "results"),
                    help="results root for this example (default: results/ beside this file)")
    ap.add_argument("--grade-only", action="store_true",
                    help="grade the saved trace (results/one-trace.json) and rewrite verdicts.json; "
                         "run nothing")
    args = ap.parse_args(argv)
    results = Path(args.results).resolve()
    results.mkdir(parents=True, exist_ok=True)
    trace_path = results / "one-trace.json"

    if args.grade_only:
        if not trace_path.is_file():
            print(f"no saved trace at {trace_path}; run without --grade-only first",
                  file=sys.stderr)
            return 1
        doc = grade(trace_path)
        prev = results / "verdicts.json"
        if prev.is_file():                  # the version check belongs to the recording run
            check = json.loads(prev.read_text(encoding="utf-8")).get("version_check")
            if check:
                doc["version_check"] = check
        prev.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        print(table(doc))
        return 0

    env = _env(results)
    before, status_before = versions_now(), kit_status()
    print("versions hashed; the kit's own known-bad store read", flush=True)

    print("recording P19's known-bad gate in this example's store (about two minutes) ...",
          flush=True)
    g = _kit(["known-bad", "--record", "-p", "P19"], env)
    print((g.stdout + g.stderr).strip(), flush=True)
    if g.returncode != 0:
        print("the known-bad gate did not pass; P19 is not run", file=sys.stderr)
        return 1

    shutil.rmtree(results / RUN_ID, ignore_errors=True)      # this example's own run only
    print(f"running P19 once on {NAME}@{CONFIG} ...", flush=True)
    r = _kit(["run", f"{TARGET}@{CONFIG}", "-p", "P19", "--run-id", RUN_ID,
              "--seed", str(args.seed)], env, extra={"ACK_P19_PLAN": json.dumps(PLAN)})
    print((r.stdout + r.stderr).strip(), flush=True)
    if r.returncode != 0:
        print(f"the runner refused the run (exit {r.returncode})", file=sys.stderr)
        return 1
    save_trace(results, trace_path)
    print(f"trace saved: {trace_path.name} ({_sha256(trace_path)})", flush=True)

    doc = grade(trace_path)
    after, status_after = versions_now(), kit_status()
    moved = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    doc["version_check"] = {"versions_moved": moved, "kit_known_bad_status_unchanged":
                            status_before == status_after,
                            "claim_rule_version": after["claim_rule_version"],
                            "P19": after["P19"]}
    (results / "verdicts.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print("\n" + table(doc))
    print(f"\nversions moved: {moved or 'none'}; the kit's own known-bad status "
          f"{'unchanged' if status_before == status_after else 'CHANGED'}")
    print(f"P19 probe {after['P19']['probe']}\nP19 fixture {after['P19']['fixture']}\n"
          f"claim rule {after['claim_rule_version']}")
    return 0 if not moved and status_before == status_after else 2


if __name__ == "__main__":
    sys.exit(main())
