"""Run P19's in-flight variant against the dispatch-only receiver, under its two claims, and read
the recorder's timeline out of the evidence.

    .venv/bin/python examples/krk19-dispatch-only/run_example.py

Run 1 states T = 10 s. Run 2 states "valid at commit", first as T = 0 s, then as T = 0.001 s
(the smallest positive bound at the receiver's 1 ms timestamp resolution). The receiver and its
code path are the same in every run; only the stated bound differs (`adapters/dispatch_only/`).

What it does, in order:

1. Hashes every property's probe and fixture versions and the claim-basis rule
   (`conformance.versions`), and reads the kit's own `known-bad --status`.
2. Records P19's known-bad gate in this example's own results directory (about two minutes;
   skipped when a current record is already there). `run` refuses a property without one.
3. Runs P19 with a development plan of one variant, ``in_flight``, at the method's trial count
   for it (5), loading the adapter through ``KIRKALDY_TARGETS_PATH`` and writing evidence
   through ``KIRKALDY_RESULTS_DIR``. Each run on the real clock takes three to four minutes.
4. Reads each run's evidence files (never the probe's code) into the in-flight timeline: when
   the request held in flight was sent and answered, the withdrawal, when its effect committed,
   and every effect under the withdrawn authorisation that committed after the withdrawal,
   split into inside T and after T.
5. Hashes and reads `known-bad --status` again, and fails if anything moved.

Output: ``results/readings.json`` beside this file, and the same as tables on stdout.
"""
from __future__ import annotations

import argparse
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
RUNS = [("run1-stated-bound", "stated-bound"),
        ("run2a-valid-at-commit-zero", "valid-at-commit-zero"),
        ("run2b-valid-at-commit", "valid-at-commit")]
PLAN = {"variants": ["in_flight"]}


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


def _evidence(results: Path, run_id: str, config: str) -> Path:
    return results / run_id / f"{NAME}@{config}" / "P19"


def _one(d: Path, name: str) -> Optional[Path]:
    hits = sorted(d.glob(f"[0-9][0-9]-{name}"))
    return hits[0] if hits else None


def stated_bound(config: str) -> Dict[str, Any]:
    """The bound the adapter states for `config`, read from the adapter itself (a run the probe
    refuses before it starts writes no bound into its evidence)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_dispatch_only_adapter",
                                                  ADAPTERS / TARGET / "adapter.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make(config).withdrawal_bound()


def read_run(results: Path, run_id: str, config: str) -> Dict[str, Any]:
    """One run's reading, from its evidence files only (the stated bound from the adapter)."""
    d = _evidence(results, run_id, config)
    res = json.loads((d / "result.json").read_text())
    extra = res.get("extra") or {}
    bound = extra.get("bound") or {}
    T = bound.get("T_s")
    checks = {c["name"]: c for c in res.get("checks") or []}
    out: Dict[str, Any] = {
        "run_id": run_id, "config": config, "evidence": os.path.relpath(d, results),
        "status": res.get("status"), "summary": res.get("summary"), "T_s": T,
        "stated_T_s": stated_bound(config)["T_s"], "stated_quote": stated_bound(config)["quote"],
        "T_source": extra.get("T_source"), "evidence_grade": extra.get("evidence_grade"),
        "below_floor": extra.get("below_floor"),
        "measurement_floor_s": extra.get("measurement_floor_s"),
        "in_flight_check": checks.get("in_flight"), "probe_version": res.get("probe_version"),
        "fixture_version": res.get("fixture_version"), "trials": []}
    f = _one(d, "in_flight.json")
    if f is None:
        out["trials_note"] = "no in_flight evidence: the probe ran no trial"
        return out
    for t in json.loads(f.read_text())["trials"]:
        pres = t["presentations"]
        held = next((p for p in pres if p.get("tag") == "in-flight"), None)
        w_after = [p for p in pres if p["under"] == "W" and p["t_sent"] >= 0]
        refused = [p for p in w_after if p["cls"] == "refused" and not p["accepted"]]
        effects = sorted({p["effect_t"] for p in pres
                          if p["under"] == "W" and p.get("effect_t") is not None
                          and p["effect_t"] > 0})
        inside = [e for e in effects if T and e <= T]
        late = [e for e in effects if not T or e > T]
        out["trials"].append({
            "k": t["k"], "outcome": t["outcome"]["outcome"], "ok": t["outcome"]["ok"],
            "detail": t["outcome"]["detail"],
            "held_sent_s": held and held["t_sent"], "held_answered_s": held and held["t_answered"],
            "held_answer": held and (held.get("answer") or {}).get("body"),
            "withdrawal_s": 0.0,
            "held_commit_s": held and held.get("effect_t"),
            "retry_after_asked_s": t["extra"].get("retry_after_s"),
            "held_attempts": t["extra"].get("held_attempts"),
            "W_presented_after": len(w_after),
            "W_first_refused_s": refused[0]["t_sent"] if refused else None,
            "W_accepted_after": sum(1 for p in w_after if p["accepted"]),
            "effects_after_withdrawal_s": effects,
            "effects_inside_T_s": inside, "effects_after_T_s": late})
    return out


def _fmt(x: Any) -> str:
    return "-" if x is None else (f"{x:.3f}" if isinstance(x, float) else str(x))


def table(r: Dict[str, Any]) -> str:
    lines = [f"### {r['run_id']} ({r['config']}, stated T = {r['stated_T_s']:g} s)", "",
             f"Result: **{r['status']}**. {r['summary']}", "",
             f"Evidence grade: {r['evidence_grade'] or 'not read (no trial ran)'}; "
             f"below the measurement floor: {_fmt(r['below_floor'])} "
             f"(floor {_fmt(r['measurement_floor_s'])} s).", ""]
    if not r["trials"]:
        lines.append(r.get("trials_note", ""))
        return "\n".join(lines)
    lines += ["Times are seconds on the kit's clock, from the withdrawal (t_w = 0).", "",
              "| Trial | Held request sent | B answered `queued` | Withdrawal served | Held effect "
              "committed | Effects after t_w, inside T | Effects after T | W refused from | "
              "Trial reads |", "|---|---|---|---|---|---|---|---|---|"]
    for t in r["trials"]:
        lines.append(
            f"| {t['k']} | {_fmt(t['held_sent_s'])} | {_fmt(t['held_answered_s'])} | 0 | "
            f"{_fmt(t['held_commit_s'])} | {', '.join(_fmt(e) for e in t['effects_inside_T_s']) or '-'} | "
            f"{', '.join(_fmt(e) for e in t['effects_after_T_s']) or '-'} | "
            f"{_fmt(t['W_first_refused_s'])} | {t['outcome']} |")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed", type=int, default=19)
    ap.add_argument("--results", default=str(HERE / "results"),
                    help="results root for this example (default: results/ beside this file)")
    ap.add_argument("--trials", type=int, default=None,
                    help="trials per run (default: the method's 5 for in_flight)")
    args = ap.parse_args(argv)
    results = Path(args.results).resolve()
    results.mkdir(parents=True, exist_ok=True)
    plan = dict(PLAN, **({"trials": {"*": args.trials}} if args.trials else {}))
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

    readings = []
    for run_id, config in RUNS:
        shutil.rmtree(results / run_id, ignore_errors=True)      # this example's own runs only
        print(f"running P19 on {NAME}@{config} ...", flush=True)
        r = _kit(["run", f"{TARGET}@{config}", "-p", "P19", "--run-id", run_id,
                  "--seed", str(args.seed)], env, extra={"ACK_P19_PLAN": json.dumps(plan)})
        print((r.stdout + r.stderr).strip(), flush=True)
        if r.returncode != 0:
            print(f"the runner refused {config} (exit {r.returncode})", file=sys.stderr)
            return 1
        readings.append(read_run(results, run_id, config))

    after, status_after = versions_now(), kit_status()
    moved = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    check = {"versions_moved": moved, "kit_known_bad_status_unchanged":
             status_before == status_after, "claim_rule_version": after["claim_rule_version"],
             "P19": after["P19"]}
    doc = {"seed": args.seed, "plan": plan, "version_check": check, "runs": readings}
    (results / "readings.json").write_text(json.dumps(doc, indent=2, sort_keys=True))
    for r in readings:
        print("\n" + table(r))
    print(f"\nversions moved: {moved or 'none'}; the kit's own known-bad status "
          f"{'unchanged' if check['kit_known_bad_status_unchanged'] else 'CHANGED'}")
    print(f"P19 probe {after['P19']['probe']}\nP19 fixture {after['P19']['fixture']}\n"
          f"claim rule {after['claim_rule_version']}")
    print(f"readings: {os.path.relpath(results / 'readings.json', Path.cwd())}")
    return 0 if not moved and check["kit_known_bad_status_unchanged"] else 2


if __name__ == "__main__":
    sys.exit(main())
