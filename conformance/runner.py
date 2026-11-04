"""Run properties against a target and write results + evidence.

    python -m conformance run toys@P1-bad -p P1       # a named configuration, one property
    python -m conformance run toys@P16-good -p P16 --seed 7  # reproduce what the kit draws
    python -m conformance matrix [RUN_ID]             # results matrix (JSON + Markdown)
    python -m conformance validity RESULT.json [--target-version V]   # valid or lapsed, and why
    python -m conformance known-bad --record [-p P16] # re-run and record the known-bad fixtures
    python -m conformance known-bad --status          # which properties may be probed now
    python -m conformance targets                     # what exists

A probe that raises is recorded as inconclusive with its traceback as evidence. It never
becomes a pass by omission.

Every run has a seed: `--seed N`, or one drawn and printed. Each probe that takes a `seed`
keyword gets it, and every result records it with the run time, its validity limit and the
probe, fixture and adapter versions (`conformance.validity`, `conformance.versions`).

The known-bad gate (spec §3.5): `run` refuses to probe a property that has no successful
known-bad run recorded for its current probe and fixture versions (`conformance.knownbad`),
and names the command that records one. Each result cites the record it relied on.
`--without-known-bad` probes anyway; a property with no current record then cites none, and
validity reads its verdict as no verdict.

Authority routing (the B-issuer profile, design §6.7; KRK-M130). An adapter whose own
``authority()`` states ``issuer: B`` is refused for P16, P18, P19 and P20, with the B-issuer id to
run instead; an adapter that does not is refused for a B-issuer property (`properties.ALL_BISSUER`).
A refusal is recorded as inconclusive and the probe is not called. The runner reads only the
``authority()`` method, never ``agreement()``, which on some targets starts a process.

Claim basis (spec §3.4; `conformance.claim_basis`). An adapter that
states ``not_claimed()`` or ``claim_basis()`` has each result judged on its claimed forms only,
after the probe and outside it: no probe or fixture version moves. A property the adapter states
is not claimed at all reads ``not_claimed`` and its probe is not called. Such a run needs a
known-bad record made with the current claim-basis rule (`knownbad`, the ``claims:`` cases). In
a development run an adapter that states neither is run exactly as before. A run marked published
(``--published``, or a property plan with ``"trials": "published"``) is refused before any probe
runs (exit 6) if the adapter states no claim basis for a property it runs, or if a
form of a stated property is neither stated not claimed nor given a claim basis,
judged from `claim_basis.inventory` (`claim_basis.before_run`). A development run probes and
flags those forms.
"""
from __future__ import annotations

import argparse
import importlib
import inspect
import json
import sys
import traceback
from pathlib import Path
from typing import Any, List, Optional

from . import bissuer, claim_basis, evidence, knownbad, matrix, validity, versions
from .evidence import Evidence, ROOT, new_run_id
from .properties import ALL, ALL_BISSUER, module, ordered
from .result import Result

TARGETS = ROOT / "targets"


def target_roots() -> List[Path]:
    """Every directory adapters are found in: the kit's own `targets/`, then each directory
    ``KIRKALDY_TARGETS_PATH`` names (`targets.roots`)."""
    import targets
    return targets.roots()


def list_targets() -> List[str]:
    """Every adapter name in every root, once. A name in two roots is the first root's, as
    `import` reads it."""
    names = set()
    for root in target_roots():
        names.update(p.name for p in root.iterdir()
                     if (p / "adapter.py").exists() and not p.name.startswith("_"))
    return sorted(names)


def load(spec: str):
    name, _, config = spec.partition("@")
    if name not in list_targets():
        raise ValueError(f"no adapter {name!r} in any target root "
                         f"({', '.join(str(r) for r in target_roots())})")
    mod = importlib.import_module(f"targets.{name}.adapter")
    return mod.make(config or "default")


def run(spec: str, props: Optional[List[str]] = None, run_id: Optional[str] = None,
        keep: bool = False, seed: Optional[int] = None,
        known_bad: str = "require", published: bool = False) -> List[Result]:
    return run_adapter(load(spec), props, run_id, keep, seed, known_bad, published=published)


def _takes_seed(probe) -> bool:
    try:
        return "seed" in inspect.signature(probe).parameters
    except (TypeError, ValueError):
        return False


ROUTED = {"P16": "P16B", "P18": "P18B", "P19": "P19B", "P20": "P20B"}
"""The A-issued properties that have a B-issuer counterpart (design §6.7)."""


def authority_refusal(a: Any, pid: str) -> Optional[str]:
    """Why `pid` may not be probed on `a` under its stated authority, or None (KRK-M130)."""
    issuer = bissuer.declared_authority(a).issuer
    if pid in ROUTED and issuer == "B":
        return (f"authority held at B: the adapter's authority() states issuer B, so the "
                f"A-issued {pid} would grade the adapter's translation, not B; run "
                f"{ROUTED[pid]} (KRK-M130)")
    if pid in ALL_BISSUER and issuer != "B":
        a_id = next((k for k, v in ROUTED.items() if v == pid), "the A-issued property")
        return (f"authority held at A: the adapter states no authority() with issuer B, so "
                f"{pid} has no B-issued object to judge; run {a_id} (KRK-M130)")
    return None


def _version(a: Any) -> str:
    try:
        return a.version() or ""
    except Exception:
        return ""


def run_adapter(a: Any, props: Optional[List[str]] = None, run_id: Optional[str] = None,
                keep: bool = False, seed: Optional[int] = None,
                known_bad: str = "require", *, published: bool = False) -> List[Result]:
    """Run `props` (default: all) against an adapter instance, stamp each result with its
    validity (`validity.stamp`) and the known-bad record it relied on, and write it beside its
    evidence.

    `known_bad="require"` (the default) raises `knownbad.KnownBadMissing` before any probe runs
    if a property to be probed has no successful known-bad run for its current probe and
    fixture versions. `"mark"` probes anyway; a result whose property has no such record cites
    none, and validity reads its verdict as no verdict.

    `published=True` marks every property published (`claim_basis.published`); a property whose
    plan says ``"trials": "published"`` is published either way. For a published property the
    adapter runs, `claim_basis.ClaimBasisIncomplete` is raised before any probe runs if the
    adapter states no claim basis for it or a form is neither stated not claimed
    nor given a basis."""
    if known_bad not in ("require", "mark"):
        raise ValueError(f"known_bad must be 'require' or 'mark', not {known_bad!r}")
    run_id = run_id or new_run_id()
    if seed is None:
        seed = validity.new_seed()
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise ValueError(f"seed must be a non-negative integer, not {seed!r}")
    module_name = versions.adapter_module(a)
    wanted = props or ordered(ALL) + ordered(ALL_BISSUER)
    results: List[Result] = []
    print(f"[{run_id}] {a.name}@{a.config}: starting (seed {seed})", flush=True)
    try:
        a.start()
    except BaseException:
        # A start that fails partway has usually launched some of its helpers already; without
        # this they outlive the run and hold their ports, so the next start fails too.
        try:
            a.stop()
        except Exception:
            pass  # report the start failure, not a stop of a half-started target
        raise
    try:
        na = a.not_applicable()
        impl = set(a.implements())
        stated = {p: claim_basis.statement(a, p) for p in wanted if p in impl or p in na}
        rule = {p: claim_basis.rule_version() for p, st in stated.items()
                if not st.empty() and not st.whole}
        pub = {p for p in wanted if p in impl and p not in na
               and claim_basis.published(p, published)}
        gaps = {p: claim_basis.before_run(a, stated[p]) for p in sorted(pub)}
        gaps = {p: g for p, g in gaps.items() if g}
        if gaps:
            raise claim_basis.ClaimBasisIncomplete(gaps)
        if known_bad == "require":
            stale = knownbad.gate([p for p in wanted if p in impl and p not in na
                                   and not (p in stated and stated[p].whole)], claim_rule=rule)
            if stale:
                raise knownbad.KnownBadMissing(stale)
        for pid in wanted:
            ev = Evidence(run_id, a.name, pid, a.config)
            run_at = validity.utcnow()
            st = stated.get(pid) or claim_basis.Statement(pid)
            if st.whole and (pid in impl or pid in na):
                r = claim_basis.not_claimed_result(a, pid, st, evidence_dir=ev.relpath())
            elif pid in na:
                r = Result.not_applicable(a.name, pid, na[pid], config=a.config,
                                          target_version=a.version(),
                                          vendor_claim=a.vendor_claims().get(pid, "not stated"),
                                          evidence_dir=ev.relpath())
            elif pid not in impl:
                continue
            elif authority_refusal(a, pid):
                r = Result.inconclusive(a.name, pid, authority_refusal(a, pid), config=a.config,
                                        target_version=a.version(), evidence_dir=ev.relpath())
            else:
                prop = module(pid)
                print(f"  {pid} {prop.TITLE} ...", flush=True)
                kw = {"run_tag": run_id.lower()}
                if _takes_seed(prop.probe):
                    kw["seed"] = seed
                try:
                    r = prop.probe(a, ev, **kw)
                except Exception as e:  # the target could not be driven
                    ev.write("traceback.txt", traceback.format_exc())
                    r = Result.inconclusive(a.name, pid, f"probe raised {type(e).__name__}: {e}",
                                            config=a.config, evidence_dir=ev.relpath())
                r = claim_basis.apply(r, st, published=pid in pub)
                unstated = ((r.extra or {}).get("claim_basis") or {}).get(
                    "claimed_without_stated_basis") or []
                if unstated and pid not in pub:
                    print(f"  {pid}: {len(unstated)} form(s) claimed without a stated basis "
                          f"(flagged; a published run refuses to start): "
                          f"{claim_basis.shorten(unstated)}", flush=True)
            measured = versions.snapshot(pid, module_name)
            kb = knownbad.lookup(pid, measured["probe_version"], measured["fixture_version"],
                                 before=run_at, claim_rule=rule.get(pid))
            validity.stamp(r, run_at=run_at, seed=seed, measured=measured,
                           unseeded=versions.unseeded(pid), target_version=_version(a),
                           known_bad=knownbad.reference(kb))
            claim_basis.stamp(r)
            (ev.dir / "result.json").write_text(json.dumps(claim_basis.result_doc(r), indent=2,
                                                           sort_keys=True))
            results.append(r)
            print(f"  {pid} -> {r.status.value}: {r.summary}", flush=True)
    finally:
        if not keep:
            a.stop()
    return results


def check_validity(path: str, *, target_version: Optional[str] = None,
                   config: Optional[str] = None, now: Optional[str] = None,
                   probe_version: Optional[str] = None, fixture_version: Optional[str] = None,
                   adapter_version: Optional[str] = None) -> "validity.Validity":
    """Read one result.json against the kit as it is now. Probe, fixture and adapter versions
    and the environment are measured from this tree unless given; the target version must be
    given, or the answer is unknown; the configuration defaults to the one recorded."""
    try:
        doc = json.loads(Path(path).read_text())
    except Exception as e:
        return validity.Validity(validity.UNKNOWN, [f"cannot read {path}: {type(e).__name__}: "
                                                    f"{e}"])
    if not isinstance(doc, dict):
        return validity.validity(doc, now=validity.utcnow(), target_version=None, config=None,
                                 probe_version=None, fixture_version=None)
    when = validity.parse_time(now) if now else validity.utcnow()
    if when is None:
        raise ValueError(f"--now {now!r} is not a UTC time (e.g. 2027-01-01T00:00:00Z)")
    cur = versions.current(doc)
    probe_version = probe_version or cur["probe_version"]
    fixture_version = fixture_version or cur["fixture_version"]
    adapter_version = adapter_version or cur["adapter_version"]
    env = cur["environment"]
    return validity.validity(doc, now=when, target_version=target_version,
                             config=config if config is not None else doc.get("config"),
                             probe_version=probe_version, fixture_version=fixture_version,
                             adapter_version=adapter_version, environment=env,
                             claim_rule_version=cur.get("claim_rule_version"))


EXIT = {validity.VALID: 0, validity.LAPSED: 1, validity.UNKNOWN: 3, validity.NO_VERDICT: 4}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="conformance")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="probe a target (exit 5: refused, a property has no current "
                                    "known-bad run)")
    r.add_argument("target", help="target[@config]")
    r.add_argument("-p", "--properties", default="", help="comma list, e.g. P1,P2")
    r.add_argument("--run-id", default=None)
    r.add_argument("--keep", action="store_true", help="leave the target running")
    r.add_argument("--seed", type=int, default=None,
                   help="the run's seed (non-negative integer); drawn and recorded if omitted")
    r.add_argument("--without-known-bad", action="store_true",
                   help="probe even without a current known-bad record; such a verdict "
                        "then reads as no verdict")
    r.add_argument("--published", action="store_true",
                   help="mark the run published: refused (exit 6) if the adapter states no "
                        "claim basis for a property it runs, or if a form of a "
                        "stated property is neither stated not claimed nor given a basis "
                        "")
    m = sub.add_parser("matrix")
    m.add_argument("run_id", nargs="?", default=None)
    m.add_argument("--target-version", action="append", default=[], metavar="ROW=VERSION",
                   help="a row's current target version (row as the matrix names it, e.g. "
                        "'my-product@default=my-product 1.2.3'); repeatable. A row "
                        "without one reads as unknown")
    m.add_argument("--now", default=None, help="UTC time to judge validity at (default: now)")
    k = sub.add_parser("known-bad", help="run the known-bad fixtures (exit 0 all as required, "
                                         "1 otherwise)")
    k.add_argument("-p", "--properties", default="", help="comma list (default: all)")
    k.add_argument("--record", action="store_true",
                   help="append each run to results/known-bad/records.jsonl; a property already "
                        "recorded for its current versions is skipped")
    k.add_argument("--force", action="store_true", help="with --record: run current ones too")
    k.add_argument("--status", action="store_true",
                   help="run nothing; say which properties are current, stale, failed or missing")
    k.add_argument("--seed", type=int, default=None)
    k.add_argument("--json", action="store_true")
    sub.add_parser("targets")
    dv = sub.add_parser("derive", help="read a P19 evidence directory, complete or cut short, "
                                        "into its statistics (JSON; not a verdict)")
    dv.add_argument("evidence", help="the P19 evidence directory (results/<run>/<target>/P19)")
    dv.add_argument("--out", default=None, help="also write the JSON to this file")
    v = sub.add_parser("validity", help="is a result still valid? exit 0 valid, 1 lapsed, "
                                        "3 unknown, 4 no verdict")
    v.add_argument("results", nargs="+", help="result.json file(s)")
    v.add_argument("--target-version", default=None,
                   help="the target's current version, exactly as results record it "
                        "(e.g. 'my-product 1.2.3'); without it the answer is unknown")
    v.add_argument("--config", default=None, help="default: the configuration recorded")
    v.add_argument("--now", default=None, help="UTC time to judge at (default: now)")
    v.add_argument("--probe-version", default=None, help="default: hashed from this tree")
    v.add_argument("--fixture-version", default=None, help="default: hashed from this tree")
    v.add_argument("--adapter-version", default=None, help="default: hashed from this tree")
    v.add_argument("--json", action="store_true", help="print the answers as JSON")
    args = ap.parse_args(argv)

    if args.cmd == "targets":
        for t in list_targets():
            mod = importlib.import_module(f"targets.{t}.adapter")
            print(t, " configs:", ", ".join(getattr(mod, "CONFIGS", ["default"])))
        return 0
    if args.cmd == "run":
        props = [p.strip().upper() for p in args.properties.split(",") if p.strip()] or None
        if args.seed is not None and args.seed < 0:
            ap.error("--seed must be a non-negative integer")
        try:
            run(args.target, props, args.run_id, args.keep, args.seed,
                "mark" if args.without_known_bad else "require", published=args.published)
        except knownbad.KnownBadMissing as e:
            print(str(e), file=sys.stderr)
            return 5
        except claim_basis.ClaimBasisIncomplete as e:
            print(str(e), file=sys.stderr)
            return 6
        return 0
    if args.cmd == "known-bad":
        props = [p.strip().upper() for p in args.properties.split(",") if p.strip()] or None
        return knownbad.main(props, record=args.record, force=args.force,
                             show_status=args.status, seed=args.seed, as_json=args.json)
    if args.cmd == "derive":
        from .properties import p19_withdrawal_within_t as p19
        try:
            doc = p19.derive(args.evidence)
        except FileNotFoundError as e:
            print(str(e), file=sys.stderr)
            return 2
        text = json.dumps(doc, indent=1, sort_keys=True, default=str)
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(text)
        return 0
    if args.cmd == "validity":
        worst, out = 0, []
        for path in args.results:
            ans = check_validity(path, target_version=args.target_version, config=args.config,
                                 now=args.now, probe_version=args.probe_version,
                                 fixture_version=args.fixture_version,
                                 adapter_version=args.adapter_version)
            worst = max(worst, EXIT[ans.state])
            out.append({"result": path, "state": ans.state, "reasons": ans.reasons,
                        "checked": ans.checked})
            if not args.json:
                print(f"{ans.state}: {path}")
                for why in ans.reasons:
                    print(f"  - {why}")
        if args.json:
            print(json.dumps(out, indent=2, sort_keys=True))
        return worst
    if args.cmd == "matrix":
        run_id = args.run_id or sorted(p.name for p in evidence.RESULTS.iterdir()
                                       if p.is_dir() and p.name != "known-bad")[-1]
        tv = {}
        for item in args.target_version:
            row, sep, ver = item.partition("=")
            if not sep:
                ap.error(f"--target-version takes ROW=VERSION, not {item!r}")
            tv[row] = ver
        when = validity.parse_time(args.now) if args.now else None
        if args.now and when is None:
            ap.error(f"--now {args.now!r} is not a UTC time")
        out = matrix.build(run_id, now=when, target_versions=tv)
        print(out["markdown_path"])
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
