"""The known-bad gate under a sweep of seeds (KRK-M210, KRK-M210).

A gate run draws one seed. A toy whose flaw is reached only under some seeds passes the gate on
the others, and a gate recorded on a lucky seed hides it: P22's `a-bad:nets_under_gross` read
pass on about one seed in thirty-two. This test runs every property's known-bad cases (its toys
and its ``claims:`` cases, through `knownbad.run_one`, as the gate does) under many seeds, and
fails if any case misses its required outcome under any seed.

It is opt-in, because a full sweep takes hours (``make seed-sweep``):

- ``ACK_SEED_SWEEP=1`` runs the seed counts in `SEEDS_PER_PROPERTY`; ``ACK_SEED_SWEEP=<n>``
  (n > 1) runs n seeds for every property.
- ``ACK_SEED_SWEEP_SHARD=i/n`` runs every n-th seed from the i-th (0-based), so the seeds of one
  property can be split across processes.
- ``ACK_SEED_SWEEP_PROPS=P20,P22`` sweeps only those properties.
- ``ACK_SEED_SWEEP_OUT=<dir>`` writes one JSON line per seed to ``<dir>/<pid>.jsonl``.

The seeds are fixed: `REGRESSION` first (the seeds that showed KRK-M210), then a list drawn from
a fixed generator, so a failure names a seed that reproduces it. P1 to P15's probes take no seed;
their entries repeat the same run, which checks only that it is repeatable.
"""
import json
import os
import random
import shutil
import time

import pytest

from conformance import evidence, knownbad
from conformance.properties import ALL, ALL_BISSUER
from conformance.runner import _takes_seed
from conformance.properties import module

pytest.importorskip("cryptography")

REGRESSION = (103, 128, 1556072351281476649)
"""The seeds under which P22's `a-bad:nets_under_gross` read pass before KRK-M210."""

SEEDS_PER_PROPERTY = {
    **{f"P{i}": 3 for i in range(1, 16)},      # no seed reaches the probe: repeats only
    "P16": 50, "P17": 50, "P18": 50, "P19": 30, "P23": 50, "P24": 50, "P25": 50, "P26": 50,
    "P18B": 50,
    "P20": 50, "P21": 50,                      # about ten minutes per seed each
    "P22": 24,
}
"""Seeds per property: 50 for every seeded property but P19 (30) and P22 (24), whose counts are
kept from the first sweep. P20 and P21 take minutes a seed; about 50 are asked for before a
published run, so a gap that shows once
in 32 seeds is found with probability about 0.80 rather than 0.32."""


def seeds(n: int):
    rng = random.Random(616161)
    out = list(REGRESSION)
    while len(out) < n:
        s = rng.getrandbits(64)
        if s not in out:
            out.append(s)
    return out[:n]


def _plan():
    raw = os.environ.get("ACK_SEED_SWEEP", "").strip()
    if not raw or raw == "0":
        return None
    n = int(raw)
    return {pid: (SEEDS_PER_PROPERTY.get(pid, 50) if n == 1 else n)
            for pid in list(ALL) + list(ALL_BISSUER)}


def _shard(xs):
    raw = os.environ.get("ACK_SEED_SWEEP_SHARD", "").strip()
    if not raw:
        return xs
    i, n = (int(x) for x in raw.split("/"))
    return xs[i::n]


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def test_every_property_with_toys_is_swept():
    """Every built property, P18B included, has a seed count; none is left out of the sweep."""
    assert set(SEEDS_PER_PROPERTY) >= set(ALL) | set(ALL_BISSUER)
    assert seeds(5)[:3] == list(REGRESSION) and len(set(seeds(60))) == 60


@pytest.mark.parametrize("pid", list(ALL) + list(ALL_BISSUER))
def test_every_known_bad_case_gives_its_required_outcome_under_every_seed(pid):
    plan = _plan()
    if plan is None:
        pytest.skip("opt-in: set ACK_SEED_SWEEP=1 (make seed-sweep)")
    only = [p for p in os.environ.get("ACK_SEED_SWEEP_PROPS", "").split(",") if p.strip()]
    if only and pid not in only:
        pytest.skip(f"not in ACK_SEED_SWEEP_PROPS ({', '.join(only)})")
    out_dir = os.environ.get("ACK_SEED_SWEEP_OUT")
    seeded = _takes_seed(module(pid).probe)
    bad = []
    for seed in _shard(seeds(plan[pid])):
        t0 = time.time()
        rec = knownbad.run_one(pid, seed=seed)
        wrong = [{"config": c["config"], "required": c["required"], "got": c.get("got"),
                  "summary": c.get("summary", "")[:300]} for c in rec["cases"] if not c["ok"]]
        if not rec["ok"] and not wrong:
            wrong = [{"config": "-", "required": "-", "got": rec.get("error", "not ok")}]
        bad += [dict(w, seed=seed) for w in wrong]
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, f"{pid}.jsonl"), "a") as f:
                f.write(json.dumps({"pid": pid, "seed": seed, "seeded": seeded,
                                    "cases": len(rec["cases"]), "wrong": wrong,
                                    "seconds": round(time.time() - t0, 1),
                                    "probe_version": rec["probe_version"],
                                    "fixture_version": rec["fixture_version"],
                                    "claim_rule_version": rec["claim_rule_version"]}) + "\n")
        if not wrong:                              # keep evidence only where a case missed
            shutil.rmtree(evidence.RESULTS / "known-bad" / rec["record_id"], ignore_errors=True)
    assert bad == [], bad
