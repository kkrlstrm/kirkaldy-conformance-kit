"""Results matrix: one row per target × configuration, one column per property.

Each cell links to its evidence directory. A run directory may hold several targets; run the
targets with the same --run-id to collect them into one matrix.

Each cell also shows the run date and the verdict's validity (spec §3.5), judged when the
matrix is built against this kit tree (`conformance.validity`): `valid`, **LAPSED**, `unknown`
or `no verdict`. The matrix cannot read a target's current version, so a row reads as unknown
unless its current version is given (`--target-version ROW=VERSION`). The Detail section gives
the reasons for every cell that is not valid.

B-issuer results (`properties.ALL_BISSUER`, design §5.3) are never a column beside the A-issued
property: they get a section of their own after the tables, one row per target, configuration
and B-issuer property, with the shape, the hook and the grade, and their own count.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

from . import claims as ledger
from . import evidence, validity, versions
from .properties import ALL, ALL_BISSUER, ordered

SYMBOL = {"pass": "pass", "fail": "**FAIL**", "not_applicable": "n/a", "inconclusive": "inconclusive",
          "not_claimed": "not claimed"}
MARK = {validity.VALID: "valid", validity.LAPSED: "**LAPSED**", validity.UNKNOWN: "unknown",
        validity.NO_VERDICT: "no verdict"}


def collect(run_id: str) -> List[Dict[str, Any]]:
    base = evidence.RESULTS / run_id
    return [json.loads(p.read_text()) for p in sorted(base.glob("*/*/result.json"))]


def judge(r: Mapping[str, Any], *, now: datetime,
          target_version: Optional[str]) -> validity.Validity:
    """The validity of one recorded result, against this kit tree at `now`."""
    try:
        cur = versions.current(dict(r))
    except Exception as e:  # a property or adapter this tree no longer has
        return validity.Validity(validity.UNKNOWN, [f"cannot measure the current versions "
                                                    f"({type(e).__name__}: {e})"])
    return validity.validity(r, now=now, target_version=target_version, config=r.get("config"),
                             probe_version=cur["probe_version"],
                             fixture_version=cur["fixture_version"],
                             adapter_version=cur["adapter_version"],
                             environment=cur["environment"],
                             claim_rule_version=cur.get("claim_rule_version"))


def run_date(r: Mapping[str, Any]) -> str:
    t = validity.parse_time(r.get("run_at"))
    return t.strftime("%Y-%m-%d") if t else "no date"


def build(run_id: str, *, now: Optional[datetime] = None,
          target_versions: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """`target_versions` maps a row (`target` or `target@config`) or a target name to its
    current version, exactly as results record it."""
    now = now or validity.utcnow()
    tv = dict(target_versions or {})
    results = collect(run_id)
    b_results = [r for r in results if r.get("property_id") in ALL_BISSUER]
    results = [r for r in results if r.get("property_id") not in ALL_BISSUER]
    rows: Dict[str, Dict[str, Any]] = {}
    for r in results:
        key = r["target"] if r["config"] == "default" else f"{r['target']}@{r['config']}"
        row = rows.setdefault(key, {"target": r["target"], "config": r["config"],
                                    "version": r.get("target_version", ""), "cells": {}})
        row["version"] = row["version"] or r.get("target_version", "")
        v = judge(r, now=now, target_version=tv.get(key, tv.get(r["target"])))
        r["validity"] = {"state": v.state, "reasons": v.reasons, "judged_at": validity.fmt(now),
                         "run_date": run_date(r)}
        row["cells"][r["property_id"]] = r

    pids = ordered(ALL)
    header = ["| Target | Version | " + " | ".join(f"{p} {ALL[p].TITLE}" for p in pids) + " |",
              "|---|---|" + "---|" * len(pids)]

    def table(keys):
        out = list(header)
        for key in keys:
            row = rows[key]
            cells = []
            for p in pids:
                r = row["cells"].get(p)
                if not r:
                    cells.append("—")
                    continue
                rel = r["evidence_dir"].split(f"results/{run_id}/", 1)[-1]
                v = r["validity"]
                mark = "" if r["status"] == "inconclusive" else f" · {MARK[v['state']]}"
                nc = ((r.get("claim_basis") or {}).get("counts") or {}).get("not_claimed")
                nc = f" · claimed forms only ({nc} not claimed)" if nc else ""
                cells.append(f"[{SYMBOL[r['status']]}]({rel}) · {v['run_date']}{mark}{nc}")
            out.append(f"| {key} | `{row['version'][:40]}` | " + " | ".join(cells) + " |")
        return out

    vendor = [k for k in sorted(rows) if ledger.role(rows[k]["target"]) != "reference"]
    reference = [k for k in sorted(rows) if ledger.role(rows[k]["target"]) == "reference"]
    given = sorted(k for k in rows if k in tv or rows[k]["target"] in tv)
    states: Dict[str, int] = {}
    for row in rows.values():
        for r in row["cells"].values():
            states[r["validity"]["state"]] = states.get(r["validity"]["state"], 0) + 1
    lines = [f"# Results — run `{run_id}`", "",
             f"Validity judged at {validity.fmt(now)} against this kit tree (spec §3.5): "
             + ", ".join(f"{n} {MARK[s].strip('*').lower()}" for s, n in sorted(states.items()))
             + ". Each cell shows its run date. A verdict lapses when the target, its "
               "configuration, the probe, its fixtures, the adapter or a declared environment "
               "field changes, and 12 months after its run. "
             + (f"Current target versions were given for: {', '.join(given)}"
                + ("." if len(given) == len(rows) else "; every other row reads as unknown, "
                   "because the matrix does not read a target's version.")
                if given else "No current target versions were given, so every verdict reads "
                              "as unknown at best: pass `--target-version ROW=VERSION` for each "
                              "row to judge it."),
             "", "## Third-party products", ""] + table(vendor)
    if reference:
        lines += ["", "## Reference implementation (the kit author's own code)", "",
                  "The reference implementation is written by the kit's author. It shows each "
                  "property can be passed; it is not an independent result.", ""]
        lines += table(reference)
    # Claimed / measured: the ledger's statement beside what the probe found, per target
    lines += ["", "## Claimed / measured", "",
              "What each product's own documentation states, beside what was measured. The basis "
              "column says where the statement comes from; `not-found` means no statement was "
              "found in the pages listed in `claims/<target>.json`. Notes follow the table.", ""]
    notes = []

    def claims_table(keys):
        out = ["| Target | Property | Basis | Documentation states | Measured |", "|---|---|---|---|---|"]
        for key in keys:
            claims = ledger.load(rows[key]["target"])
            for p in pids:
                r = rows[key]["cells"].get(p)
                if not r or r["status"] in ("not_applicable", "not_claimed"):
                    continue
                c = claims.get(p, {"basis": "not-found", "source": "no ledger entry"})
                said = (c.get("quote") or "—").replace("|", "\\|")
                if len(said) > 220:
                    said = said[:217] + "…"
                out.append(f"| {key} | {p} {ALL[p].TITLE} | {c['basis']} | {said} | "
                           f"**{r['status']}**: {r['summary'][:160].replace('|', '/')} |")
                note = f"**{rows[key]['target']} {p}:** {c['note']} (source: {c.get('source', '')})" \
                    if c.get("note") else ""
                if note and note not in notes:
                    notes.append(note)
        return out

    lines += claims_table(vendor)
    if reference:
        lines += ["", "Reference implementation (the kit author's own documentation):", ""]
        lines += claims_table(reference)
    if notes:
        lines += ["", "**Notes**", ""] + [f"- {n}" for n in notes]
    lines += _bissuer_section(b_results, run_id, now=now, tv=tv)
    lines += ["", "`—` = not run: either no probe exists yet for this target, or this configuration "
              "was run for a subset of properties. `n/a` = the target has no such mechanism; the "
              "detail says why.",
              "", "## Detail", ""]
    for key in sorted(rows):
        for p in pids:
            r = rows[key]["cells"].get(p)
            if not r:
                continue
            lines.append(f"### {key} — {p} {ALL[p].TITLE}: {r['status']}")
            lines.append("")
            lines.append(f"- **Found:** {r['summary']}")
            v = r["validity"]
            lines.append(f"- **Run:** {r.get('run_at') or 'no run time recorded'}; "
                         f"**validity:** {MARK[v['state']]}")
            if v["state"] != validity.VALID:
                for why in v["reasons"]:
                    lines.append(f"  - {why}")
            lines.append(f"- **Vendor states:** {r.get('vendor_claim') or 'not stated'}")
            cb = r.get("claim_basis") or {}
            if cb:
                n = cb.get("counts") or {}
                lines.append(f"- **Claim basis:** {n.get('claimed', 0)} forms claimed, "
                             f"{n.get('not_claimed', 0)} not claimed (information only, outside "
                             f"the verdict; spec §3.4). The probe's own reading: "
                             f"{(cb.get('probe_as_read') or {}).get('status', '—')}")
                for fid, row in sorted((cb.get("forms") or {}).items()):
                    if "not_claimed" in row:
                        lines.append(f"  - `{fid}` not claimed: {row['not_claimed'][:120]}"
                                     + (f" (read: {row.get('reading')})" if row.get("reading")
                                        else ""))
            if r.get("control_detail"):
                lines.append(f"- **Control:** {r['control_detail']}")
            for c in r.get("checks", []):
                mark = {True: "ok", False: "VIOLATION", None: "info"}[c.get("ok")]
                lines.append(f"  - `{c['name']}` → {c['outcome']} ({mark})"
                             + (f" — {c['detail'][:160]}" if c.get("detail") else ""))
            lines.append("")
    md = "\n".join(lines) + "\n"
    out_md = evidence.RESULTS / run_id / "MATRIX.md"
    out_json = evidence.RESULTS / run_id / "matrix.json"
    out_md.write_text(md)
    out_json.write_text(json.dumps({"run_id": run_id, "rows": rows, "bissuer_rows": b_results},
                                   indent=2, sort_keys=True))
    return {"markdown_path": str(out_md), "json_path": str(out_json), "rows": rows,
            "bissuer_rows": b_results}


def _bissuer_section(results: List[Dict[str, Any]], run_id: str, *, now: datetime,
                     tv: Mapping[str, str]) -> List[str]:
    """One row per target, configuration and B-issuer property; never a column beside the
    A-issued property, never counted with it (design §5.3)."""
    if not results:
        return []
    out = ["", "## Authority held at B (B-issuer profile `b-issuer/0.1`)", "",
           "Judged against B's own signed objects and B's store, with approvals given by the "
           "tester at B's page. These rows are not comparable with the tables above, where the "
           "requesting organisation issues the authorisation, and are not counted with them.", "",
           "| Target | Version | Property | Shape | Hook | Grade | Result |",
           "|---|---|---|---|---|---|---|"]
    states: Dict[str, int] = {}
    for r in sorted(results, key=lambda x: (x["target"], x["config"], x["property_id"])):
        key = r["target"] if r["config"] == "default" else f"{r['target']}@{r['config']}"
        v = judge(r, now=now, target_version=tv.get(key, tv.get(r["target"])))
        r["validity"] = {"state": v.state, "reasons": v.reasons, "judged_at": validity.fmt(now),
                         "run_date": run_date(r)}
        states[v.state] = states.get(v.state, 0) + 1
        auth = (r.get("extra") or {}).get("authority") or {}
        grade = (r.get("extra") or {}).get("grade_label") or (r.get("extra") or {}).get(
            "evidence_grade") or "—"
        rel = r["evidence_dir"].split(f"results/{run_id}/", 1)[-1]
        mark = "" if r["status"] == "inconclusive" else f" · {MARK[v.state]}"
        title = ALL_BISSUER[r["property_id"]].TITLE if r["property_id"] in ALL_BISSUER else ""
        out.append(f"| {key} | `{r.get('target_version', '')[:40]}` | {r['property_id']} {title} "
                   f"| {auth.get('shape') or '—'} | {auth.get('hook') or '—'} | {grade} | "
                   f"[{SYMBOL[r['status']]}]({rel}) · {run_date(r)}{mark} |")
    out += ["", "B-issuer verdicts: " + ", ".join(f"{n} {MARK[s].strip('*').lower()}"
                                                  for s, n in sorted(states.items())) + ".", ""]
    for r in results:
        key = r["target"] if r["config"] == "default" else f"{r['target']}@{r['config']}"
        out.append(f"### {key} — {r['property_id']}: {r['status']}")
        out.append("")
        out.append(f"- **Found:** {r['summary']}")
        for c in r.get("checks", []):
            mark = {True: "ok", False: "VIOLATION", None: "info"}[c.get("ok")]
            out.append(f"  - `{c['name']}` → {c['outcome']} ({mark})"
                       + (f" — {c['detail'][:160]}" if c.get("detail") else ""))
        out.append("")
    return out
