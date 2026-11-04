"""Claim basis: a target is judged only on what it claims (spec §3.4, §3.2, Appendix B).

An adapter MAY state which forms its target does not claim, and the claim basis of the ones it
does. Both statements are optional in a development run. **An adapter that states neither is run
exactly as before in a development run**: `apply` returns its result unchanged and no
`claim_basis` field is written. **A published run must state a claim basis** for every property
it runs: with neither statement for a property, it is refused before any probe
runs (`before_run`).

**The statements.**

- ``not_claimed()`` returns a mapping. A key is a form pattern and its value a short reason
  (the pages checked, or the plan row that records them). A key that is a property id with a
  string value marks the whole property not claimed: the probe is not run. A key that is a
  property id with a mapping value scopes the patterns in that mapping to that property; any
  other key applies to every property the adapter implements.
- ``claim_basis()`` returns a mapping of the same shape whose values are
  ``{"quote", "location", "source"}``: the target's own statement, quoted, where it is, and the
  kind of source (documentation, specification, README, interface, or a standard the target says
  it implements, with its revision). The pattern ``*`` gives a default for every claimed form.

**Form ids.** For a property whose result carries ``extra["forms"]`` (variant → form → reading),
a form id is ``<variant>/<form key>``, the key exactly as the probe wrote it (P21 writes a
holder-position form of a positioned variant as ``amount@holder``). For any other property a form
is a check, and its id is the check's name. A pattern is matched with `fnmatch.fnmatchcase`; a
pattern with no ``/`` also matches every form of the check of that name. A check named
``control`` (`CONTROL_CHECK`; P25 and P26 write one) is the control, never a form: it is not
stated, not listed and never makes a result pass.

**What changes for a stated target** (applied by the runner, never inside a probe, so no probe or
fixture version moves; the rule's own version is `rule_version`, and a result that used it lists
``claim_rule_version`` in its renewal condition):

1. A reading on a form that is not claimed is kept as information: its ``ok`` becomes ``None``,
   with ``ok_as_read`` and ``not_claimed`` (the reason) beside it.
2. Each check is re-read from its claimed forms. A check fails only if a claimed form failed.
3. The verdict counts claimed forms only. A result whose claimed forms hold is ``pass``; one with
   a failing claimed form is ``fail``. A result whose every form is not claimed is
   ``not_claimed``; one whose claimed forms all landed without a reading is ``inconclusive``.
   A result that would read ``pass`` while the probe's ``extra["must_land_missed"]``
   (`MUST_LAND_FIELD`) lists a form that must land and did not reads ``inconclusive``, whether or
   not that form is claimed; a claimed failing form still reads ``fail``.
   The rule never turns ``inconclusive`` or ``not_applicable`` into a verdict, and never makes a
   result fail.
4. The disclosure class (``extra["disclosure"]``) counts claimed failing forms only, and is never
   raised: a result that no longer fails is ``conformance``, and one whose classes are stated per
   form (``extra["disclosure_forms"]``) keeps ``vulnerability`` only if a claimed form carries it.
5. The summary states the claimed-only reading, then the probe's own, which is also kept in
   ``extra["claim_basis"]["probe_as_read"]``. It gives the number of unclaimed forms and at
   most `SHOWN` of their ids; the full list is in ``claim_basis.forms``.
6. Fields the probe derives from its forms are recomputed on claimed forms only: P21's
   ``dimensions_covered``, P22's ``information`` and P23's ``clauses``. The
   probe's own values are kept in ``probe_as_read.derived``.
7. A run marked published (`published`) needs every form of a stated property either stated not
   claimed or given a claim basis. The runner checks this before any probe runs, against the
   property's form inventory (`inventory`), and refuses with `ClaimBasisIncomplete`. A form the
   inventory did not foresee that is still claimed without a basis after the probe makes the
   published result inconclusive. A development run only flags such forms, in
   ``claimed_without_stated_basis``. The inventory covers P20 to P26 (P24 to P26
   folded in from the former ``claim_forms.py``); a check-level property needs a
   default basis ``*``.

A probe result that is inconclusive, including one made inconclusive because a form that must land
did not, stays inconclusive whether or not that form is claimed (point 3).

Each result of a stated target carries ``claim_basis``: every form, with its claim basis or its
``not_claimed`` reason. The rule is pinned by KRK-M148.
"""
from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .result import Check, Result, Status

SCHEMA = "kirkaldy.claim-basis/0.1"
RULE_FILES = ("conformance/claim_basis.py",)
"""The files `rule_version` covers: this module and nothing else, so the version moves only when
the rule does."""
RENEWAL_FIELD = "claim_rule_version"
SOURCES = ("documentation", "specification", "README", "interface", "standard")
SHOWN = 5
"""At most this many unclaimed form ids are named in a summary."""
FORM_LEVEL = ("P20", "P21", "P22", "P23", "P24", "P25", "P26")
"""Properties whose results carry ``extra["forms"]``: their forms are ``<variant>/<form>``. Every
other property's forms are its checks. P24 to P26 were folded in from ``claim_forms.py``."""
CONTROL_CHECK = "control"
"""A check of this name is the property's control (P25 and P26 write one), never a form."""
MUST_LAND_FIELD = "must_land_missed"
"""``extra`` field where a probe lists the forms that must land and did not. P21, P24
and P26 write it; P18, P18B, P19, P20, P22, P23 and P25 will at their next probe change."""
EXTRA_CHECKS = {"P20": ("recovery",)}
"""Checks a form-level property writes beside its variants (P20 judges recovery after each outage
as its own check). `tests/test_claim_basis.py` runs each form-level property's toys and fails if
a form or check is missing from `inventory`."""
ANY_FORM = "\x00"
"""Stands for a form of a variant the probe module's ``FORMS`` table does not list (P21's
``narrowed_parent``). No exact pattern matches it, so only a pattern for the whole check, or a
wildcard, covers it before the run."""


class ClaimBasisIncomplete(Exception):
    """A run marked published, refused before any probe runs: some form of a stated property is
    neither stated not claimed nor given a claim basis."""

    def __init__(self, gaps: Dict[str, List[str]]):
        self.gaps = gaps
        lines = [f"  {pid}: {', '.join(i.replace(ANY_FORM, '*') for i in ids)}"
                 for pid, ids in sorted(gaps.items())]
        super().__init__("refused: a published run must state a claim basis for every property "
                         "it runs, and every form stated not claimed or given a claim basis. "
                         "Forms with neither:\n" + "\n".join(lines))


class _NotClaimed(str):
    """The status of a result whose every form is not claimed (spec §3.2). `Status` is in every
    probe's closure, so it is not extended; this value behaves like a `Status` member where the
    runner, the matrix and validity read one (``.value``, comparison with ``"not_claimed"``)."""

    @property
    def value(self) -> str:
        return str(self)


NOT_CLAIMED = _NotClaimed("not_claimed")
RANK = {"conformance": 0, "vulnerability": 1}


def rule_version() -> str:
    from . import versions
    return versions.digest(list(RULE_FILES))


@dataclass
class NotClaimedResult(Result):
    """A result with status ``not_claimed``: the target has no claim basis for the property, or
    for any form of it. Not a verdict, never counted against the target."""

    def __post_init__(self) -> None:
        self.status = NOT_CLAIMED
        self.control_held = None

    def to_doc(self) -> Dict[str, Any]:
        d = super().to_doc()
        d["status"] = NOT_CLAIMED.value
        return d


@dataclass
class Statement:
    """What one adapter states for one property."""

    pid: str
    not_claimed: Dict[str, str] = field(default_factory=dict)
    basis: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    whole: Optional[str] = None
    """The reason the whole property is not claimed, or None."""
    property_basis: Optional[Dict[str, Any]] = None

    def empty(self) -> bool:
        return not (self.not_claimed or self.basis or self.whole or self.property_basis)

    @staticmethod
    def _match(pattern: str, form_id: str, check: str) -> bool:
        if "/" not in pattern and fnmatchcase(check, pattern):
            return True
        return fnmatchcase(form_id, pattern)

    def reason(self, form_id: str, check: str) -> Optional[str]:
        if self.whole:
            return self.whole
        for pat, why in self.not_claimed.items():
            if self._match(pat, form_id, check):
                return why
        return None

    def basis_for(self, form_id: str, check: str) -> Optional[Dict[str, Any]]:
        for pat, b in self.basis.items():
            if pat != "*" and self._match(pat, form_id, check):
                return dict(b)
        if "*" in self.basis:
            return dict(self.basis["*"])
        return dict(self.property_basis) if self.property_basis else None


def _call(a: Any, name: str) -> Dict[str, Any]:
    fn = getattr(a, name, None)
    if not callable(fn):
        return {}
    got = fn()
    if got is None:
        return {}
    if not isinstance(got, Mapping):
        raise TypeError(f"{name}() must return a mapping, not {type(got).__name__}")
    return dict(got)


def _is_pid(k: str) -> bool:
    return bool(re.fullmatch(r"P\d+B?", k))


def statement(a: Any, pid: str) -> Statement:
    """The adapter's statements for `pid` (empty when it makes none)."""
    st = Statement(pid)
    for k, v in _call(a, "not_claimed").items():
        if _is_pid(k):
            if k != pid:
                continue
            if isinstance(v, str):
                st.whole = v
            elif isinstance(v, Mapping):
                st.not_claimed.update({str(p): str(w) for p, w in v.items()})
            else:
                raise TypeError(f"not_claimed()[{k!r}] must be a reason or a mapping")
        else:
            st.not_claimed[str(k)] = str(v)
    for k, v in _call(a, "claim_basis").items():
        if not isinstance(v, Mapping):
            raise TypeError(f"claim_basis()[{k!r}] must be a mapping")
        if _is_pid(k):
            if k != pid:
                continue
            if "quote" in v:
                st.property_basis = _basis(v, k)
            else:
                st.basis.update({str(p): _basis(b, p) for p, b in v.items()})
        else:
            st.basis[str(k)] = _basis(v, k)
    return st


def _basis(b: Any, where: str) -> Dict[str, Any]:
    if not isinstance(b, Mapping) or not all(b.get(x) for x in ("quote", "location", "source")):
        raise ValueError(f"claim_basis()[{where!r}] needs a quote, a location and a source "
                         f"(spec §3.4)")
    if b["source"].split(" ", 1)[0].rstrip(",:;") not in SOURCES:
        raise ValueError(f"claim_basis()[{where!r}] source {b['source']!r} must start with one of "
                         f"{', '.join(SOURCES)}")
    return {"quote": str(b["quote"]), "location": str(b["location"]), "source": str(b["source"])}


def forms_of(r: Result) -> List[Tuple[str, str, Optional[Dict[str, Any]]]]:
    """(form id, check name, the form's reading entry or None) for every form of `r`. The
    `CONTROL_CHECK` is not a form."""
    out: List[Tuple[str, str, Optional[Dict[str, Any]]]] = []
    forms = (r.extra or {}).get("forms")
    seen = set()
    if isinstance(forms, Mapping):
        for variant, fr in forms.items():
            if not isinstance(fr, Mapping):
                continue
            for key, entry in fr.items():
                if isinstance(entry, dict) and "ok" in entry:
                    out.append((f"{variant}/{key}", str(variant), entry))
                    seen.add(str(variant))
    for c in r.checks:
        if c.name not in seen and c.name != CONTROL_CHECK:
            out.append((c.name, c.name, None))
    return out


def shorten(ids: Any) -> str:
    """At most `SHOWN` ids, then how many more."""
    ids = sorted(ids)
    head = ", ".join(i.replace(ANY_FORM, "*") for i in ids[:SHOWN])
    more = len(ids) - SHOWN
    return head + (f" and {more} more (all of them in claim_basis.forms)" if more > 0 else "")


def inventory(pid: str, a: Any = None) -> Optional[List[Tuple[str, str]]]:
    """(form id, check name) for every form `pid` can write, read from its probe module's tables
    (``VARIANTS``, ``FORMS``, ``POSITIONED``, ``ROLE_FORMS``) and `EXTRA_CHECKS`, or None for a
    property outside `FORM_LEVEL`. Those are judged check by check, and their modules hold no
    complete list of check names (P18's ``VARIANTS`` omits checks it writes), so before the run
    only a default basis covers them.

    A positioned form (P21) is listed at both positions, ``f`` and ``f@holder``. P22 lists the
    forms of the adapter's own role, P25 those of its ``disclosure_profile()`` (without the other
    profile's ``A_ISSUED_ONLY`` / ``B_HELD_ONLY`` forms) and P26 those of the variants its
    ``topology()`` runs (`TOPOLOGY_VARIANTS`); an adapter that names no known profile or topology
    gets every form. The control is never listed. A variant ``FORMS`` does not list stands as
    ``<variant>/`` + `ANY_FORM`. The list may hold forms a given run never writes (a holder-only
    target writes no position-``a`` form); it is used only to refuse a published run, so a form
    too many asks the adapter for one more statement, never for a weaker one. Reading the tables
    runs no probe and moves no version."""
    if pid not in FORM_LEVEL:
        return None
    from .properties import module
    m = module(pid)
    variants = getattr(m, "VARIANTS", None) or ()
    by_topology = getattr(m, "TOPOLOGY_VARIANTS", None)
    if isinstance(by_topology, Mapping):
        variants = by_topology.get(_ask(a, "topology"), variants)
    other: Any = set()
    if pid == "P25":
        other = {"a-issued": m.B_HELD_ONLY, "b-held": m.A_ISSUED_ONLY}.get(
            _ask(a, "disclosure_profile"), set())
    forms: Mapping[str, Any] = getattr(m, "FORMS", None) or {}
    role_forms = getattr(m, "ROLE_FORMS", None)
    if isinstance(role_forms, Mapping) and a is not None:
        try:
            role = str(a.role())
        except Exception:
            role = None
        if role in role_forms:
            forms = role_forms[role]
    positioned = getattr(m, "POSITIONED", ())
    out: List[Tuple[str, str]] = []
    for v in variants:
        fs = forms.get(v)
        if not fs:
            out.append((f"{v}/{ANY_FORM}", str(v)))
            continue
        for f in fs:
            if (v, f) in other or (v, "*") in other:
                continue
            out.append((f"{v}/{f}", str(v)))
            if v in positioned:
                out.append((f"{v}/{f}@holder", str(v)))
    out += [(c, c) for c in EXTRA_CHECKS.get(pid, ())]
    return out


def _ask(a: Any, name: str) -> Optional[str]:
    if a is None:
        return None
    try:
        v = getattr(a, name)()
    except Exception:
        return None
    return None if v is None else str(v)


def published(pid: str, flag: bool = False) -> bool:
    """Is `pid` run as published? `flag` (``run --published``) marks every property; otherwise a
    property whose plan (its module's ``PLAN_ENV``) sets ``trials`` to ``"published"`` is
    published. Any other run is a development run."""
    if flag:
        return True
    from .properties import module
    env = getattr(module(pid), "PLAN_ENV", None)
    raw = os.environ.get(env) if env else None
    if not raw:
        return False
    try:
        if raw.strip().startswith("{"):
            plan = json.loads(raw)
        else:
            with open(raw, encoding="utf-8") as fh:
                plan = json.load(fh)
    except (OSError, ValueError):
        return False                                # the probe reports a plan it cannot read
    return isinstance(plan, Mapping) and plan.get("trials") == "published"


def before_run(a: Any, st: Statement) -> List[str]:
    """What keeps a published run of `st.pid` from starting: a property with no statement at
    all, or the forms `unstated_before_run` names. Empty when it may
    start."""
    if st.empty():
        return [f"(no claim basis stated for {st.pid}: a published run must state not_claimed() "
                f"or claim_basis())"]
    return unstated_before_run(a, st)


def unstated_before_run(a: Any, st: Statement) -> List[str]:
    """The forms of `st.pid` that `st` neither states not claimed nor gives a basis, judged
    before the run from `inventory`. A property with no inventory is covered only by a default
    basis (``*``, or one for the whole property); without one the answer names the gap."""
    if st.empty() or st.whole:
        return []
    inv = inventory(st.pid, a)
    if inv is None:
        if "*" in st.basis or st.property_basis or "*" in st.not_claimed:
            return []
        return [f"(no form inventory for {st.pid}: state a default basis '*' or a basis for the "
                f"whole property)"]
    return [fid for fid, chk in inv
            if st.reason(fid, chk) is None and st.basis_for(fid, chk) is None]


_LABELS = re.compile(r"^((?:Library-level reading \(.*?\)\. )?(?:Development plan \(.*?\)\. )?)")


def _recheck(c: Check, entries: List[Tuple[str, Dict[str, Any]]], unclaimed: Dict[str, str]
             ) -> Check:
    """`c` re-read from its claimed forms only (point 2 of the module docstring)."""
    claimed = [(fid, e) for fid, e in entries if fid not in unclaimed]
    fails = [(fid, e) for fid, e in claimed if e.get("ok") is False]
    note = (f"claimed forms only ({len(unclaimed)} of {len(entries)} not claimed: "
            f"{', '.join(sorted(unclaimed))}); as read: {c.outcome}"
            f"{'' if c.ok is None else (' ok' if c.ok else ' VIOLATION')}; {c.detail}")
    if not claimed:
        return Check(c.name, NOT_CLAIMED.value, None, f"no form of this check is claimed; {note}")
    if fails:
        fid, e = fails[0]
        return Check(c.name, str(e.get("reading")), False, f"{fid}: {e.get('detail', '')}; {note}")
    if c.ok is False:
        if any(e.get("reading") == "inconclusive" for _f, e in claimed):
            return Check(c.name, "inconclusive", None, note)
        passes = sorted({str(e.get("reading")) for _f, e in claimed if e.get("ok") is True})
        if passes:
            return Check(c.name, "+".join(passes), True, note)
        return Check(c.name, str(claimed[0][1].get("reading")), None, note)
    if c.ok is True and not any(e.get("ok") is True for _f, e in claimed):
        return Check(c.name, str(claimed[0][1].get("reading")), None, note)
    return Check(c.name, c.outcome, c.ok, note)


def _derived(pid: str, extra: Dict[str, Any], checks: List[Check], probe_extra: Dict[str, Any],
             unclaimed: Dict[str, str]) -> Dict[str, Any]:
    """Point 6: recompute, in `extra`, the fields the probe derived from its
    forms, on claimed forms only. Unclaimed entries already read ``ok: None``. Returns the probe's
    own values."""
    was: Dict[str, Any] = {}
    forms = extra.get("forms") if isinstance(extra.get("forms"), Mapping) else {}
    if pid == "P21" and "dimensions_covered" in extra:
        from .properties import module
        m = module("P21")
        carried = extra.get("constraint_profile") or ()
        holder = bool(extra.get("grant_profile_holder_only"))
        was["dimensions_covered"] = copy.deepcopy(probe_extra.get("dimensions_covered"))
        extra["dimensions_covered"] = sorted({
            d for (v, f), ds in m.DIMS_OF.items() for d in ds if d in carried
            and ((forms.get(v) or {}).get(f"{f}@holder" if holder and v in m.POSITIONED else f)
                 or {}).get("ok") is True})
    if pid == "P22" and isinstance(extra.get("information"), Mapping):
        was["information"] = copy.deepcopy(probe_extra.get("information"))
        extra["information"] = {k: v for k, v in extra["information"].items()
                                if k not in unclaimed}
    if pid == "P23" and isinstance(extra.get("clauses"), Mapping):
        from .properties import module
        clause_of = module("P23").CLAUSE
        was["clauses"] = copy.deepcopy(probe_extra.get("clauses"))
        old_c = (extra["clauses"].get("c") or {}).get("failed") or []
        truth = [t for t in old_c if "/" in t and t.split(":", 1)[0] not in unclaimed]
        clauses: Dict[str, Dict[str, Any]] = {}
        for cl in sorted(extra["clauses"]):
            mine = [c for c in checks if clause_of.get(c.name) == cl]
            fl = [c.name for c in mine if c.ok is False]
            if cl == "c":
                fl = fl + truth
            ok = [c.name for c in mine if c.ok is True]
            clauses[cl] = {"reading": "fail" if fl else ("pass" if ok else "not_applicable"),
                           "failed": fl, "passed": ok}
        extra["clauses"] = clauses
    return was


def apply(r: Result, st: Statement, *, published: bool = False) -> Result:
    """`r` judged on claimed forms only. Returns `r` itself, unchanged, for an empty statement.
    With `published`, a pass or fail that would rest on a form claimed without a stated basis
    reads inconclusive instead (point 7)."""
    if st.empty():
        return r
    out = copy.deepcopy(r)
    extra = out.extra
    forms = forms_of(out)
    unclaimed: Dict[str, str] = {}
    table: Dict[str, Dict[str, Any]] = {}
    for fid, check, entry in forms:
        why = st.reason(fid, check)
        if why is not None:
            unclaimed[fid] = why
            row: Dict[str, Any] = {"not_claimed": why}
            if entry is not None:
                row.update(reading=entry.get("reading"), ok_as_read=entry.get("ok"))
                entry["ok_as_read"] = entry.get("ok")
                entry["ok"] = None
                entry["not_claimed"] = why
            table[fid] = row
        else:
            table[fid] = {"claim_basis": st.basis_for(fid, check)}
    checks: List[Check] = []
    for c in out.checks:
        entries = [(fid, e) for fid, chk, e in forms if chk == c.name and e is not None]
        if entries:
            mine = {fid: w for fid, w in unclaimed.items() if any(fid == f for f, _e in entries)}
            checks.append(_recheck(c, entries, mine) if mine else c)
        elif c.name in unclaimed:
            checks.append(Check(c.name, NOT_CLAIMED.value, None,
                                f"not claimed ({unclaimed[c.name]}); as read: {c.outcome}"
                                f"{'' if c.ok is None else (' ok' if c.ok else ' VIOLATION')}; "
                                f"{c.detail}"))
        else:
            checks.append(c)
    probe_as_read = {"status": r.status.value, "summary": r.summary,
                     "disclosure": (r.extra or {}).get("disclosure")}
    derived = _derived(st.pid, extra, checks, r.extra or {}, unclaimed)
    if derived:
        probe_as_read["derived"] = derived
    n_claimed = sum(1 for fid, _c, _e in forms if fid not in unclaimed)
    unstated = sorted(fid for fid, row in table.items()
                      if "claim_basis" in row and row["claim_basis"] is None)
    cb: Dict[str, Any] = {
        "schema": SCHEMA, "property_id": st.pid, "property": st.property_basis,
        "forms": table, "counts": {"forms": len(forms), "claimed": n_claimed,
                                   "not_claimed": len(unclaimed),
                                   "claimed_without_stated_basis": len(unstated)},
        "claimed_without_stated_basis": unstated, "probe_as_read": probe_as_read,
        "published": bool(published),
        "statement": {"not_claimed": dict(st.not_claimed), "whole": st.whole,
                      "claim_basis_patterns": sorted(st.basis)}}
    extra["claim_basis"] = cb
    if r.status not in (Status.PASS, Status.FAIL):
        out.checks = checks
        return out                                  # never turns these into a verdict
    labels = _LABELS.match(r.summary).group(1)
    missed = [str(x) for x in ((r.extra or {}).get(MUST_LAND_FIELD) or [])]
    nc = (f"{len(unclaimed)} of {len(forms)} forms not claimed, outside the verdict: "
          f"{shorten(unclaimed)}" if unclaimed else "every form claimed")
    fails = [c for c in checks if c.ok is False]
    common = dict(target=out.target, property_id=out.property_id, config=out.config,
                  target_version=out.target_version, vendor_claim=out.vendor_claim,
                  evidence_dir=out.evidence_dir, extra=extra, checks=checks,
                  control_detail=out.control_detail)
    tail = f" As the probe read every form: {r.status.value}: {r.summary}"
    if fails and r.status is not Status.FAIL:       # cannot happen: a claimed failing form
        raise AssertionError("the claim-basis rule never makes a result fail")  # failed before
    if published and unstated:
        new = Result.inconclusive(out.target, out.property_id,
                                  f"{labels}Published run, but {len(unstated)} claimed "
                                  f"form{'s' if len(unstated) != 1 else ''} with no stated claim "
                                  f"basis: {shorten(unstated)}; no verdict. "
                                  f"{nc}.{tail}", control_held=True,
                                  **{k: v for k, v in common.items()
                                     if k not in ("target", "property_id")})
    elif fails:
        bad = [f"{fid} ({e.get('reading')})" for fid, chk, e in forms
               if e is not None and fid not in unclaimed and e.get("ok") is False]
        bad += [f"{c.name} ({c.outcome})" for c in fails
                if not any(chk == c.name and e is not None for _f, chk, e in forms)]
        new = Result(status=Status.FAIL, control_held=True,
                     summary=f"{labels}Claimed forms only: fail on {', '.join(bad)}. {nc}.{tail}",
                     **common)
    elif any(c.ok is True for c in checks if c.name != CONTROL_CHECK) and missed:
        new = Result.inconclusive(out.target, out.property_id,
                                  f"{labels}Claimed forms only: no claimed form failed, but forms "
                                  f"that must land did not: {shorten(missed)}; no verdict. "
                                  f"{nc}.{tail}", control_held=True,
                                  **{k: v for k, v in common.items()
                                     if k not in ("target", "property_id")})
    elif any(c.ok is True for c in checks if c.name != CONTROL_CHECK):
        new = Result(status=Status.PASS, control_held=True,
                     summary=f"{labels}Claimed forms only: no violation on a claimed form. "
                             f"{nc}.{tail}", **common)
    elif n_claimed == 0:
        common.pop("control_detail")
        new = NotClaimedResult(status=Status.NOT_APPLICABLE, control_held=None,
                               control_detail=out.control_detail,
                               summary=f"{labels}No form of {out.property_id} has a claim basis "
                                       f"({nc}).{tail}", **common)
    else:
        new = Result.inconclusive(out.target, out.property_id,
                                  f"{labels}Claimed forms only: no claimed form landed with a "
                                  f"verdict. {nc}.{tail}", control_held=True,
                                  **{k: v for k, v in common.items()
                                     if k not in ("target", "property_id")})
    _disclosure(new, r, unclaimed)
    for name in ("run_at", "valid_until", "seed", "probe_version", "fixture_version",
                 "adapter_version", "environment", "hashed", "renewal", "unseeded", "known_bad"):
        setattr(new, name, copy.deepcopy(getattr(out, name)))
    return new


def _disclosure(new: Result, old: Result, unclaimed: Dict[str, str]) -> None:
    """Point 4: count claimed failing forms only; never raise the class."""
    extra = new.extra
    was = (old.extra or {}).get("disclosure")
    if was is None:
        return
    now = was
    if new.status is not Status.FAIL:
        now = "conformance"
    else:
        per_form = (old.extra or {}).get("disclosure_forms")
        if isinstance(per_form, Mapping) and was == "vulnerability":
            claimed_vuln = [k for k, v in per_form.items()
                            if k not in unclaimed and isinstance(v, Mapping)
                            and v.get("class") == "vulnerability"]
            now = "vulnerability" if claimed_vuln else "conformance"
    if RANK.get(now, 1) > RANK.get(was, 1):
        now = was                                   # never raised
    extra["disclosure"] = now
    extra["claim_basis"]["disclosure_basis"] = (
        "per form (extra.disclosure_forms), claimed forms only"
        if isinstance((old.extra or {}).get("disclosure_forms"), Mapping)
        else "the probe's class, lowered to conformance when no claimed form fails")


def not_claimed_result(a: Any, pid: str, st: Statement, *, evidence_dir: str) -> Result:
    """The result for a property the adapter states is not claimed at all; the probe is not
    run."""
    vc = {}
    try:
        vc = a.vendor_claims() or {}
    except Exception:
        pass
    r = NotClaimedResult(target=a.name, property_id=pid, status=Status.NOT_APPLICABLE,
                         summary=f"not claimed: {st.whole}", control_held=None,
                         config=a.config, target_version=a.version(),
                         vendor_claim=vc.get(pid, "not stated"), evidence_dir=evidence_dir)
    r.extra["claim_basis"] = {"schema": SCHEMA, "property_id": pid, "property": None,
                              "forms": {}, "whole": st.whole,
                              "counts": {"forms": 0, "claimed": 0, "not_claimed": 0,
                                         "claimed_without_stated_basis": 0},
                              "statement": {"not_claimed": dict(st.not_claimed),
                                            "whole": st.whole,
                                            "claim_basis_patterns": sorted(st.basis)}}
    return r


def stamp(r: Result) -> Result:
    """After `validity.stamp`: a result that used the rule records the rule's version and lists
    it in its renewal condition."""
    cb = (r.extra or {}).get("claim_basis")
    if not isinstance(cb, dict):
        return r
    cb["rule_version"] = rule_version()
    lapses = r.renewal.setdefault("lapses_on_change", [])
    if RENEWAL_FIELD not in lapses:
        lapses.append(RENEWAL_FIELD)
    return r


def result_doc(r: Result) -> Dict[str, Any]:
    """`r` as written to result.json: `claim_basis` and `claim_rule_version` as fields of the
    record (Appendix B) when the rule was used; otherwise exactly `r.to_doc()`."""
    d = r.to_doc()
    cb = (d.get("extra") or {}).pop("claim_basis", None)
    if cb is not None:
        d["claim_basis"] = cb
        if cb.get("rule_version"):
            d[RENEWAL_FIELD] = cb["rule_version"]
    return d


def status_of(doc_or_result: Any) -> str:
    if isinstance(doc_or_result, Result):
        return doc_or_result.status.value
    return str((doc_or_result or {}).get("status"))


def exact(form_id: str) -> str:
    """A pattern that matches `form_id` and nothing else."""
    return "".join(f"[{ch}]" if ch in "*?[" else ch for ch in form_id)


def _failing(r: Result) -> List[str]:
    out = []
    for fid, chk, e in forms_of(r):
        if e is not None and e.get("ok") is False:
            out.append(fid)
        elif e is None and any(c.name == chk and c.ok is False for c in r.checks):
            out.append(fid)
    return out


def _holding(r: Result) -> List[str]:
    out = []
    for fid, chk, e in forms_of(r):
        if e is not None and e.get("ok") is True:
            out.append(fid)
        elif e is None and any(c.name == chk and c.ok is True for c in r.checks):
            out.append(fid)
    return out


def gate_cases(pid: str, runs: List[Tuple[str, Status, Result]]) -> List[Dict[str, Any]]:
    """The known-bad gate's ``claims:`` cases for `pid` (spec §3.10 rule 1: a change to a verdict
    rule passes a known-bad run). Built from the toys' own results, so no toy is added and no
    fixture moves. From the first toy that must fail and failed:

    - ``claims:fails-only-unclaimed``: every failing form is stated not claimed. It MUST NOT fail:
      it reads ``pass`` where a claimed form holds (else ``inconclusive``, or ``not_claimed``
      where no form is claimed);
    - ``claims:fails-on-a-claimed-form``: every form but one failing form is stated not claimed.
      It MUST still fail;
    - ``claims:no-statement``: an empty statement. The result MUST come back unchanged.

    - ``claims:every-form-unclaimed``: every form is stated not claimed. It MUST read
      ``not_claimed``; a ``control`` check is not a form and cannot make it pass;
    - ``claims:must-land-missed``: as ``fails-only-unclaimed``, with a form that must land listed
      as missed (`MUST_LAND_FIELD`). Where ``fails-only-unclaimed`` reads ``pass`` it MUST read
      ``inconclusive``; otherwise the same.

    From the first toy that must pass and passed, ``claims:passes-some-unclaimed``: every other
    holding form is stated not claimed. It MUST still pass. In every case the disclosure class
    MUST NOT be raised."""
    out: List[Dict[str, Any]] = []
    src_fail = next(((c, r) for c, req, r in runs if req is Status.FAIL
                     and r.status is Status.FAIL and _failing(r)), None)
    src_pass = next(((c, r) for c, req, r in runs if req is Status.PASS
                     and r.status is Status.PASS and _holding(r)), None)

    def disc(x: Result) -> int:
        return RANK.get((x.extra or {}).get("disclosure") or "conformance", 1)

    def case(name: str, src: str, base: Result, st: Statement, need: Any,
             extra_ok: bool = True) -> None:
        try:
            got = apply(base, st)
            ok = (got.status == need and disc(got) <= disc(base) and extra_ok
                  and (base.status is Status.FAIL or got.status is not Status.FAIL))
            out.append({"config": f"claims:{name}", "from": src, "required": str(need.value),
                        "got": got.status.value, "summary": got.summary[:300], "ok": bool(ok),
                        "not_claimed": sorted(st.not_claimed)[:50],
                        "disclosure": [(base.extra or {}).get("disclosure"),
                                       (got.extra or {}).get("disclosure")]})
        except Exception as e:                       # a rule that raises fails its case
            out.append({"config": f"claims:{name}", "from": src, "required": str(need.value),
                        "got": "raised", "summary": f"{type(e).__name__}: {e}"[:300],
                        "ok": False})

    if src_fail:
        src, r = src_fail
        failing = _failing(r)
        every = [fid for fid, _c, _e in forms_of(r)]
        st = Statement(pid, not_claimed={exact(f): "gate: stated not claimed" for f in failing})
        left = [f for f in every if f not in failing]
        holds = [f for f in _holding(r) if f not in failing]
        need = Status.PASS if holds else (NOT_CLAIMED if not left else Status.INCONCLUSIVE)
        case("fails-only-unclaimed", src, r, st, need)
        keep = failing[0]
        st = Statement(pid, not_claimed={exact(f): "gate: stated not claimed"
                                         for f in every if f != keep})
        case("fails-on-a-claimed-form", src, r, st, Status.FAIL)
        same = apply(r, Statement(pid))
        out.append({"config": "claims:no-statement", "from": src, "required": r.status.value,
                    "got": same.status.value, "summary": same.summary[:300],
                    "ok": same is r and same.to_doc() == r.to_doc()})
        # Every form but a check named "control", spelled out here rather than read from
        # CONTROL_CHECK, so a rule that read the control as a form would pass this case and fail it.
        real = [fid for fid, chk, _e in forms_of(r) if chk != "control"]
        case("every-form-unclaimed", src, r,
             Statement(pid, not_claimed={exact(f): "gate: stated not claimed" for f in real}),
             NOT_CLAIMED)
        missed = copy.deepcopy(r)
        missed.extra[MUST_LAND_FIELD] = ["gate/must-land"]
        st = Statement(pid, not_claimed={exact(f): "gate: stated not claimed" for f in failing})
        case("must-land-missed", src, missed, st,
             Status.INCONCLUSIVE if need is Status.PASS else need)
    if src_pass:
        src, r = src_pass
        holds = _holding(r)
        drop = holds[1::2]
        if drop:
            st = Statement(pid, not_claimed={exact(f): "gate: stated not claimed" for f in drop})
            case("passes-some-unclaimed", src, r, st, Status.PASS)
    return out
