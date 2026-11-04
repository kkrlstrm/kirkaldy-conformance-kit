"""When a verdict stops being valid (spec §3.5).

A verdict is evidence about one build, in one configuration, measured with one version of the
probe and its fixtures, at one time. It lapses on any change to those, and in any case
`MAX_AGE_MONTHS` after the run. The runner stamps every result with what it needs for that
(`stamp`); `validity` and `still_valid` read a stamped result against the current state.

The renewal condition is data in the result:

    "renewal": {"schema": "kirkaldy.renewal/0.1",
                "lapses_on_change": ["target_version", "config", "probe_version",
                                     "fixture_version", "adapter_version",
                                     "environment.python", ...],
                "max_age_months": 12}

Each name in `lapses_on_change` is a field of the result itself (`environment.<k>` is a key of
its `environment`), so the recorded value sits beside the condition that refers to it.

The four states, and which way each fails:

- ``valid``: every listed field was given a current value and matches, and the age limit has
  not passed.
- ``lapsed``: a listed field differs, or the age limit has passed (or `valid_until` has, if it
  is earlier). Lapse reasons win over everything else.
- ``unknown``: the result carries no renewal condition (written before this module existed, or
  built outside the runner), its dates cannot be read, or a listed field was not given a
  current value. Never reported as valid.
- ``no-verdict``: the result is inconclusive, so there is no verdict to keep valid; or it is a
  `pass` or `fail` that carries no successful known-bad run recorded, before the run, for the
  same probe and fixture versions (`known_bad`; `conformance.knownbad`). Such a verdict was
  never established, so it has nothing to lapse.

`not_applicable` results carry the same renewal condition and lapse the same way: a new
version of the target may add the mechanism. They are not produced by a probe, so the
known-bad requirement does not apply to them.

Times are UTC. The age limit is counted in calendar months from `run_at`: the same day and time
twelve months later, or the last day of that month when it has no such day. Every field the
renewal condition lists, the target version included, is compared as an exact string, so a
target version with `+dirty` (uncommitted changes) differs from the same commit without it.
"""
from __future__ import annotations

import calendar
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

from .result import Result

MAX_AGE_MONTHS = 12
RENEWAL_SCHEMA = "kirkaldy.renewal/0.1"
CHANGE_FIELDS = ("target_version", "config", "probe_version", "fixture_version",
                 "adapter_version")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

VALID, LAPSED, UNKNOWN, NO_VERDICT = "valid", "lapsed", "unknown", "no-verdict"


def new_seed() -> int:
    """A fresh 64-bit run seed, as P16 has always drawn one."""
    return int.from_bytes(os.urandom(8), "big")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def fmt(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime(TIME_FORMAT)


def parse_time(s: Any) -> Optional[datetime]:
    if not isinstance(s, str) or not s:
        return None
    try:
        t = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else None           # a time without a zone is not a UTC time


def add_months(t: datetime, months: int) -> datetime:
    """Calendar months; a day the target month lacks is clamped (29 Feb -> 28 Feb)."""
    m = t.month - 1 + months
    year, month = t.year + m // 12, m % 12 + 1
    return t.replace(year=year, month=month, day=min(t.day, calendar.monthrange(year, month)[1]))


def renewal_condition(environment: Mapping[str, str]) -> Dict[str, Any]:
    return {"schema": RENEWAL_SCHEMA,
            "lapses_on_change": list(CHANGE_FIELDS) + [f"environment.{k}"
                                                       for k in sorted(environment)],
            "max_age_months": MAX_AGE_MONTHS}


def stamp(result: Result, *, run_at: datetime, seed: Optional[int],
          measured: Mapping[str, Any], unseeded: Optional[List[str]] = None,
          target_version: str = "", known_bad: Optional[Mapping[str, Any]] = None) -> Result:
    """Fill in what `validity` needs. `measured` is `versions.snapshot(...)`; `known_bad` is
    `knownbad.reference(...)` of the record the run relied on, or None."""
    result.run_at = fmt(run_at)
    result.valid_until = fmt(add_months(run_at.astimezone(timezone.utc), MAX_AGE_MONTHS))
    result.seed = seed
    result.probe_version = measured["probe_version"]
    result.fixture_version = measured["fixture_version"]
    result.adapter_version = measured["adapter_version"]
    result.environment = dict(measured.get("environment") or {})
    result.hashed = dict(measured.get("hashed") or {})
    result.renewal = renewal_condition(result.environment)
    result.unseeded = list(unseeded or [])
    result.known_bad = dict(known_bad or {})
    if not result.target_version and target_version:
        result.target_version = target_version
    return result


@dataclass
class Validity:
    state: str
    reasons: List[str] = field(default_factory=list)
    checked: Dict[str, Any] = field(default_factory=dict)
    """Each listed field -> {"recorded": ..., "current": ...}."""

    @property
    def valid(self) -> bool:
        return self.state == VALID


def _doc(result: Union[Result, Mapping[str, Any]]) -> Mapping[str, Any]:
    if isinstance(result, Result):
        from .claim_basis import result_doc        # the record as written (Appendix B)
        return result_doc(result)
    return result


def validity(result: Union[Result, Mapping[str, Any]], *, now: datetime,
             target_version: Optional[str], config: Optional[str],
             probe_version: Optional[str], fixture_version: Optional[str],
             adapter_version: Optional[str] = None,
             environment: Optional[Mapping[str, str]] = None,
             claim_rule_version: Optional[str] = None) -> Validity:
    """Is `result` still valid at `now`, for a target, configuration, probe, fixtures, adapter
    and environment in the state given? A current value of None means "not given": a field
    the renewal condition lists and that is not given makes the answer unknown, not valid.
    `claim_rule_version` is the current claim-basis rule (`claim_basis.rule_version`); only a
    result judged on its claimed forms lists it."""
    try:
        doc = _doc(result)
    except Exception as e:  # a malformed Result object
        return Validity(UNKNOWN, [f"the result cannot be read ({type(e).__name__}: {e})"])
    if not isinstance(doc, Mapping):
        return Validity(UNKNOWN, [f"the result is a {type(doc).__name__}, not a result record"])
    if doc.get("status") == "inconclusive":
        return Validity(NO_VERDICT, ["the result is inconclusive: there is no verdict to keep "
                                     "valid"])
    renewal = doc.get("renewal")
    if not isinstance(renewal, Mapping) or not renewal.get("lapses_on_change"):
        return Validity(UNKNOWN, ["validity unknown: the result carries no renewal condition "
                                  "(written before verdict expiry was recorded, or not by the "
                                  "runner); re-run it"])
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise TypeError("now must be a timezone-aware datetime")
    if doc.get("status") in ("pass", "fail"):
        missing = known_bad_problem(doc)
        if missing:
            return Validity(NO_VERDICT, [missing])

    lapsed: List[str] = []
    unknown: List[str] = []
    checked: Dict[str, Any] = {}

    run_at, until = parse_time(doc.get("run_at")), parse_time(doc.get("valid_until"))
    max_age = renewal.get("max_age_months")
    if run_at is None:
        unknown.append(f"run_at {doc.get('run_at')!r} is not a UTC time")
    elif not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0:
        unknown.append(f"max_age_months {max_age!r} is not a positive whole number")
    else:
        # Never later than the kit's own limit, whatever the record says.
        limit = add_months(run_at, min(max_age, MAX_AGE_MONTHS))
        if until is not None and until < limit:
            limit = until
        elif until is None:
            unknown.append(f"valid_until {doc.get('valid_until')!r} is not a UTC time")
        checked["age"] = {"run_at": fmt(run_at), "valid_until": fmt(limit), "now": fmt(now)}
        if now < run_at:
            unknown.append(f"run_at {fmt(run_at)} is after now ({fmt(now)})")
        elif now >= limit:
            lapsed.append(f"age: run {fmt(run_at)}, valid until {fmt(limit)}, now {fmt(now)} "
                          f"(at most {MAX_AGE_MONTHS} months)")

    current = {"target_version": target_version, "config": config,
               "probe_version": probe_version, "fixture_version": fixture_version,
               "adapter_version": adapter_version, "claim_rule_version": claim_rule_version}
    env_now = dict(environment) if environment is not None else None
    env_then = doc.get("environment") if isinstance(doc.get("environment"), Mapping) else {}
    for name in renewal["lapses_on_change"]:
        if not isinstance(name, str):
            unknown.append(f"the renewal condition lists {name!r}, which is not a field name")
            continue
        if name.startswith("environment."):
            key = name.split(".", 1)[1]
            recorded = env_then.get(key)
            now_v = None if env_now is None else env_now.get(key)
        elif name in current:
            recorded, now_v = doc.get(name), current[name]
        else:
            unknown.append(f"{name}: the renewal condition lists a field this kit cannot check")
            continue
        checked[name] = {"recorded": recorded, "current": now_v}
        if recorded in (None, ""):
            unknown.append(f"{name}: the result records no value")
        elif now_v is None:
            unknown.append(f"{name}: no current value given, so a change cannot be ruled out")
        elif now_v != recorded:
            lapsed.append(f"{name} changed: recorded {recorded!r}, now {now_v!r}")

    if lapsed:
        return Validity(LAPSED, lapsed + unknown, checked)
    if unknown:
        return Validity(UNKNOWN, unknown, checked)
    return Validity(VALID, [f"nothing listed changed, and it is valid until "
                            f"{checked['age']['valid_until']}"], checked)


def known_bad_problem(doc: Mapping[str, Any]) -> Optional[str]:
    """Why `doc` (a pass or fail) does not show a successful known-bad run recorded before it
    for its own probe and fixture versions; None when it does."""
    kb = doc.get("known_bad")
    hint = (f"run `python -m conformance known-bad --record -p {doc.get('property_id', '?')}`, "
            f"then re-run the probe")
    if not isinstance(kb, Mapping) or not kb:
        return ("no verdict: no known-bad run was recorded for this probe and fixture version "
                f"before the run (spec §3.5); {hint}")
    if kb.get("ok") is not True:
        return f"no verdict: the known-bad run {kb.get('record_id')!r} it cites did not pass; {hint}"
    for name in ("probe_version", "fixture_version"):
        if not kb.get(name) or kb.get(name) != doc.get(name):
            return (f"no verdict: the known-bad run {kb.get('record_id')!r} checked "
                    f"{name} {kb.get(name)!r}, not the {doc.get(name)!r} this result ran with; "
                    f"{hint}")
    rule = doc.get("claim_rule_version")
    if rule and kb.get("claim_rule_version") != rule:
        return (f"no verdict: the result was judged on its claimed forms under claim-basis rule "
                f"{rule!r}, and the known-bad run {kb.get('record_id')!r} did not check that rule "
                f"(it records {kb.get('claim_rule_version')!r}); {hint}")
    at, run_at = parse_time(kb.get("recorded_at")), parse_time(doc.get("run_at"))
    if at is None:
        return f"no verdict: the known-bad run's time {kb.get('recorded_at')!r} cannot be read"
    if run_at is not None and at > run_at:
        return (f"no verdict: the known-bad run was recorded at {fmt(at)}, after the run "
                f"({fmt(run_at)})")
    return None


def still_valid(result: Union[Result, Mapping[str, Any]], *, now: datetime,
                target_version: Optional[str], config: Optional[str],
                probe_version: Optional[str], fixture_version: Optional[str],
                adapter_version: Optional[str] = None,
                environment: Optional[Mapping[str, str]] = None,
                claim_rule_version: Optional[str] = None) -> Tuple[bool, List[str]]:
    """(True, why) only when `validity` says valid; (False, reasons) for lapsed, unknown
    (including every result written before verdict expiry) and no verdict."""
    v = validity(result, now=now, target_version=target_version, config=config,
                 probe_version=probe_version, fixture_version=fixture_version,
                 adapter_version=adapter_version, environment=environment,
                 claim_rule_version=claim_rule_version)
    return v.valid, ([] if v.valid else [f"{v.state}"]) + v.reasons
