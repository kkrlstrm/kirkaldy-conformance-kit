#!/usr/bin/env python3
"""Synthetic Operations effect-observer example. Python 3.10+, standard library."""
import json
import sqlite3
import tempfile
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class Scope:
    test_run_id: str
    account_id: str
    operation_id: str


@dataclass(frozen=True)
class Observation:
    scope: Scope
    status: str  # observed = complete; unavailable = cannot establish completeness
    effect_ids: tuple[str, ...] = ()
    reason: str = ""


class EffectObserver(Protocol):
    def observe(self, scope: Scope) -> Observation: ...


class SQLiteObserver:
    """Read physical test effects independently from the receiver's response cache."""
    def __init__(self, path: Path, unavailable: bool = False):
        self.path = path
        self.unavailable = unavailable

    def observe(self, scope: Scope) -> Observation:
        if self.unavailable:
            return Observation(scope, "unavailable", reason="synthetic_observer_outage")
        try:
            with closing(sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
                rows = db.execute(
                    "SELECT effect_id FROM effects WHERE run_id=? AND account_id=? "
                    "AND operation_id=? ORDER BY effect_id",
                    (scope.test_run_id, scope.account_id, scope.operation_id),
                ).fetchall()
            return Observation(scope, "observed", tuple(row[0] for row in rows))
        except sqlite3.Error:
            return Observation(scope, "unavailable", reason="effect_store_unreachable")


class TestCompany:
    """Locally owned receiver: safe replay or deliberately creates a duplicate."""
    def __init__(self, path: Path, duplicate: bool = False):
        self.path = path
        self.duplicate = duplicate
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("CREATE TABLE effects (effect_id TEXT PRIMARY KEY, run_id TEXT, account_id TEXT, operation_id TEXT)")
            db.execute("CREATE TABLE receipts (run_id TEXT, account_id TEXT, operation_id TEXT, response TEXT, PRIMARY KEY(run_id,account_id,operation_id))")

    def execute(self, scope: Scope) -> str:
        key = (scope.test_run_id, scope.account_id, scope.operation_id)
        with closing(sqlite3.connect(self.path)) as db, db:
            prior = db.execute("SELECT response FROM receipts WHERE run_id=? AND account_id=? AND operation_id=?", key).fetchone()
            if prior and not self.duplicate:
                return prior[0]
            count = db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
            effect_id = f"return-{count + 1}"
            db.execute("INSERT INTO effects VALUES (?,?,?,?)", (effect_id, *key))
            if prior:
                # Intentional fault: perform a second action but return original response.
                return prior[0]
            response = json.dumps({"result": "performed", "return_id": effect_id}, sort_keys=True)
            db.execute("INSERT INTO receipts VALUES (?,?,?,?)", (*key, response))
            return response


def valid(obs: Observation, scope: Scope) -> bool:
    return (isinstance(obs, Observation) and obs.scope == scope
            and obs.status == "observed" and isinstance(obs.effect_ids, tuple)
            and all(isinstance(x, str) and x for x in obs.effect_ids)
            and len(obs.effect_ids) == len(set(obs.effect_ids)))


def observe_safely(observer: EffectObserver, scope: Scope) -> Observation:
    try:
        result = observer.observe(scope)
    except Exception:
        return Observation(scope, "unavailable", reason="observer_exception")
    if not valid(result, scope):
        return Observation(scope, "unavailable", reason="observation_unavailable_or_invalid")
    return result


def check_lost_response(company: TestCompany, observer: EffectObserver, scope: Scope) -> dict:
    """Fixture-specific check of a synchronous synthetic return action."""
    before = observe_safely(observer, scope)
    if before.status != "observed":
        return {"verdict": "INCONCLUSIVE", "reason": "baseline_unavailable_or_invalid", "before": asdict(before)}
    if before.effect_ids:
        return {"verdict": "INCONCLUSIVE", "reason": "test_scope_not_empty", "before": asdict(before)}
    try:
        # Capture and suppress delivery locally; this is not an HTTP fault injector.
        first_captured = company.execute(scope)
        after_first = observe_safely(observer, scope)
        retry_response = company.execute(scope)
        after_retry = observe_safely(observer, scope)
    except Exception:
        # The adapter/fault injection did not complete this synchronous scenario.
        return {"verdict": "INCONCLUSIVE", "reason": "execution_or_capture_error"}
    result = {"before": asdict(before), "after_first": asdict(after_first),
              "after_retry": asdict(after_retry), "first_captured": first_captured,
              "retry_response": retry_response, "responses_byte_equal": first_captured == retry_response}
    # Preserve independently observed failures, even if another observation is missing.
    for observation in (after_first, after_retry):
        if observation.status == "observed" and len(observation.effect_ids) > 1:
            return {"verdict": "FAIL", "reason": "effects_changed_or_duplicated_on_retry", **result}
    if after_first.status != "observed" or after_retry.status != "observed":
        return {"verdict": "INCONCLUSIVE", "reason": "effect_observation_unavailable_or_invalid", **result}
    if len(after_first.effect_ids) != 1:
        return {"verdict": "FAIL", "reason": "first_attempt_did_not_produce_one_effect", **result}
    if after_retry.effect_ids != after_first.effect_ids:
        return {"verdict": "FAIL", "reason": "effects_changed_or_duplicated_on_retry", **result}
    try:
        first = json.loads(first_captured)
        retry = json.loads(retry_response)
    except (ValueError, TypeError):
        return {"verdict": "FAIL", "reason": "invalid_fixture_response", **result}
    # These are the complete response semantics of THIS synthetic return action.
    # Real adapters need an action-specific comparator; do not compare arbitrary JSON.
    expected = {"result": "performed", "return_id": after_first.effect_ids[0]}
    if first != expected or retry != expected:
        return {"verdict": "FAIL", "reason": "retry_response_differs", **result}
    return {"verdict": "PASS", "reason": "one_stable_effect_and_equivalent_response", **result}


def run_case(mode: str) -> dict:
    if mode not in ("safe", "duplicate", "unavailable"):
        raise ValueError("Unknown demonstration mode")
    with tempfile.TemporaryDirectory(prefix="poppy-observer-") as tmp:
        path = Path(tmp) / "effects.sqlite"
        company = TestCompany(path, duplicate=(mode == "duplicate"))
        observer = SQLiteObserver(path)
        if mode == "unavailable":
            class GoesUnavailable:
                def __init__(self): self.calls = 0
                def observe(self, scope):
                    self.calls += 1
                    if self.calls == 1: return observer.observe(scope)
                    return Observation(scope, "unavailable", reason="synthetic_observer_outage")
            observer_for_check = GoesUnavailable()
        else:
            observer_for_check = observer
        result = check_lost_response(company, observer_for_check, Scope("run-1", "test-account", "operation-1"))
        return {"case": mode, **result}


def main():
    outcomes = [run_case(mode) for mode in ("safe", "duplicate", "unavailable")]
    print(json.dumps({"scope": "synthetic local demonstration; not Poppy conformance", "cases": outcomes}, indent=2))
    expected = [("PASS", "one_stable_effect_and_equivalent_response"),
                ("FAIL", "effects_changed_or_duplicated_on_retry"),
                ("INCONCLUSIVE", "effect_observation_unavailable_or_invalid")]
    if [(r["verdict"], r["reason"]) for r in outcomes] != expected:
        raise SystemExit("Unexpected outcome")


if __name__ == "__main__": main()
