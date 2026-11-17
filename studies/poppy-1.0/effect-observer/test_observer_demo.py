import tempfile
import unittest
from pathlib import Path
from observer_demo import EffectObserver, Observation, Scope, SQLiteObserver, TestCompany, check_lost_response, run_case


class CheckTests(unittest.TestCase):
    def test_safe(self):
        result = run_case("safe")
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["after_first"]["effect_ids"], ("return-1",))
        self.assertEqual(result["after_retry"]["effect_ids"], ("return-1",))

    def test_duplicate_same_response(self):
        result = run_case("duplicate")
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(result["responses_equal"])
        self.assertEqual(len(result["after_retry"]["effect_ids"]), 2)

    def test_missing_effect_observation(self):
        self.assertEqual(run_case("unavailable")["verdict"], "INCONCLUSIVE")

    def test_scope_mismatch_never_passes(self):
        class WrongScope:
            def observe(self, scope): return Observation(Scope("other", scope.account_id, scope.operation_id), "observed")
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(check_lost_response(TestCompany(Path(d)/"db"), WrongScope(), Scope("r","a","o"))["verdict"], "INCONCLUSIVE")

    def test_duplicate_effect_ids_never_pass(self):
        class DuplicateIDs:
            def observe(self, scope): return Observation(scope, "observed", ("x", "x"))
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(check_lost_response(TestCompany(Path(d)/"db"), DuplicateIDs(), Scope("r","a","o"))["verdict"], "INCONCLUSIVE")

    def test_preexisting_effect_is_not_a_fresh_test(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"db"; company=TestCompany(p); scope=Scope("r","a","o"); company.execute(scope)
            self.assertEqual(check_lost_response(company, SQLiteObserver(p), scope)["verdict"], "INCONCLUSIVE")

    def test_mismatched_retry_response_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"db"; company=TestCompany(p); scope=Scope("r","a","o")
            class BadResponse:
                calls=0
                def execute(self, s):
                    self.calls+=1; actual=company.execute(s)
                    return actual if self.calls==1 else '{"result":"different"}'
            self.assertEqual(check_lost_response(BadResponse(), SQLiteObserver(p), scope)["reason"], "retry_response_differs")

if __name__ == "__main__": unittest.main()
