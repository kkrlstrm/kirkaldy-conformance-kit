import tempfile
import unittest
from pathlib import Path
from observer_demo import Observation, Scope, SQLiteObserver, TestCompany, check_lost_response, run_case


class CheckTests(unittest.TestCase):
    def test_safe(self):
        result = run_case("safe")
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["after_first"]["effect_ids"], ("return-1",))
        self.assertEqual(result["after_retry"]["effect_ids"], ("return-1",))

    def test_duplicate_same_response(self):
        result = run_case("duplicate")
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(result["responses_byte_equal"])
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

    def test_equivalent_json_formatting_passes(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"db"; company=TestCompany(p)
            class Reformatted:
                calls=0
                def execute(self, scope):
                    self.calls+=1; value=company.execute(scope)
                    return value if self.calls==1 else json.dumps(json.loads(value), indent=2)
            result=check_lost_response(Reformatted(), SQLiteObserver(p), Scope("r","a","o"))
            self.assertEqual(result["verdict"], "PASS")
            self.assertFalse(result["responses_byte_equal"])

    def test_bad_observations_are_inconclusive(self):
        for bad in (None, {}, "x", Observation(Scope("r","a","o"), "observed", "x"),
                    Observation(Scope("r","a","o"), "observed", ([],))):
            class Broken:
                def observe(self, scope): return bad
            with self.subTest(bad=repr(bad)), tempfile.TemporaryDirectory() as d:
                result=check_lost_response(TestCompany(Path(d)/"db"), Broken(), Scope("r","a","o"))
                self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_observer_exception_is_inconclusive(self):
        class Broken:
            def observe(self, scope): raise TimeoutError()
        with tempfile.TemporaryDirectory() as d:
            result=check_lost_response(TestCompany(Path(d)/"db"), Broken(), Scope("r","a","o"))
            self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_missing_store_is_unavailable(self):
        with tempfile.TemporaryDirectory() as d:
            obs=SQLiteObserver(Path(d)/"absent").observe(Scope("r","a","o"))
            self.assertEqual(obs.status, "unavailable")

    def test_execution_error_is_inconclusive(self):
        class Broken:
            def execute(self, scope): raise RuntimeError()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"db"; TestCompany(p)
            self.assertEqual(check_lost_response(Broken(), SQLiteObserver(p), Scope("r","a","o"))["verdict"], "INCONCLUSIVE")

    def test_known_duplicate_survives_later_observer_outage(self):
        scope=Scope("r","a","o")
        class Observations:
            calls=0
            def observe(self, s):
                self.calls+=1
                return [Observation(s,"observed"), Observation(s,"observed",("one","two")),
                        Observation(s,"unavailable")][self.calls-1]
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(check_lost_response(TestCompany(Path(d)/"db"), Observations(),scope)["verdict"], "FAIL")

    def test_wrong_effect_id_in_response_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"db"; company=TestCompany(p)
            class Lying:
                def execute(self, scope):
                    company.execute(scope)
                    return '{"result":"performed","return_id":"wrong"}'
            self.assertEqual(check_lost_response(Lying(), SQLiteObserver(p), Scope("r","a","o"))["verdict"], "FAIL")

if __name__ == "__main__": unittest.main()
