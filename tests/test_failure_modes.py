"""Pins for the measurement failure modes in docs/FAILURE-MODES.md (KRK-M*) that are not
already pinned elsewhere. Each test shows the failure would happen, then that it does not."""
import subprocess
from pathlib import Path

import pytest

from conformance.evidence import Evidence
from conformance.mockserver import MockServer
from conformance.properties import ALL
from conformance.result import Status
from known_bad.toys import TOYS

def _run(pid, toy, tag, tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    toy.start()
    try:
        return ALL[pid].probe(toy, Evidence("t", toy.name, pid, tag), run_tag=tag)
    finally:
        toy.stop()


def test_KRK_M1_one_attempt_per_outage_reads_a_delayed_fail_open_as_closed(tmp_path, monkeypatch):
    """The bad gateway refuses the first request after its decider goes down and lets the rest
    through. One attempt per outage calls that fail-closed; the probe's repeats do not."""
    monkeypatch.setattr("conformance.properties.p1_failure_direction.REPEATS", 1)
    assert _run("P1", TOYS["P1"]("bad"), "once", tmp_path, monkeypatch).status is Status.PASS
    monkeypatch.setattr("conformance.properties.p1_failure_direction.REPEATS", 3)
    assert _run("P1", TOYS["P1"]("bad"), "thrice", tmp_path, monkeypatch).status is Status.FAIL


def test_KRK_M3_a_failure_that_was_never_induced_gives_no_verdict(tmp_path, monkeypatch):
    """`docker compose stop` without its env vars fails and leaves the database up. Every
    request is then judged against a healthy decider. The probe checks the decider independently
    and refuses to judge a mode it could not induce."""
    toy = TOYS["P1"]("good")
    toy.induce_does_nothing = True
    r = _run("P1", toy, "noop", tmp_path, monkeypatch)
    assert r.status is Status.INCONCLUSIVE, r.summary


def test_KRK_M9_the_mock_upstream_returns_a_new_completion_id_every_time():
    """A gateway that keys its usage log on the upstream's completion id. A mock that returned
    one id for everything made every logged request after the first vanish, silently."""
    import json
    import urllib.request
    m = MockServer()
    try:
        ids = set()
        for _ in range(3):
            req = urllib.request.Request(f"{m.url}/v1/chat/completions", method="POST",
                                         data=json.dumps({"model": "x", "messages": []}).encode(),
                                         headers={"Content-Type": "application/json"})
            ids.add(json.loads(urllib.request.urlopen(req).read())["id"])
        assert len(ids) == 3
    finally:
        m.close()


def test_scripted_mock_streams_openai_tool_calls():
    """Agent runtimes commonly require SSE even when gateway probes use plain JSON."""
    import json
    import urllib.request
    m = MockServer()
    try:
        script = {"messages": [{"tool_calls": [{
            "id": "call_1", "type": "function",
            "function": {"name": "shell", "arguments": '{"command":"true"}'},
        }]}]}
        urllib.request.urlopen(urllib.request.Request(
            f"{m.url}/__script", method="POST", data=json.dumps(script).encode(),
            headers={"Content-Type": "application/json"})).read()
        body = {"model": "mock", "messages": [], "tools": [{"type": "function"}],
                "stream": True}
        req = urllib.request.Request(f"{m.url}/v1/chat/completions", method="POST",
                                     data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as response:
            raw = response.read().decode()
            assert response.headers["Content-Type"] == "text/event-stream"
        events = [line.removeprefix("data: ") for line in raw.splitlines()
                  if line.startswith("data: ") and line != "data: [DONE]"]
        chunks = [json.loads(event) for event in events]
        assert chunks[0]["choices"][0]["delta"]["tool_calls"][0]["function"]["name"] == "shell"
        assert chunks[-1]["choices"][0]["finish_reason"] == "tool_calls"
        assert raw.endswith("data: [DONE]\n\n")
    finally:
        m.close()


def test_scripted_mock_streams_responses_function_calls():
    """Some agent runtimes use the Responses wire API; retain the same scripted-tool seam."""
    import json
    import urllib.request
    m = MockServer()
    try:
        script = {"key": "responses-key", "messages": [{"tool_calls": [{
            "id": "call_1", "type": "function",
            "function": {"name": "shell", "arguments": '{"command":"true"}'},
        }]}]}
        urllib.request.urlopen(urllib.request.Request(
            f"{m.url}/__script", method="POST", data=json.dumps(script).encode(),
            headers={"Content-Type": "application/json"})).read()
        body = {"model": "ack", "tools": [{"type": "function"}],
                "input": "responses-key", "stream": True}
        req = urllib.request.Request(f"{m.url}/v1/responses", method="POST",
                                     data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as response:
            raw = response.read().decode()
            assert response.headers["Content-Type"] == "text/event-stream"
        assert "response.output_item.done" in raw
        assert '"function_call"' in raw
        assert '"name": "shell"' in raw
        assert "response.completed" in raw
    finally:
        m.close()


def test_KRK_M10_a_refusal_for_an_unrelated_reason_is_not_evidence(tmp_path, monkeypatch):
    """An impostor stopped by something other than the approval guarantee proved nothing. When
    no attempt reaches the guarantee, there is no verdict."""
    toy = TOYS["P4"]("bad")
    toy.reached_guarantee = lambda impostor, said: False
    toy.approve_as = lambda who, aid: "403 unrelated permission"
    r = _run("P4", toy, "unreached", tmp_path, monkeypatch)
    assert r.status is Status.INCONCLUSIVE, r.summary


def test_KRK_M7_a_wait_started_from_a_process_that_exits_leaves_no_client_socket():
    """KRK-M7's mechanism, without a product: a client library that keeps its connection after
    it is closed leaves a socket the server still holds, so a server-side count charges the
    client's socket to the server. Started from a process that exits, the operating system closes
    every client socket and the server holds nothing for it."""
    import socket
    import sys
    import threading
    import time
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    held = []

    def accept():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            held.append(c)
    threading.Thread(target=accept, daemon=True).start()

    def open_server_side():
        """Server-side sockets whose client has not closed its end."""
        n = 0
        for c in held:
            c.setblocking(False)
            try:
                if c.recv(1, socket.MSG_PEEK) != b"":
                    n += 1
            except BlockingIOError:
                n += 1
            except OSError:
                pass
        return n
    try:
        leaky = socket.create_connection(("127.0.0.1", port))   # in-process, never closed
        time.sleep(0.2)
        assert open_server_side() == 1                           # what the count would charge
        code = ("import socket,sys; s=socket.create_connection(('127.0.0.1', int(sys.argv[1])));"
                " sys.exit(0)")                                  # leaves its socket open; exits
        subprocess.run([sys.executable, "-c", code, str(port)], check=True, timeout=30)
        time.sleep(0.2)
        assert len(held) == 2 and open_server_side() == 1        # only the in-process one
        leaky.close()
    finally:
        srv.close()
        for c in held:
            c.close()


def test_KRK_M11_a_late_execution_after_restart_is_not_a_lost_one(tmp_path, monkeypatch):
    """An engine lost its notification connection when its database restarted and woke the
    waiting workflow on a 60-second fallback poll. A 20-second window called that approval
    lost."""
    toy = TOYS["P3"]("good")
    toy.wake_after_restart_s = 60.0
    monkeypatch.setattr("conformance.properties.p3_approval_durability.AFTER_RESTART_WAIT_S", 20.0)
    assert _run("P3", toy, "short", tmp_path, monkeypatch).status is Status.FAIL
    toy = TOYS["P3"]("good")
    toy.wake_after_restart_s = 60.0
    monkeypatch.setattr("conformance.properties.p3_approval_durability.AFTER_RESTART_WAIT_S", 150.0)
    assert _run("P3", toy, "long", tmp_path, monkeypatch).status is Status.PASS


def test_KRK_M12_a_stored_message_is_read_through_its_serializer():
    """KRK-M12's mechanism: an engine that stores a message as a base64 pickle. Searching the
    stored text for the approver's name finds nothing, which reads as no record of the approval.
    Read through the serializer the store names, the name is there."""
    import base64
    import json
    import pickle

    def decode(stored, serializer):                 # what an adapter must do before searching
        if serializer == "py_pickle":
            return pickle.loads(base64.b64decode(stored))
        return json.loads(stored)
    stored = base64.b64encode(pickle.dumps({"approver": "human:alice"})).decode()
    assert "human:alice" not in stored
    assert decode(stored, "py_pickle") == {"approver": "human:alice"}
    assert decode('{"approver": "human:alice"}', "portable_json") == {"approver": "human:alice"}


def test_KRK_M13_async_waits_started_from_one_event_loop_hold_no_thread():
    """KRK-M13's mechanism: async waits started through a synchronous entry point each get a
    thread, which P8 reads as a thread held per wait. Started from one event loop, as an async
    application does, they hold none."""
    import asyncio
    import threading

    async def wait(stop):
        await stop.wait()

    def sync_entry(n):                              # one thread per wait, each with its own loop
        stops, threads = [], []
        for _ in range(n):
            ready = threading.Event()
            box = {}

            def run():
                loop = asyncio.new_event_loop()
                box["loop"], box["stop"] = loop, asyncio.Event()
                ready.set()
                loop.run_until_complete(wait(box["stop"]))
                loop.close()
            th = threading.Thread(target=run, daemon=True)
            th.start()
            ready.wait(5)
            stops.append((box["loop"], box["stop"]))
            threads.append(th)
        return stops, threads

    before = threading.active_count()
    stops, threads = sync_entry(5)
    assert threading.active_count() - before == 5               # what P8 would have read
    for loop, stop in stops:
        loop.call_soon_threadsafe(stop.set)
    for th in threads:
        th.join(5)

    async def one_loop(n):
        stop = asyncio.Event()
        tasks = [asyncio.create_task(wait(stop)) for _ in range(n)]
        await asyncio.sleep(0)
        grew = threading.active_count() - before
        stop.set()
        await asyncio.gather(*tasks)
        return grew
    assert asyncio.run(one_loop(5)) == 0


def test_KRK_M14_a_pool_that_warms_up_once_is_not_a_cost_per_wait(tmp_path, monkeypatch):
    """An engine's async waits make short calls through Python's default thread pool, which
    starts threads on demand and keeps them. Over one batch of waits that looked like a thread per
    wait. P8 now judges a second batch, where a warmed pool no longer grows."""
    toy = TOYS["P8"]("good")
    toy.warming_pool = 8
    r = _run("P8", toy, "pool", tmp_path, monkeypatch)
    first = next(c for c in r.checks if c.name == "threads per wait, first batch")
    assert float(first.outcome) >= 0.5          # what a one-batch probe would have judged
    assert r.status is Status.PASS, r.summary
    bad = TOYS["P8"]("bad")
    bad.warming_pool = 8
    assert _run("P8", bad, "pool-bad", tmp_path, monkeypatch).status is Status.FAIL


def test_KRK_M14_a_status_path_that_warms_a_pool_is_not_a_leak(tmp_path, monkeypatch):
    """An engine's first status calls open a fixed set of connections to the service, then stop.
    One round of the churn control called that a per-call leak and refused to measure P8."""
    import json
    toy = TOYS["P8"]("good")
    toy.warming_status_pool = 8
    r = _run("P8", toy, "spool", tmp_path, monkeypatch)
    churn = json.loads(next((tmp_path / "t").rglob("*churn-control.json")).read_text())
    assert churn["growth_round_1"]["threads"] >= 5      # what one round would have judged
    assert r.status is Status.PASS, r.summary


def test_KRK_M15_a_retraction_in_the_same_second_as_the_approval_is_not_a_revocation_test(
        tmp_path, monkeypatch):
    """A target that tells a new answer from a re-read of the old one by a one-second
    timestamp. A probe that retracts the instant after approving finds the retraction ignored,
    and reports that revocation does not work. Applied a few seconds later, it does."""
    toy = TOYS["P9"]("good")
    toy.reply_clock_s = 1
    monkeypatch.setattr("conformance.properties.p9_grant_validity.SETTLE_S", 0)
    r = _run("P9", toy, "instant", tmp_path, monkeypatch)
    assert r.status is Status.FAIL and "revoked" in r.summary, r.summary
    monkeypatch.setattr("conformance.properties.p9_grant_validity.SETTLE_S", 2.0)
    toy = TOYS["P9"]("good")
    toy.reply_clock_s = 1
    assert _run("P9", toy, "settled", tmp_path, monkeypatch).status is Status.PASS


def test_KRK_M18_a_status_set_from_the_expected_effect_gives_no_verdict(tmp_path, monkeypatch):
    """Anticipated in P16's design, not observed. A target records the expected effect with the
    decision, before B acts. A status taken from that record reads done at approval, and on the
    honest control it looks exactly like a completed effect. P16 reads the status before B
    executes and gives no verdict when the control is already done there."""
    import json
    from known_bad.receipts_toys import make
    toy = make()
    recorded = toy.submit

    def submit(envelope, expected):              # done as soon as the expectation is recorded
        case_id = recorded(envelope, expected)
        toy.cases[case_id].update(status="done", grade="signed-by-B")
        return case_id

    toy.submit = submit
    r = _run("P16", toy, "expected", tmp_path, monkeypatch)
    assert r.status is Status.INCONCLUSIVE and "before B executed" in r.summary, r.summary
    # Without the early read the control would have held: B wrote the items, the judgement
    # accepts B's receipt, and the target ends done / signed-by-B.
    honest = json.loads(next((tmp_path / "t").rglob("*honest.json")).read_text())
    assert honest["status_before_execution"] == "done"
    assert honest["judgement"]["accept"] is True
    assert honest["store_counts"]["written"] == honest["count"]
    assert honest["reads"][-1] == {"status": "done", "grade": "signed-by-B"}
    assert _run("P16", make(), "good", tmp_path, monkeypatch).status is Status.PASS


def test_KRK_M19_a_target_that_completes_on_the_executors_report_fails(tmp_path, monkeypatch):
    """Observed on the reference implementation during the KRK-16 baseline. P16's control
    required the honest case to end done at grade signed-by-B, which is the guarantee P16 tests,
    so a target with no receipt path could never satisfy it and got no verdict instead of a
    fail. The control now requires done at any grade and records it; the grade is judged as the
    honest check."""
    import json
    from known_bad.receipts_toys import make
    r = _run("P16", make("no_receipt_check"), "executor-word", tmp_path, monkeypatch)
    # The evidence shows the control held: B wrote every item, the judgement accepts B's receipt,
    # the target was not done before B executed, and it ended done.
    honest = json.loads(next((tmp_path / "t").rglob("*honest.json")).read_text())
    assert honest["store_counts"]["written"] == honest["count"]
    assert honest["judgement"]["accept"] is True
    assert honest["status_before_execution"] != "done"
    assert honest["reads"][-1] == {"status": "done", "grade": "executor-report"}
    # The old control demanded signed-by-B here, so the result would have been inconclusive.
    assert honest["reads"][-1]["grade"] != "signed-by-B"
    assert r.status is Status.FAIL and r.control_held is True, r.summary
    control = next(c for c in r.checks if c.name == "honest")
    assert (control.outcome, control.ok) == ("completed-without-verified-receipt", False)
    assert _run("P16", make(), "good", tmp_path, monkeypatch).status is Status.PASS


# --------------------------------------------------------------------------- P16, KRK-M20..M26
# The toys below are generic shapes of targets and adapters, not any product.


def _p16_checks(r):
    return {c.name: (c.outcome, c.ok) for c in r.checks}


def test_KRK_M20_the_stranger_sibling_passes_a_membership_check(tmp_path, monkeypatch):
    """A wrong-request probe whose receipt names a request A never made cannot catch a target
    that only asks "is this a reference I know?". The variant set without sibling_request passes
    the membership-only toy; the set with it fails it, on sibling_request alone."""
    from conformance.properties import p16_effect_receipt as p16
    from known_bad.receipts_toys import make
    full = p16.VARIANTS
    monkeypatch.setattr(p16, "VARIANTS", tuple(v for v in full if v != "sibling_request"))
    old = _run("P16", make("accepts_known_request"), "old-set", tmp_path, monkeypatch)
    assert old.status is Status.PASS, old.summary
    assert _p16_checks(old)["wrong_request"] == ("not_done", True)
    monkeypatch.setattr(p16, "VARIANTS", full)
    new = _run("P16", make("accepts_known_request"), "new-set", tmp_path, monkeypatch)
    assert new.status is Status.FAIL, new.summary
    assert {c.name for c in new.checks if c.ok is False} == {"sibling_request"}
    assert _p16_checks(new)["wrong_request"] == ("not_done", True)
    assert _run("P16", make(), "good", tmp_path, monkeypatch).status is Status.PASS


def _claims(token):
    import base64
    import json
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def _format_toy(flaw, profile):
    """A target that reads only its own receipt format: a receipt without the format's member
    is unreadable to it and blocked as malformed."""
    from known_bad.receipts_toys import ToyEffectReceipts

    class FormatToy(ToyEffectReceipts):
        def receipt_profile(self):
            return profile

        def _check(self, c, token):
            if "fmt_status" not in (_claims(token) or {}):
                return "blocked", None, "not in this target's format"
            return super()._check(c, token)

    return FormatToy("bad", flaw)


def test_KRK_M21_a_verdict_the_targets_format_cannot_say_is_not_a_pass(tmp_path, monkeypatch):
    """A target in another receipt format rejects what it cannot parse. When no kit receipt is in
    its format, the honest one is rejected too and the control gives no verdict. When only some
    verdicts have no form in its format, the control holds and those variants would read as the
    target's rejections, hiding a flaw the target has on exactly those verdicts."""
    from conformance import counterparty as cp
    fmt = {"executed": {"fmt_status": "ok"}, "refused": {"fmt_status": "refused"}}
    monkeypatch.setitem(cp.PROFILES, "test-format", lambda claims: dict(fmt.get(
        claims["verdict"], {})))
    # The whole format missing: the control catches it.
    r = _run("P16", _format_toy("no_record_as_done", None), "no-profile", tmp_path, monkeypatch)
    assert r.status is Status.INCONCLUSIVE, r.summary
    # The no-record verdict missing from the format: a target that would count a no-record as
    # done must not read as passing those variants.
    r = _run("P16", _format_toy("no_record_as_done", "test-format"), "gap", tmp_path,
             monkeypatch)
    got = _p16_checks(r)
    for v in ("signed_no_record", "disputed_no_record"):
        assert got[v] == ("fixture_not_landed", None), (v, got[v])
        assert "no form in the target's format" in next(c.detail for c in r.checks if c.name == v)
    assert got["signed_refusal"] == ("not_done", True)          # refusal has a form: read
    # With a format that can say no-record, the flaw shows.
    fmt["no-record"] = {"fmt_status": "no-record"}
    r = _run("P16", _format_toy("no_record_as_done", "test-format"), "full", tmp_path,
             monkeypatch)
    assert {c.name for c in r.checks if c.ok is False} == {"signed_no_record",
                                                           "disputed_no_record"}


def test_KRK_M22_nothing_decided_is_not_a_hold(tmp_path, monkeypatch):
    """Where completion is written by a model step the probe does not drive, no deterministic
    code runs on an answer with no receipt. An adapter that reports that as awaiting-receipt
    turns the absence of a gate into a pass; reported as `unverified`, it is information."""
    from conformance.properties import p16_effect_receipt as p16
    from known_bad.receipts_toys import ToyEffectReceipts

    class ModelCompletes(ToyEffectReceipts):
        honest_label = True

        def status(self, case_id):
            c = self.cases[case_id]
            if self.honest_label and c.get("receipt") is None and c["status"] != "done":
                return p16.NOTHING_DECIDED          # nothing deterministic ran
            return super().status(case_id)

    naive = ModelCompletes("good")
    naive.honest_label = False
    got = _p16_checks(_run("P16", naive, "naive", tmp_path, monkeypatch))
    assert got["missing"] == got["agent_report"] == ("not_done", True)   # the error
    got = _p16_checks(_run("P16", ModelCompletes("good"), "labelled", tmp_path, monkeypatch))
    assert got["missing"] == got["agent_report"] == ("nothing_decided", None)
    assert not any(p16.NOTHING_DECIDED in v for v in p16.ALLOWED.values())


class _Translator:
    """An adapter that re-encodes B's answer before the target sees it, around a target that
    blocks for a person when no receipt has arrived by its deadline. `forward(token)` is the
    translation; `delivered` reports what the target received."""

    def __init__(self, inner, forward, report=True):
        self.inner, self.forward, self.got = inner, forward, {}
        if report:
            self.delivered = lambda case_id: list(self.got[case_id])
        self.name, self.config = inner.name, f"translated:{inner.config}"
        for m in ("version", "vendor_claims", "not_applicable", "implements", "start", "stop",
                  "pin_counterparty_key", "submit", "evidence_grade", "receipt_deadline_s",
                  "elapse"):
            setattr(self, m, getattr(inner, m))

    def deliver(self, case_id, receipt, report):
        from conformance.properties import p16_effect_receipt as p16
        out = self.forward(receipt)
        self.got.setdefault(case_id, []).append(p16.sent_as(out, self.inner.pinned))
        self.inner.deliver(case_id, out, report)

    def status(self, case_id):
        st = self.inner.status(case_id)
        c = self.inner.cases[case_id]
        if st == "awaiting-receipt" and self.inner.clock - c["submitted_at"] >= self.inner.receipt_deadline_s():
            return "blocked"                         # in front of a person
        return st


def test_KRK_M23_landed_for_the_kit_is_not_landed_in_the_target(tmp_path, monkeypatch):
    """The kit's landed check reads B's store and the kit's judgement of B's receipt. When the
    adapter's re-encoding has no form for a verdict and hands the target no receipt, the
    fixture lands for the kit while the target saw something else, and a target that blocks a
    missing receipt reads as passing variants it never received."""
    from known_bad.receipts_toys import make

    def no_form(token):
        return None if token and _claims(token)["verdict"] in ("refused", "no-record") else token

    blind = _Translator(make("no_record_as_done"), no_form, report=False)
    got = _p16_checks(_run("P16", blind, "unreported", tmp_path, monkeypatch))
    assert got["signed_no_record"] == got["disputed_no_record"] == ("not_done", True)  # the error
    seen = _Translator(make("no_record_as_done"), no_form)
    r = _run("P16", seen, "reported", tmp_path, monkeypatch)
    got = _p16_checks(r)
    for v in ("signed_no_record", "disputed_no_record", "signed_refusal"):
        assert got[v] == ("fixture_not_landed", None), (v, got[v])
        assert "not in the target" in next(c.detail for c in r.checks if c.name == v)
    assert got["honest"] == ("done_signed_by_B", True)


def test_KRK_M25_a_translator_that_verifies_hides_the_targets_check(tmp_path, monkeypatch):
    """A translator that forwards only receipts whose signature it has verified does A's check
    for it. A target that accepts unsigned receipts then never sees one, and blocking the
    missing receipt reads as refusing it. Reporting what reached the target exposes that."""
    from conformance import receipts
    from known_bad.receipts_toys import make
    inner = make("accepts_unsigned")

    def verifying(token):
        return token if token and receipts.verify_receipt(token, inner.pinned).ok else None

    blind = _Translator(inner, verifying, report=False)
    got = _p16_checks(_run("P16", blind, "unreported", tmp_path, monkeypatch))
    assert got["unsigned"] == ("not_done", True)                     # the error
    inner = make("accepts_unsigned")
    seen = _Translator(inner, verifying)
    got = _p16_checks(_run("P16", seen, "reported", tmp_path, monkeypatch))
    assert got["unsigned"] == got["unpinned_key"] == ("fixture_not_landed", None)
    # A faithful translator over the same target lets the flaw show.
    inner = make("accepts_unsigned")
    r = _run("P16", _Translator(inner, lambda t: t), "faithful", tmp_path, monkeypatch)
    assert {c.name for c in r.checks if c.ok is False} == {"unsigned"}


def test_KRK_M24_the_adapters_application_is_not_graded_as_the_product(tmp_path, monkeypatch):
    """A target with no record of completion needs the adapter to supply the application. A
    check only that application can answer (here, ignoring the executor's report) reads as a
    pass that belongs to the adapter. Declared not applicable it is information; a check that
    may not be declared away is driven and carries the adapter's note, which changes no
    outcome."""
    import json
    from known_bad.receipts_toys import make
    thin = make()
    got = _p16_checks(_run("P16", thin, "undeclared", tmp_path, monkeypatch))
    assert got["agent_report"] == ("not_done", True)                 # the adapter's pass
    note = "describes the adapter's application, not the product"
    thin = make()
    thin.variants_not_applicable = lambda: {"agent_report": "the product has no such input"}
    thin.variant_notes = lambda: {"missing": note, "sibling_request": note}
    r = _run("P16", thin, "declared", tmp_path, monkeypatch)
    got = _p16_checks(r)
    assert got["agent_report"] == ("not_applicable", None)
    assert got["missing"] == ("not_done", True)
    assert note in next(c.detail for c in r.checks if c.name == "missing")
    ev = json.loads(next((tmp_path / "t").rglob("*declared*/**/*-missing.json")).read_text())
    assert ev["adapter_note"] == note
    # A note never changes an outcome.
    bad = make("accepts_known_request")
    bad.variant_notes = lambda: {"sibling_request": note}
    got = _p16_checks(_run("P16", bad, "noted-bad", tmp_path, monkeypatch))
    assert got["sibling_request"] == ("done", False)


def test_KRK_M26_a_revocation_that_never_landed_gives_no_reading():
    """A harness that publishes a revocation in the target's format through an update that returns a
    new copy leaves the published list unchanged, and the verifier then accepts the 'revoked' receipt:
    a reading of failing open that describes the harness. The harness reads the published list
    back and refuses to count the reading unless every revocation landed."""
    from conformance.readback import FixtureNotLanded, require_landed

    class Bits:                                       # set() returns a new list; this one is unchanged
        def __init__(self, on=()):
            self.on = frozenset(on)

        def set(self, i):
            return Bits(self.on | {i})

        def test(self, i):
            return i in self.on

    def publish(revoked, buggy):
        bits = Bits()
        for i in revoked:
            if buggy:
                bits.set(i)                           # the result is discarded
            else:
                bits = bits.set(i)
        return bits

    def verifier_accepts(published, index):
        return not published.test(index)

    for buggy in (True, False):
        published = publish([2], buggy)
        read_back = {i: published.test(i) for i in [2]}
        if buggy:
            assert verifier_accepts(published, 2)     # would read as failing open
            with pytest.raises(FixtureNotLanded):
                require_landed("revocation", [2], read_back)
        else:
            require_landed("revocation", [2], read_back)
            assert not verifier_accepts(published, 2)


# --------------------------------------------------------------------------- P17, KRK-M27..M35
# Generic shapes of reconcilers, targets and counterparties, not any product.


def _p17(toy, tag, tmp_path, monkeypatch, seed=515151):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    return ALL["P17"].probe(toy, Evidence("t", toy.name, "P17", tag), run_tag=tag, seed=seed)


def _p17_checks(r):
    return {c.name: (c.outcome, c.ok) for c in r.checks}


def test_KRK_M27_the_receipt_read_as_the_counterpartys_log_cannot_tell_good_from_bad(
        tmp_path, monkeypatch):
    """Anticipated. If B's side of the comparison is built from the receipts A holds, A is
    compared with its own copy of B's statement and matches by construction: a reconciler that
    reads B's log and one that reads only receipts give the same reading on a receipt B's log
    contradicts. Read through `record()`, the two differ."""
    from conformance import counterparty as cp
    from known_bad.records_toys import make
    real = cp.StubCounterparty.record

    def from_receipts(self, peer):                  # B's "log" rebuilt from what B signed
        out = []
        for e in real(self, peer):
            if e["kind"] == "effect-committed":
                iss = next((x for x in real(self, peer) if x["kind"] == "receipt-issued"
                            and x["correlation_id"] == e["correlation_id"]), None)
                if iss and iss["body"].get("outcome"):
                    e = dict(e, body=dict(e["body"], **{k: iss["body"]["outcome"][k] for k in
                                                        ("created", "updated", "deleted")}))
            out.append(e)
        return out

    monkeypatch.setattr(cp.StubCounterparty, "record", from_receipts)
    good = _p17_checks(_p17(make(), "f27-good-r", tmp_path, monkeypatch))
    bad = _p17_checks(_p17(make("reconciles_against_receipts"), "f27-bad-r", tmp_path,
                           monkeypatch))
    assert good["c:receipt_contradicts_log"] == bad["c:receipt_contradicts_log"]  # the error
    monkeypatch.setattr(cp.StubCounterparty, "record", real)
    good = _p17_checks(_p17(make(), "f27-good", tmp_path, monkeypatch))
    bad = _p17_checks(_p17(make("reconciles_against_receipts"), "f27-bad", tmp_path, monkeypatch))
    assert good["c:receipt_contradicts_log"] == ("found_flagged", True)
    assert bad["c:receipt_contradicts_log"] == ("missed", False)
    assert good["receipt_contradicts_log"] == ("found", True)


def test_KRK_M28_a_gap_in_a_global_sequence_is_not_a_removal(tmp_path):
    """Anticipated. B's global log number is interleaved with other requesters' entries, so a
    gap in it is normal: read as A's numbering it reports removals that never happened. B's
    per-requester numbering has no such gap, and a declared void keeps its number."""
    import random
    from conformance import books, receipts
    from conformance import counterparty as cp
    from conformance.properties.p17_reconcilable_record import build_case
    b = cp.StubCounterparty(str(tmp_path / "b.sqlite"), receipts.Keypair.generate("k"),
                            bytes(16), counterparty_id="did:web:b.example")
    rng = random.Random(1)
    for who in ("did:web:a.example", "did:web:other.example") * 2:
        env, exp = build_case(receipts, rng, b.salt, "did:web:b.example", "f28", requester=who)
        b.execute(env, exp, rng=rng)
    mine = [e for e in b.log_truth() if e["peer"] == "did:web:a.example"]
    by_global = [dict({k: v for k, v in e.items() if k not in ("log_seq", "stored_digest")},
                      pair_seq=e["log_seq"], prev_digest=None) for e in mine]
    assert "gap" in {x.kind for x in books.chain_breaks(by_global)[0]}       # the error
    assert books.chain_breaks(b.record("did:web:a.example")) == ([], [])
    env, exp = build_case(receipts, rng, b.salt, "did:web:b.example", "f28v")
    b.set_record_mode(env["correlation_id"], "declared_void")
    b.execute(env, exp, rng=rng)
    assert books.chain_breaks(b.record("did:web:a.example")) == ([], [])


def test_KRK_M29_a_reconciler_that_compares_totals_reads_a_compensating_pair_as_matched():
    """Anticipated. One request missing at B and one extra at B with the same count leave the
    totals equal. A reconciler comparing totals reads matched; the kit's compares per key, and
    its self-test fails a totals-only copy of it (`test_books.py`)."""
    from tests.test_books import CountsOnly, _self_test
    from conformance import books
    assert _self_test(books.Reconciler, "compensating_pair")[0]
    assert not _self_test(CountsOnly, "compensating_pair")[0]


def test_KRK_M30_a_reconciler_that_matches_before_the_counterparty_acts_gives_no_verdict(
        tmp_path, monkeypatch):
    """Anticipated in design. A target or adapter that reconciles A against A's own copy reads
    matched before B has acted, and its reconciliation readings describe that copy. P17
    reconciles once after the first submit and before B executes; matched there withholds the
    reconciliation verdict. Without that read, the same target gets one."""
    from known_bad.records_toys import ToyRecords

    class SelfMatch(ToyRecords):
        def states(self, peer):                       # every action matched, from A alone
            return {k: "matched" for k in super().states(peer)} or {"x": "matched"}

    from conformance.properties import p17_reconcilable_record as p17
    r = _p17(SelfMatch("bad", "trusts_own_done"), "f30", tmp_path, monkeypatch)
    got = _p17_checks(r)
    assert got["c:unbacked_on_a"][0] == "no_verdict"
    assert "before B acted" in r.extra["reconciliation_checks"]
    real = p17.run_pair

    def no_early_read(*args, **kw):
        obs = real(*args, **kw)
        obs.pop("states_before_b", None)
        return obs

    monkeypatch.setattr(p17, "run_pair", no_early_read)
    got = _p17_checks(_p17(SelfMatch("bad", "trusts_own_done"), "f30-no-guard", tmp_path,
                           monkeypatch))
    assert got["c:unbacked_on_a"] == ("missed", False)                   # a verdict on A vs A


def test_KRK_M31_a_reconciler_that_joins_by_clock_is_caught_only_beyond_its_tolerance(
        tmp_path, monkeypatch):
    """Anticipated. Joining or ordering across organisations by wall clock misjoins an action
    whose clocks differ. A skew inside the target's tolerance never shows it; P17 draws the skew
    beyond the tolerance the target states, and the kit's reconciler reads no clock for join or
    order (`test_books.py::test_the_reconciler_reads_no_clock_for_order_or_join`)."""
    from conformance.properties import p17_reconcilable_record as p17
    from known_bad.records_toys import make
    real = p17._plan

    def inside(variant, b, env, exp, rng, fix, tolerance_s=0.0):
        return real(variant, b, env, exp, rng, fix, 0.0)

    monkeypatch.setattr(p17, "SKEW_S", (5, 10))
    monkeypatch.setattr(p17, "_plan", inside)
    got = _p17_checks(_p17(make("joins_by_time_window"), "f31-in", tmp_path, monkeypatch))
    assert got["c:clock_skew"] == ("explained", True)                    # the error
    monkeypatch.setattr(p17, "SKEW_S", (60, 3600))
    monkeypatch.setattr(p17, "_plan", real)
    got = _p17_checks(_p17(make("joins_by_time_window"), "f31", tmp_path, monkeypatch))
    assert got["c:clock_skew"] == ("joined_by_clock", False)


def test_KRK_M32_a_tamper_that_never_landed_gives_no_reading(tmp_path, monkeypatch):
    """Observed while building P17, on the kit's own test adapter: an operator write
    that raised in the adapter was read as the target refusing it, which counts as prevented (a
    pass). Now only the target's own "refused" counts, and a write counts only if the target's
    export read back shows it."""
    from conformance.properties import p17_reconcilable_record as p17
    from known_bad.records_toys import make

    def raises(peer, digest, change):
        raise KeyError(digest)

    toy = make("mutable_record")
    toy.operator_write = raises
    got = _p17_checks(_p17(toy, "f32-raise", tmp_path, monkeypatch))
    assert got["a_edit_after_ack"] == ("fixture_not_landed", None)
    # A write the hook calls done but that changed nothing: without the read-back, a correct
    # target reads as hiding an edit it never had.
    toy = make()
    toy.operator_write = lambda peer, digest, change: "changed"
    monkeypatch.setattr(p17, "_read_back", lambda *a, **k: {"landed": True, "detail": "trusted"})
    got = _p17_checks(_p17(toy, "f32-unread", tmp_path, monkeypatch))
    assert got["a_edit_after_ack"] == ("hidden", False)                  # the error
    monkeypatch.undo()
    toy = make()
    toy.operator_write = lambda peer, digest, change: "changed"
    got = _p17_checks(_p17(toy, "f32", tmp_path, monkeypatch))
    assert got["a_edit_after_ack"] == ("fixture_not_landed", None)


def test_KRK_M33_the_testers_mapping_is_never_the_comparison_basis(tmp_path, monkeypatch):
    """Anticipated. With a mapping the agreement did not declare used as the basis, an action
    recorded in two vocabularies reads as matched. The kit's reconciler uses only the mapping
    the agreement declares, so with none declared it reads no-basis."""
    from conformance import books
    from conformance.properties import p17_reconcilable_record as p17
    from known_bad.records_toys import make
    real = p17.run_pair

    def testers_mapping(a, ev, variant, *args, **kw):
        obs = real(a, ev, variant, *args, **kw)
        if variant == "basis_undeclared" and "error" not in obs:   # the tester's own mapping
            k = dict(obs["_keys"], mapping=p17.MAPPING)
            obs["_kit"] = books.reconcile(obs["export"], obs["b_record"],
                                          holdings_a=obs["holdings"], **k)
        return obs

    monkeypatch.setattr(p17, "run_pair", testers_mapping)
    got = _p17_checks(_p17(make(), "f33-tester", tmp_path, monkeypatch))
    assert got["basis_undeclared"] == ("hidden", False)                  # the error
    monkeypatch.setattr(p17, "run_pair", real)
    got = _p17_checks(_p17(make(), "f33", tmp_path, monkeypatch))
    assert got["basis_undeclared"] == ("found", True)


def test_KRK_M34_a_settlement_judged_without_its_originals_hides_an_overwrite(
        tmp_path, monkeypatch):
    """Anticipated. A target that settles by rewriting an entry reads as settling correctly if
    only the settled state is read. P17 exports before and after a person settles and compares
    every original entry byte for byte."""
    from conformance.properties import p17_reconcilable_record as p17
    from known_bad.records_toys import make
    real = p17._settle

    def state_only(a, peer, obs, books):
        out = real(a, peer, obs, books)
        return dict(out, lost_entries=[], lost_raw_lines=0, unnamed=[])

    monkeypatch.setattr(p17, "_settle", state_only)
    got = _p17_checks(_p17(make("overwrite_loser"), "f34-state", tmp_path, monkeypatch))
    assert got["c:seq_duplicate"] == ("found_flagged", True)              # the error
    monkeypatch.setattr(p17, "_settle", real)
    got = _p17_checks(_p17(make("overwrite_loser"), "f34", tmp_path, monkeypatch))
    assert got["c:seq_duplicate"] == ("overwrote", False)


def test_KRK_M35_a_counterparty_log_changed_in_place_looks_like_a_tamper(tmp_path):
    """Anticipated; the cause was in the KRK-16 stub, which updated its log rows in place to add
    the receipt and the replay variant. A log B's own honest path changes cannot be told from an
    insider's change. B's log now refuses UPDATE and DELETE, and an honest series never uses the
    tamper path."""
    import random
    import sqlite3
    from conformance import books, receipts
    from conformance import counterparty as cp
    from conformance.properties.p17_reconcilable_record import build_case
    b = cp.StubCounterparty(str(tmp_path / "b.sqlite"), receipts.Keypair.generate("k"),
                            bytes(16), counterparty_id="did:web:b.example")
    rng = random.Random(2)
    for _ in range(3):
        env, exp = build_case(receipts, rng, b.salt, "did:web:b.example", "f35")
        b.execute(env, exp, rng=rng)
    kid, pub = b.checkpoint_public_key()
    held = books.verify_checkpoint(b.checkpoint("did:web:a.example"), {kid: pub}).claims
    assert b.tamper_log == [] and books.checkpoint_covers(b.record("did:web:a.example"),
                                                          held) == []
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        with b._db() as db:                           # what the old stub's honest path did
            db.execute("UPDATE log SET body = body WHERE kind = 'effect-committed'")
    # Without the triggers, an in-place update on the honest path reads exactly as a tamper.
    db = sqlite3.connect(b.db_path)
    for t in cp.APPEND_ONLY:
        db.execute(f"DROP TRIGGER {t}_no_update")
    db.execute("UPDATE log SET body = json_set(body, '$.created', 0) WHERE log_seq = "
               "(SELECT log_seq FROM log WHERE kind = 'effect-committed' LIMIT 1)")
    db.commit()
    db.close()
    assert [x.kind for x in books.checkpoint_covers(b.record("did:web:a.example"), held)] == \
        ["changed-after-ack"]


def test_KRK_M66_the_record_settled_read_as_the_effect_settled(tmp_path, monkeypatch):
    """Observed. A target that ends the dispute about an effect when a person settles the break
    for the record, with no outcome, keeps every original entry and names them in the
    settlement, so the record checks all pass. Without reading the effect after the settlement,
    P17 passes it; with the effect check, it fails."""
    from conformance.properties import p17_reconcilable_record as p17
    from conformance.result import Status
    from known_bad.records_toys import make
    real = p17.effect_check
    monkeypatch.setattr(p17, "effect_check", lambda variant, obs: None)   # the record alone
    r = _p17(make("record_settles_effect"), "f66-record", tmp_path, monkeypatch)
    assert r.status is Status.PASS                                         # the error
    monkeypatch.setattr(p17, "effect_check", real)
    r = _p17(make("record_settles_effect"), "f66", tmp_path, monkeypatch)
    got = _p17_checks(r)
    assert r.status is Status.FAIL
    assert got["e:receipt_contradicts_log"] == ("closed_without_outcome", False)
    assert got["e:late_entry"] == ("closed_without_outcome", False)
    assert _p17_checks(_p17(make(), "f66-good", tmp_path, monkeypatch))[
        "e:receipt_contradicts_log"] == ("held_then_followed", True)


# ----------------------------------------------------------------------- P18 (KRK-18)

SEED18 = 515151


def _p18(toy, tag, tmp_path, monkeypatch, seed=SEED18, *, start=True):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    if start:
        toy.start()
    try:
        return ALL["P18"].probe(toy, Evidence("t", toy.name, "P18", tag), run_tag=tag, seed=seed)
    finally:
        if start:
            toy.stop()


def _p18_checks(r):
    return {c.name: (c.outcome, c.ok) for c in r.checks}


def test_KRK_M36_ids_drawn_from_the_seed_replay_themselves_against_durable_memory(
        tmp_path, monkeypatch):
    """Anticipated. A B that remembers uses durably sees a re-run with the same seed. With
    issuer and authorisation ids drawn from the seed, the second run presents ids B has already
    used, B refuses them, and the control does not hold; drawn from the operating system, both
    runs hold."""
    import random
    from conformance import authz, requester
    from known_bad.binding_toys import make
    toy = make()
    toy.start()
    try:
        for i in (1, 2):
            r = _p18(toy, f"f36-os-{i}", tmp_path, monkeypatch, seed=7, start=False)
            assert r.status is Status.PASS, r.summary
        gen = {}

        def reseed():
            gen["rng"] = random.Random(7)
        monkeypatch.setattr(authz, "new_authorisation_id",
                            lambda: f"az-{gen['rng'].getrandbits(64):016x}")
        monkeypatch.setattr(requester, "new_issuer",
                            lambda: f"did:web:a-{gen['rng'].getrandbits(32):08x}.example")
        reseed()
        assert _p18(toy, "f36-seed-1", tmp_path, monkeypatch, seed=7,
                    start=False).status is Status.PASS
        reseed()
        r = _p18(toy, "f36-seed-2", tmp_path, monkeypatch, seed=7, start=False)
        assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary  # the error
    finally:
        toy.stop()


def test_KRK_M37_a_fixture_normalised_before_it_reached_b_gives_no_reading(tmp_path, monkeypatch):
    """Anticipated. An adapter that parses and re-serialises each request collapses the duplicate
    member before B sees it. Judged anyway, the correct B reads as running ambiguous bytes it
    never received. Compared byte for byte with what B received, the variant did not land."""
    import dataclasses
    import json
    from conformance.properties import p18_payload_bound as p18
    from known_bad.binding_toys import ToyBinding

    class Reserialising(ToyBinding):
        def present(self, p):
            try:
                obj = json.loads(p.request.decode("utf-8"))
                raw = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False).encode("utf-8")
                p = dataclasses.replace(p, request=raw)
            except (ValueError, UnicodeDecodeError):
                pass
            return super().present(p)

    real = p18._landed_bytes
    monkeypatch.setattr(p18, "_landed_bytes", lambda pair, plan: None)
    got = _p18_checks(_p18(Reserialising(), "f37-unchecked", tmp_path, monkeypatch))
    assert got["duplicate_key"] == ("ran_ambiguous", False)                   # the error
    monkeypatch.setattr(p18, "_landed_bytes", real)
    got = _p18_checks(_p18(Reserialising(), "f37", tmp_path, monkeypatch))
    assert got["duplicate_key"] == ("fixture_not_landed", None)
    assert got["noncanonical_equivalent"] == ("fixture_not_landed", None)


def test_KRK_M38_a_retry_by_the_testers_transport_is_never_charged_or_credited_to_b(
        tmp_path, monkeypatch):
    """Anticipated. A client under the kit that sends every request twice lets B's own memory
    absorb the second copy, so B is credited with single use the run did not test cleanly; with
    the wire log counting presentations, the control does not hold. Behind the kit's own
    transport (one send per presentation) a B with no memory shows two effects."""
    from conformance import requester
    from known_bad.binding_toys import make
    real_send, real_sent = requester.Transport.send, requester.Transport.sent

    def twice(self, p, **kw):
        real_send(self, p, **kw)
        return real_send(self, p, **kw)
    monkeypatch.setattr(requester.Transport, "send", twice)
    monkeypatch.setattr(requester.Transport, "sent", lambda self, pid: 1)    # not counted
    r = _p18(make(), "f38-uncounted", tmp_path, monkeypatch)
    assert r.control_held is True                                             # the error
    monkeypatch.setattr(requester.Transport, "sent", real_sent)
    r = _p18(make(), "f38", tmp_path, monkeypatch)
    assert r.status is Status.INCONCLUSIVE and "left the kit 2 times" in r.summary
    monkeypatch.setattr(requester.Transport, "send", real_send)
    got = _p18_checks(_p18(make("no_memory"), "f38-real", tmp_path, monkeypatch))
    assert got["replay_after_answer"] == ("ran_twice", False)


def test_KRK_M39_presentations_serialised_before_b_are_not_a_race(tmp_path, monkeypatch):
    """Anticipated. A front end that hands B's handler one presentation at a time turns a race
    into a sequence, and a B that reads, acts, then marks gives one effect. Counted as a race it
    passes; with overlap measured inside B, the round does not count."""
    from conformance.properties import p18_payload_bound as p18
    from known_bad.binding_toys import make
    toy = make("check_then_set")
    toy.serialise = True
    real = p18.overlapped
    monkeypatch.setattr(p18, "overlapped", lambda spread, yard: True)
    assert _p18_checks(_p18(toy, "f39-any", tmp_path, monkeypatch))["race_same"] == \
        ("ran_once", True)                                                     # the error
    monkeypatch.setattr(p18, "overlapped", real)
    toy = make("check_then_set")
    toy.serialise = True
    assert _p18_checks(_p18(toy, "f39", tmp_path, monkeypatch))["race_same"] == ("no_overlap", None)
    untimed = make()
    untimed.no_timing = True
    r = _p18(untimed, "f39-untimed", tmp_path, monkeypatch)
    assert _p18_checks(r)["race_same"] == ("no_overlap", None)
    assert r.status is Status.INCONCLUSIVE                    # race_same must land for a pass


def test_KRK_M40_an_effect_where_the_recorder_is_not_connected_reads_as_refused(
        tmp_path, monkeypatch):
    """Anticipated. A B whose second endpoint's executor never reaches the recorder runs a
    request addressed to its first endpoint there, and the recorder sees nothing. Without the
    capability control at that endpoint the variant reads as refused."""
    from conformance.properties import p18_payload_bound as p18
    from known_bad.binding_toys import make
    toy = make("per_endpoint_memory")
    toy.unrecorded_endpoint = "orders-eu"
    real = p18.capability_ran
    monkeypatch.setattr(p18, "capability_ran", lambda effects, req: True)
    got = _p18_checks(_p18(toy, "f40-blind", tmp_path, monkeypatch))
    assert got["replay_other_endpoint"] == ("refused", True)                   # the error
    assert any(e["endpoint"] == "orders-eu" for e in toy.local_effects)       # it did run there
    monkeypatch.setattr(p18, "capability_ran", real)
    toy = make("per_endpoint_memory")
    toy.unrecorded_endpoint = "orders-eu"
    got = _p18_checks(_p18(toy, "f40", tmp_path, monkeypatch))
    assert got["replay_other_endpoint"] == ("capability_not_held", None)


def test_KRK_M41_a_refusal_by_a_fast_clock_is_not_a_refusal_of_the_expired(tmp_path, monkeypatch):
    """Anticipated. B's clock runs five minutes ahead, beyond its stated tolerance, so it refuses
    an authorisation A issued with three minutes left. The expired one is refused too, but not
    for having expired. The control on the valid side, by the same margin, does not hold."""
    from conformance.properties import p18_payload_bound as p18
    from known_bad.binding_toys import make
    toy = make()
    toy.clock_ahead_s = 300
    real = p18.capability_ran
    monkeypatch.setattr(p18, "capability_ran", lambda effects, req: True)
    assert _p18_checks(_p18(toy, "f41-blind", tmp_path, monkeypatch))["expired"] == \
        ("refused", True)                                                      # the error
    monkeypatch.setattr(p18, "capability_ran", real)
    toy = make()
    toy.clock_ahead_s = 300
    assert _p18_checks(_p18(toy, "f41", tmp_path, monkeypatch))["expired"] == \
        ("capability_not_held", None)


def test_KRK_M42_members_the_adapter_did_not_declare_are_changed_too(tmp_path, monkeypatch):
    """Anticipated. If the kit changed only the members an adapter declared outside the binding,
    a B that takes the recipient from an undeclared header would never be shown a changed one.
    The kit changes every member it sends outside the bytes it authorised."""
    from conformance import requester
    from known_bad.binding_toys import make
    monkeypatch.setattr(requester, "UNBOUND", ())      # the adapter declared none
    assert _p18_checks(_p18(make("header_recipient"), "f42-declared", tmp_path,
                            monkeypatch))["unbound_member"] == ("ran_as_authorised", True)
    monkeypatch.setattr(requester, "UNBOUND", requester.HEADERS)
    assert _p18_checks(_p18(make("header_recipient"), "f42", tmp_path,
                            monkeypatch))["unbound_member"] == ("ran_changed", False)


def test_KRK_M43_an_answer_class_read_from_a_status_number_reads_duplicate_as_refused(
        tmp_path, monkeypatch):
    """Anticipated. The correct B answers a repeat with HTTP 409 and the code ``duplicate``. An
    adapter that maps 409 to refused makes it read as denying an effect that happened. Classes
    come from the product's codes; an answer an adapter cannot place in a class is ``error``,
    information, never a refusal."""
    from known_bad.binding_toys import make
    by_number = make()
    by_number.classify = lambda ans: "executed" if ans.get("status") == 200 else "refused"
    assert _p18_checks(_p18(by_number, "f43-number", tmp_path, monkeypatch))[
        "replay_after_answer"] == ("denied_done", False)                       # the error
    unplaced = make()
    unplaced.classify = lambda ans: {"executed": "executed"}.get(
        (ans.get("body") or {}).get("code"), "conflict")
    r = _p18(unplaced, "f43-unplaced", tmp_path, monkeypatch)
    c = next(c for c in r.checks if c.name == "replay_after_answer")
    assert (c.outcome, c.ok) == ("ran_once", True) and "no statement" in c.detail
    assert _p18_checks(_p18(make(), "f43", tmp_path, monkeypatch))[
        "replay_after_answer"] == ("ran_once", True)


def test_KRK_M44_a_restart_that_left_the_memory_running_is_not_a_restart(tmp_path, monkeypatch):
    """Anticipated. A restart hook that restarts a wrapper while the process holding B's use
    records keeps running leaves in-memory records in place, so a B with process memory only
    passes. The hook must report a new boot id for the process that holds B's state."""
    from conformance.properties import p18_payload_bound as p18
    from known_bad.binding_toys import make
    toy = make("memory_only")
    toy.restart_wrapper_only = True
    real = p18.restart_happened
    monkeypatch.setattr(p18, "restart_happened", lambda ret: True)
    assert _p18_checks(_p18(toy, "f44-any", tmp_path, monkeypatch))["replay_after_restart"] == \
        ("ran_once", True)                                                     # the error
    monkeypatch.setattr(p18, "restart_happened", real)
    toy = make("memory_only")
    toy.restart_wrapper_only = True
    assert _p18_checks(_p18(toy, "f44", tmp_path, monkeypatch))["replay_after_restart"] == \
        ("capability_not_held", None)


def test_KRK_M45_a_refusal_of_a_repeat_read_as_the_outcome(tmp_path, monkeypatch):
    """Observed. A requester whose retry changes its bytes under the same id gets a genuine
    signed refusal of the retry and records the action as refused, while B performed the first
    send. Judged against B's answer to the repeat, that record agrees; counted in B's store, it
    contradicts the effect."""
    from conformance.properties import p18_payload_bound as p18
    from known_bad.binding_toys import make_a
    real = p18.b_effect

    def from_last_answer(b, cid):                       # the guard off: B's answer as the effect
        last = [r for r in b.received_requests if r.get("correlation_id") == cid][-1]
        return {"performed": last.get("answer") in p18.CLAIMING, "executed_requests": None,
                "written": None, "by": "B's last answer"}
    monkeypatch.setattr(p18, "b_effect", from_last_answer)
    got = _p18_checks(_p18(make_a("refusal_as_outcome"), "f45-answer", tmp_path, monkeypatch))
    assert got["record_matches_effect"] == ("agrees", True)                    # the error
    monkeypatch.setattr(p18, "b_effect", real)
    got = _p18_checks(_p18(make_a("refusal_as_outcome"), "f45", tmp_path, monkeypatch))
    assert got["record_matches_effect"] == ("contradicts_effect", False)
    assert got["retry_same"] == ("changed_bytes", False)
    assert _p18_checks(_p18(make_a(), "f45-good", tmp_path, monkeypatch))[
        "record_matches_effect"] == ("agrees", True)


# --------------------------------------------------------------------------- KRK-19 (P19)
# Each pin switches one guard off to show the reading it prevents, then shows the probe's own
# reading. The toys run on a virtual clock (`known_bad/withdrawal_toys.py`); a toy defined here
# changes one behaviour of the correct toy, for one pin.

W3 = {"trials": {"withdrawn": 3}, "variants": ["withdrawn"]}


def _p19(toy, tag, tmp_path, monkeypatch, plan, seed=19):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    toy.start()
    try:
        return ALL["P19"].probe(toy, Evidence("t", toy.name, "P19", tag), run_tag=tag, seed=seed,
                                plan=plan)
    finally:
        toy.stop()


def _c19(r):
    return {c.name: (c.outcome, c.ok) for c in r.checks}


def _forms19(r, variant):
    return {t["form"]: t["outcome"] for t in r.extra["statistics"][variant]["trials"]}


def test_KRK_M46_a_grant_newer_than_the_receivers_list_is_not_read_as_refused(
        tmp_path, monkeypatch):
    """Anticipated. A receiver that reads every grant absent from its snapshot as unknown (the
    fail-safe reading the status format once allowed) refuses a grant issued
    after its last fetch until its next one. Presented once, the control does not hold and the
    run gives no verdict; with the probe's retries for `READY_S`, that receiver passes
    ``withdrawn``. The retries stay needed under the rule, for a receiver that fails safe in
    this way and for an issuer whose clock moves back between a snapshot and a grant."""
    from conformance.properties import p19_withdrawal_within_t as p19
    from conformance.result import Status
    from known_bad.withdrawal_toys import ToyWithdrawal

    class UnknownWhenAbsent(ToyWithdrawal):
        def _status(self, chain, values, staple):
            snap, _ = self._snap()
            listed = set((snap or {}).get("entries") or {})
            gone = [g["grant_id"] for g in chain if snap is not None
                    and g["grant_id"] not in listed]
            if gone:
                return f"withdrawn: {gone[0]} is not in the snapshot"
            return super()._status(chain, values, staple)

    def once(run, grant, under, endpoint, *, deadline, log):           # the guard off
        p = run.send(run.presentation(grant, endpoint), under,
                     session=run.open(grant, endpoint), tag="ready")
        log.append(p)
        return p.accepted
    real = p19._ready
    monkeypatch.setattr(p19, "_ready", once)
    r = _p19(UnknownWhenAbsent(), "f46-once", tmp_path, monkeypatch, W3)
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary  # the error
    monkeypatch.setattr(p19, "_ready", real)
    assert _c19(_p19(UnknownWhenAbsent(), "f46", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("refused_within_T", True)


def test_KRK_M47_a_flaw_built_by_deleting_data_changes_with_the_format(tmp_path, monkeypatch):
    """Observed in the kit's toys. `grant_status_only` was built by emptying the
    snapshot's standing section. Once a principal missing from a snapshot that lists its grant
    reads unknown, that construction refuses everything: its own variant gives no verdict, which
    is not the flaw. The toy now reads every principal as standing, and fails its variant."""
    from conformance import status as st
    from conformance.result import Status
    from known_bad.withdrawal_toys import ToyWithdrawal

    class DropsStanding(ToyWithdrawal):         # the old construction: correct, standing emptied
        def _snap(self):
            snap, fetched = super()._snap()
            return (None if snap is None else {**snap, "standing": {}}), fetched
    plan = {"trials": {"withdrawn": 5, "*": 2}, "variants": ["standing_withdrawn", "withdrawn"]}
    g = {"grant_id": "gr-00000000000000aa", "principal": "p@a.example", "ceiling": None}
    assert st.chain_state({"entries": {g["grant_id"]: {"state": "valid", "ceiling": None}},
                           "standing": {}}, [g])["state"] == "unknown"
    r = _p19(DropsStanding(), "f47-old", tmp_path, monkeypatch, plan)
    assert r.status is not Status.FAIL                                      # the error
    r = _p19(ToyWithdrawal("bad", "grant_status_only"), "f47", tmp_path, monkeypatch, plan)
    assert r.status is Status.FAIL and _c19(r)["standing_withdrawn"][1] is False


def test_KRK_M48_a_slow_answer_widens_the_bracket_past_T_read_as_within(tmp_path, monkeypatch):
    """Observed. The probe sent one presentation, waited for its answer, then sent the next, so its spacing was B's answer time. Two toys answer slowly:
    ``slow-good`` refuses in time; ``slow_and_late`` acts on a withdrawal only 1.2 T after it
    sees it. Sent one at a time and read without the crossing rule, both read within T, the
    late one falsely. With the crossing rule alone both read inconclusive: no false pass, but
    no verdict for the correct one either. Sent on the probe's own schedule, the correct one
    passes with brackets a few seconds wide and the late one fails."""
    from conformance import timing
    from conformance.properties import p19_withdrawal_within_t as p19
    from known_bad.withdrawal_toys import ToyWithdrawal, make

    def reading(toy, tag):
        r = _p19(toy, tag, tmp_path, monkeypatch, W3)
        brackets = [t["bracket"] for t in r.extra["statistics"]["withdrawn"]["trials"]]
        return _c19(r)["withdrawn"], brackets
    real_crosses = timing.crosses
    monkeypatch.setattr(p19._Dispatcher, "WAIT", True)                 # the old sending
    monkeypatch.setattr(timing, "crosses", lambda *a, **k: False)      # and no crossing rule
    good, gb = reading(ToyWithdrawal("slow-good"), "f48-old-good")
    late, lb = reading(make("slow_and_late"), "f48-old-late")
    assert good == ("refused_within_T", True)
    assert late == ("refused_within_T", True)                                  # the error
    T = 60.0
    assert all(lo <= T < hi for lo, hi in lb), lb      # every bracket crossed T, unread
    monkeypatch.setattr(timing, "crosses", real_crosses)
    assert reading(ToyWithdrawal("slow-good"), "f48-rule-good")[0] == ("inconclusive", None)
    assert reading(make("slow_and_late"), "f48-rule-late")[0] == ("inconclusive", None)
    monkeypatch.setattr(p19._Dispatcher, "WAIT", False)                # the probe's schedule
    good, gb = reading(ToyWithdrawal("slow-good"), "f48-good")
    assert good == ("refused_within_T", True)
    assert max(hi - lo for lo, hi in gb) < 0.15 * T, gb
    assert reading(make("slow_and_late"), "f48-late")[0] == ("refused_late", False)


def test_KRK_M50_a_withdrawal_timed_when_asked_charges_the_publishing_delay_to_b(
        tmp_path, monkeypatch):
    """Anticipated. The stub's source publishes 62 s after the kit asks. Timed from the request,
    the correct receiver is late; timed from the commit the source served it from, within T."""
    from conformance import requester
    from known_bad.withdrawal_toys import make
    real = requester.StubRequester.withdraw

    def slow(self, gid, *, charged=False):
        asked = self.clock.now()
        self.clock.sleep(62)
        w = real(self, gid)
        if charged:
            w.t_commit = asked                          # the guard off: t_w when asked
        return w
    monkeypatch.setattr(requester.StubRequester, "withdraw",
                        lambda self, gid: slow(self, gid, charged=True))
    assert _c19(_p19(make(), "f50-asked", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("refused_late", False)                                                # the error
    monkeypatch.setattr(requester.StubRequester, "withdraw", lambda self, gid: slow(self, gid))
    assert _c19(_p19(make(), "f50", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("refused_within_T", True)


def test_KRK_M51_a_repeated_request_refused_by_single_use_reads_as_withdrawn(
        tmp_path, monkeypatch):
    """Anticipated. A receiver with single-use memory and no withdrawal check refuses a
    repeated request. Presenting one request under W again reads as refusing within T; fresh
    requests read as never refused inside the window. Both runs read B's answers, so the repeat
    is the only difference (at the recorder a repeated request also keeps its first effect's
    ref, which is the other reason every presentation is fresh)."""
    from conformance import requester
    from known_bad.withdrawal_toys import ToyWithdrawal

    class SingleUse(ToyWithdrawal):
        def present(self, p, *, session=None):
            from conformance import authz
            az = (authz.claims_of(p.authorisation) or {}).get("authorisation_id")
            seen = self.__dict__.setdefault("used", set())
            if az in seen:
                return {"status": 409, "body": {"code": "refused", "reason": "duplicate"}}
            seen.add(az)
            return super().present(p, session=session)

        def evidence_grade(self):
            return "b-response"
    real = requester.StubRequester.under
    cache = {}

    def repeated(self, grant, values, **kw):           # the guard off: after the withdrawal,
        if self._states[grant.id]["state"] == "valid":  # W's last request is presented again
            cache[grant.id] = real(self, grant, values, **kw)
            return cache[grant.id]
        return cache.get(grant.id) or real(self, grant, values, **kw)
    monkeypatch.setattr(requester.StubRequester, "under", repeated)
    assert _c19(_p19(SingleUse("bad", "no_check"), "f51-repeat", tmp_path, monkeypatch,
                     W3))["withdrawn"] == ("refused_within_T", True)              # the error
    monkeypatch.setattr(requester.StubRequester, "under", real)
    assert _c19(_p19(SingleUse("bad", "no_check"), "f51", tmp_path, monkeypatch,
                     W3))["withdrawn"] == ("not_refused_within_W", False)


def test_KRK_M52_a_receiver_that_refuses_everything_is_not_read_as_refusing_the_withdrawn(
        tmp_path, monkeypatch):
    """Anticipated. A receiver that refuses every request once any withdrawal is visible. With
    the live sibling ignored it reads as refusing within T; with it the trial is collateral and
    there is no verdict."""
    from conformance.properties import p19_withdrawal_within_t as p19
    from known_bad.withdrawal_toys import ToyWithdrawal

    class RefusesAll(ToyWithdrawal):
        def present(self, p, *, session=None):
            snap, _ = self._snap()
            if snap and any(e["state"] != "valid" for e in snap["entries"].values()):
                return {"status": 503, "body": {"code": "refused", "reason": "busy"}}
            return super().present(p, session=session)
    one = {"trials": {"withdrawn": 1}, "variants": ["withdrawn"]}
    real = p19._failsafe
    monkeypatch.setattr(p19, "_failsafe", lambda v, f: True)     # the guard off
    assert _c19(_p19(RefusesAll(), "f52-blind", tmp_path, monkeypatch, one))["withdrawn"] == \
        ("refused_within_T", True)                                             # the error
    monkeypatch.setattr(p19, "_failsafe", real)
    r = _p19(RefusesAll(), "f52", tmp_path, monkeypatch, one)
    assert _c19(r)["withdrawn"] == ("collateral_refusal", None)
    assert r.status is Status.INCONCLUSIVE


def test_KRK_M53_a_long_tail_under_its_mean_is_read_from_its_worst_case(tmp_path, monkeypatch):
    """Anticipated. The long-tail toy's mean time to refusal is under T over 30 trials; its
    maximum is not, and the variant fails. The statistics carry no mean."""
    from known_bad.withdrawal_toys import make
    r = _p19(make("long_tail_poll"), "f53", tmp_path, monkeypatch,
             {"trials": {"withdrawn": 30}, "variants": ["withdrawn"]})
    st = r.extra["statistics"]["withdrawn"]
    times = [t["time_s"] for t in st["trials"] if t["time_s"] is not None]
    assert len(times) >= 25 and sum(times) / len(times) < 60          # the error: the mean
    assert _c19(r)["withdrawn"] == ("refused_late", False) and st["max_s"] > 60
    assert not any("mean" in k or "average" in k for k in st)


def test_KRK_M54_withdrawals_timed_just_before_each_fetch_hide_the_worst_phase(
        tmp_path, monkeypatch):
    """Anticipated. A receiver polling every 1.5 T with no age limit. Withdrawn just before
    each of its fetches it reads within T; the probe's random and worst phases find it late."""
    from conformance import timing
    from known_bad.withdrawal_toys import ToyWithdrawal

    class Slow(ToyWithdrawal):
        def _interval(self):
            return 1.5 * self.T

        def _age(self, snap, fetched_at):
            return 0.0
    plan = {"trials": {"withdrawn": 3, "worst_phase": 2}, "variants": ["withdrawn",
                                                                       "worst_phase"]}
    real = timing.phase_target
    monkeypatch.setattr(timing, "phase_target", lambda f, P, rng, mode: f + P - 0.5)
    got = _c19(_p19(Slow(), "f54-lucky", tmp_path, monkeypatch, plan))
    assert got["worst_phase"] == ("refused_within_T", True)                    # the error
    monkeypatch.setattr(timing, "phase_target", real)
    got = _c19(_p19(Slow(), "f54", tmp_path, monkeypatch, plan))
    assert got["worst_phase"] == ("refused_late", False)


def test_KRK_M55_presentations_wider_than_the_bound_miss_an_acceptance_after_it(
        tmp_path, monkeypatch):
    """Anticipated. A receiver that keeps accepting a withdrawn grant until 1.5 s after T.
    Presented at 0 and 1.5 T only, nothing lands between T and its refusal and it reads within;
    since KRK-M48 that bracket, which crosses T, reads inconclusive; on the
    probe's schedule, with its boundary presentation, it is late."""
    from conformance import timing
    from known_bad.withdrawal_toys import ToyWithdrawal

    class Lenient(ToyWithdrawal):
        def _interval(self):
            return 0.5

        def _take(self, claims):
            seen = self.__dict__.setdefault("seen", {})
            for gid, e in claims["entries"].items():
                if e["state"] != "valid":
                    seen.setdefault(gid, self._c().now())     # when it learned of it
            super()._take(claims)

        def _status(self, chain, values, staple):
            why = super()._status(chain, values, staple)
            first = self.__dict__.get("seen", {}).get(chain[0]["grant_id"])
            if why and why.startswith("withdrawn") and first is not None \
                    and self._c().now() - first < self.T + 1.5:
                return None
            return why
    real, real_crosses = timing.schedule, timing.crosses
    monkeypatch.setattr(timing, "schedule", lambda T, rng, **kw: [timing.Slot(0.0),
                                                                  timing.Slot(1.5 * T)])
    monkeypatch.setattr(timing, "crosses", lambda *a, **k: False)     # KRK-M48's guard off too
    assert _c19(_p19(Lenient(), "f55-wide", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("refused_within_T", True)                                             # the error
    monkeypatch.setattr(timing, "crosses", real_crosses)
    assert _c19(_p19(Lenient(), "f55-wide-48", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("inconclusive", None)                                     # no verdict, not a pass
    monkeypatch.setattr(timing, "schedule", real)
    assert _c19(_p19(Lenient(), "f55", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("refused_late", False)


def test_KRK_M56_a_real_target_on_a_virtual_clock_gives_no_verdict(tmp_path, monkeypatch):
    """Anticipated. An adapter outside the toys declares a virtual clock. With the check off
    it gets a verdict measured in time its own caches never lived through; with it, none."""
    from conformance.properties import p19_withdrawal_within_t as p19
    from known_bad.withdrawal_toys import ToyWithdrawal

    class Product(ToyWithdrawal):
        pass
    Product.__module__ = "targets.some_product"
    monkeypatch.setattr(p19, "_is_toy", lambda a: True)          # the guard off
    assert _p19(Product(), "f56-blind", tmp_path, monkeypatch, W3).status is Status.PASS
    monkeypatch.undo()
    r = _p19(Product(), "f56", tmp_path, monkeypatch, W3)
    assert r.status is Status.INCONCLUSIVE and "KRK-M56" in r.summary


def test_KRK_M57_a_cache_on_the_testers_side_is_charged_to_the_receiver(tmp_path, monkeypatch):
    """Anticipated. A 600 s cache in front of the stub's source serves the snapshot from before
    the withdrawal. A receiver that trusts what it fetched then reads as never refusing inside
    the window; with no cache it refuses within T. The source says no-store over HTTP."""
    import urllib.request
    from conformance import requester
    from known_bad.withdrawal_toys import ToyWithdrawal

    class Trusting(ToyWithdrawal):
        def _age(self, snap, fetched_at):
            return 0.0
    real = requester.StubRequester._serve
    memo = {}

    def cached(self, path, client):                   # the guard off: a kit-side cache
        hit = memo.get(id(self))
        if hit and self.clock.now() - hit[0] < 600 and path != requester.BASELINE_PATH:
            return hit[1]
        got = real(self, path, client)
        if path != requester.BASELINE_PATH:
            memo[id(self)] = (self.clock.now(), got)
        return got
    monkeypatch.setattr(requester.StubRequester, "_serve", cached)
    assert _c19(_p19(Trusting(), "f57-cache", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("not_refused_within_W", False)                                        # the error
    monkeypatch.setattr(requester.StubRequester, "_serve", real)
    assert _c19(_p19(Trusting(), "f57", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("refused_within_T", True)
    stub = requester.StubRequester(requester.new_issuer())
    url = stub.serve()
    try:
        stub.issue("agent-1", principal="alice")
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.headers["Cache-Control"] == "no-store"
    finally:
        stub.close()


def test_KRK_M58_presenting_at_one_replica_hides_another_that_still_accepts(
        tmp_path, monkeypatch):
    """Anticipated. The receiver's second endpoint stopped refreshing its status. Presented at
    the first endpoint only it reads within T; rotating over both, never refused in the
    window."""
    from conformance.properties import p19_withdrawal_within_t as p19
    from known_bad.withdrawal_toys import ToyWithdrawal

    class Replicas(ToyWithdrawal):
        def bind_requester(self, anchor, source_url, *, receiver=None):
            how = super().bind_requester(anchor, source_url, receiver=receiver)
            self.e2 = dict(self.store)                   # e2's copy, never refreshed again
            return how

        def present(self, p, *, session=None):
            self.at = p.endpoint
            return super().present(p, session=session)

        def _snap(self):
            if getattr(self, "at", "") == "e2":
                return self.e2["snap"], self._c().wall()
            return super()._snap()

        def _age(self, snap, fetched_at):
            return 0.0 if getattr(self, "at", "") == "e2" else super()._age(snap, fetched_at)
    real_init = p19._Run.__init__

    def one_endpoint(self, *a, **kw):                  # the guard off: one endpoint only
        real_init(self, *a, **kw)
        self.endpoints = self.endpoints[:1]
    monkeypatch.setattr(p19._Run, "__init__", one_endpoint)
    assert _c19(_p19(Replicas(), "f58-one", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("refused_within_T", True)                                             # the error
    monkeypatch.setattr(p19._Run, "__init__", real_init)
    assert _c19(_p19(Replicas(), "f58", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("not_refused_within_W", False)


def test_KRK_M59_an_outage_the_receiver_did_not_see_is_not_read_as_failing_safe(
        tmp_path, monkeypatch):
    """Anticipated. The stub's outage spares the receiver's own fetches (a second path). The
    `fails_open` toy then never meets the outage and reads as refusing within T; with the check,
    its successful fetches during the outage mean the outage did not land."""
    from conformance import requester
    from conformance.properties import p19_withdrawal_within_t as p19
    from known_bad.withdrawal_toys import make
    real = requester.StubRequester._serve

    def leaky(self, path, client):
        if str(client).startswith("toy-") and self._mode in ("down", "hang", "error"):
            return "ok", self.current()                 # a path the outage missed
        return real(self, path, client)
    monkeypatch.setattr(requester.StubRequester, "_serve", leaky)
    plan = {"trials": {"*": 1}, "variants": ["source_unreachable"]}
    real_breach = p19._outage_breaches
    monkeypatch.setattr(p19, "_outage_breaches", lambda run, t_w: [])   # the guard off
    assert _c19(_p19(make("fails_open"), "f59-blind", tmp_path, monkeypatch, plan))[
        "source_unreachable"] == ("refused_within_T", True)                    # the error
    monkeypatch.setattr(p19, "_outage_breaches", real_breach)
    got = _c19(_p19(make("fails_open"), "f59", tmp_path, monkeypatch, plan))
    assert got["source_unreachable"] == ("fixture_not_landed", None)


def test_KRK_M60_a_refusal_answered_over_an_effect_reads_from_the_effect(tmp_path, monkeypatch):
    """Anticipated. A receiver that answers refused once it knows of the withdrawal, and
    performs the effect anyway. Read by its answers it refuses within T; at the recorder it is
    never refused in the window."""
    from conformance import status as st
    from known_bad.withdrawal_toys import ToyWithdrawal

    class SaysNo(ToyWithdrawal):
        def present(self, p, *, session=None):
            ans = super().present(p, session=session)        # no_check: it performs it
            why, chain, values, _ = self._read(p)
            snap, _ = self._snap()
            if chain and snap and st.chain_state(snap, chain)["state"] not in st.IN_FORCE:
                return {"status": 403, "body": {"code": "refused", "reason": "withdrawn"}}
            return ans
    toy = SaysNo("bad", "no_check")
    toy.evidence_grade = lambda: "b-response"                      # the guard off
    assert _c19(_p19(toy, "f60-answers", tmp_path, monkeypatch, W3))["withdrawn"] == \
        ("refused_within_T", True)                                             # the error
    assert _c19(_p19(SaysNo("bad", "no_check"), "f60", tmp_path, monkeypatch, W3))[
        "withdrawn"] == ("not_refused_within_W", False)


def test_KRK_M61_a_stale_snapshot_that_already_showed_the_withdrawal_is_no_fixture(
        tmp_path, monkeypatch):
    """Anticipated. The "stale" snapshot stapled to each request is the current one, which
    already shows the withdrawal. The toy that trusts any signed snapshot then reads as refusing
    within T; with the check, the fixture did not land."""
    from conformance import requester
    from conformance.properties import p19_withdrawal_within_t as p19
    from known_bad.withdrawal_toys import make
    monkeypatch.setattr(requester.StubRequester, "latest_before",
                        lambda self, t: self.current())               # a "stale" one that is not
    plan = {"trials": {"*": 1}, "variants": ["stale_signed_snapshot"]}
    real = p19._staple_for
    monkeypatch.setattr(p19, "_staple_for", lambda stub, t_w, wd: (
        stub.latest_before(t_w)["profile_token"], stub.latest_before(t_w)["version"], ""))
    r = _p19(make("trusts_snapshot_signature"), "f61-fresh", tmp_path, monkeypatch, plan)
    assert _forms19(r, "stale_signed_snapshot")["stapled"] == "within"         # the error
    monkeypatch.setattr(p19, "_staple_for", real)
    r = _p19(make("trusts_snapshot_signature"), "f61", tmp_path, monkeypatch, plan)
    assert _forms19(r, "stale_signed_snapshot")["stapled"] == "fixture_not_landed"


def test_KRK_M62_a_narrowing_a_binary_list_cannot_carry_is_not_charged_to_the_receiver(
        tmp_path, monkeypatch):
    """Anticipated. A receiver that reads a binary revocation list. Narrowed in place, the list
    shows no change; taken as landed, the receiver reads as ignoring the narrowing. With the
    read-back it did not land; run as withdraw and reissue, the receiver refuses within T and
    the gap is recorded."""
    from conformance import requester, status
    from known_bad.withdrawal_toys import ToyWithdrawal

    class Binary(ToyWithdrawal):
        def status_profile(self):
            return status.BITSTRING

        def _fetch(self):
            try:
                code, tok = self._get()
            except Exception:
                return
            v = status.verify(tok, self._pinned(), status.BITSTRING_TYP) if code == 200 else None
            if v is not None and v.ok:
                self._take(v.claims)

        def _status(self, chain, values, staple):
            snap, fetched_at = self._snap()
            if snap is None or self._age(snap, fetched_at) > self.T / 2:
                return "status-unavailable"
            for g in chain:
                try:
                    if status.bit(snap["encoded_list"], g["status"]["index"]):
                        return "withdrawn"
                except IndexError:
                    pass                                   # issued after the list
            return None
    plan = {"trials": {"*": 1}, "variants": ["narrowed"]}
    real_narrow, real_rb = requester.StubRequester.narrow, requester.StubRequester.read_back

    def in_place(self, gid, ceiling):                 # a narrowing the list cannot carry
        return self._change(gid, "narrowed", {"state": "narrowed", "ceiling": dict(ceiling)},
                            gid)
    monkeypatch.setattr(requester.StubRequester, "narrow", in_place)
    monkeypatch.setattr(requester.StubRequester, "read_back",
                        lambda self, expect: {k: True for k in expect})   # the guard off
    assert _c19(_p19(Binary(), "f62-blind", tmp_path, monkeypatch, plan))["narrowed"] == \
        ("not_refused_within_W", False)                                        # the error
    monkeypatch.setattr(requester.StubRequester, "read_back", real_rb)
    assert _c19(_p19(Binary(), "f62-landed", tmp_path, monkeypatch, plan))["narrowed"] == \
        ("fixture_not_landed", None)
    monkeypatch.setattr(requester.StubRequester, "narrow", real_narrow)
    r = _p19(Binary(), "f62", tmp_path, monkeypatch, plan)
    assert _c19(r)["narrowed"] == ("refused_within_T", True)
    assert any(g.get("state") == "narrowed" for g in r.extra["format_gaps"])


def test_KRK_M63_a_regrant_at_the_refusals_own_instant_is_judged_after_it(tmp_path, monkeypatch):
    """Observed while building P19. The re-grant is issued at the first refusal; on the virtual
    clock they share an instant. Split strictly before it, the correct toy's trial ends in
    acceptances and reads never refused; with the probe's split, the re-grant is honoured."""
    import dataclasses
    from conformance.properties import p19_withdrawal_within_t as p19
    from known_bad.withdrawal_toys import make
    plan = {"trials": {"*": 1}, "variants": ["regrant"]}
    real = p19._split_at
    monkeypatch.setattr(p19, "_split_at", lambda log, mid: dataclasses.replace(
        log, presentations=[p for p in log.presentations if p.t_sent < mid],
        w_effects=[e for e in log.w_effects if e < mid]))          # the guard off
    assert _c19(_p19(make(), "f63-strict", tmp_path, monkeypatch, plan))["regrant"][1] is False
    monkeypatch.setattr(p19, "_split_at", real)
    assert _c19(_p19(make(), "f63", tmp_path, monkeypatch, plan))["regrant"] == \
        ("regrant_honoured", True)


def test_KRK_M64_a_restart_hook_that_restarted_nothing_is_not_a_restart(tmp_path, monkeypatch):
    """Anticipated. The restart hook returns without restarting. Taken at its word, the toy
    that forgets on restart reads as keeping its refusal; with the boot-id check, the restart
    did not land."""
    from conformance.properties import p19_withdrawal_within_t as p19
    from known_bad.withdrawal_toys import make
    toy = make("forgets_on_restart")
    toy.restart = lambda: {"before": toy.boot, "after": toy.boot, "how": "nothing"}
    plan = {"trials": {"*": 1}, "variants": ["restart_after_refusal"]}
    real = p19.restart_happened
    monkeypatch.setattr(p19, "restart_happened", lambda ret: True)     # the guard off
    assert _c19(_p19(toy, "f64-blind", tmp_path, monkeypatch, plan))[
        "restart_after_refusal"] == ("refused_within_T", True)                 # the error
    monkeypatch.setattr(p19, "restart_happened", real)
    toy = make("forgets_on_restart")
    toy.restart = lambda: {"before": toy.boot, "after": toy.boot, "how": "nothing"}
    assert _c19(_p19(toy, "f64", tmp_path, monkeypatch, plan))["restart_after_refusal"] == \
        ("not_landed", None)


def test_KRK_M65_a_receivers_clock_offset_is_reported_not_charged(tmp_path, monkeypatch):
    """Anticipated. The receiver stamps its answers 300 s ahead. Timed by those stamps the
    correct toy reads late; on the kit's clock it is within T, and the offset is reported."""
    from conformance.properties import p19_withdrawal_within_t as p19
    from known_bad.withdrawal_toys import ToyWithdrawal

    class Ahead(ToyWithdrawal):
        def present(self, p, *, session=None):
            ans = super().present(p, session=session)
            ans["b_time"] = self._c().wall() + 300.0
            return ans
    real_send = p19._Run.send

    def by_b_clock(self, p, under, **kw):              # the guard off: B's stamps as times
        pr = real_send(self, p, under, **kw)
        pr.t_sent += 300.0
        if pr.effect_t is not None:
            pr.effect_t += 300.0
        return pr
    monkeypatch.setattr(p19._Run, "send", by_b_clock)
    assert _c19(_p19(Ahead(), "f65-b", tmp_path, monkeypatch, W3))["withdrawn"][1] is False
    monkeypatch.setattr(p19._Run, "send", real_send)
    r = _p19(Ahead(), "f65", tmp_path, monkeypatch, W3)
    assert _c19(r)["withdrawn"] == ("refused_within_T", True)
    assert abs(r.extra["b_clock_offset_s"]["median"] - 300.0) < 1.0
