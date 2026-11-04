"""The kit's ground truth: an HTTP server that records everything that reaches it.

One file, standard library only, so it runs the same way in-process (tests, host-side
listeners) and as a container next to a target (`python mockserver.py --port 8080`).

It plays three roles:

- **Upstream mock.** Answers OpenAI-shaped `/chat/completions` and `/models`, so a gateway has
  somewhere real to forward to. What it received is the control for P1 and P2: a denied request
  that reached it got through; a canary in its Authorization header proves the gateway used the
  credential.
- **Side-effect recorder.** `POST /effect/<id>` counts executions, for P3 (exactly once?).
  Since KRK-18 (P18) it also keeps each effect's body byte for byte (``raw_b64``) and, when the
  body is a JSON object, its members (``effect``) and the time the caller's executor says it
  began (``began_at``: the body's ``began_at`` member, else an ``X-Began-At`` header, as epoch
  seconds). `MockServer.effects(prefix)` reads them back. Nothing about the answer changes.
  Since KRK-19 (P19) every record also carries ``t_kit``, the time it was committed on the kit's
  own clock (the `clock` the server was given, ``time.monotonic`` by default), so effect times
  and presentation times are read on one clock. `MockServer.hold(ref, retry_after_s)` makes the
  recorder answer the first effect whose body's ``ref`` is `ref` with ``503`` and a
  ``Retry-After``, without committing it (the ``in_flight`` variant: B holds the request and
  retries); that attempt is recorded with ``held`` true and is not an effect.
- **Egress listener.** Any request at all is a connection that got out, for P6. `--tcp-port`
  also records raw TCP connections that never speak HTTP.
- **Scripted model.** `POST /__script {"messages": [...]}` queues assistant messages (content
  and/or OpenAI `tool_calls`); each chat completion pops the next one. With `"key": K` the
  queue belongs to whichever conversation's requests contain the text K, so concurrent
  conversations each get their own script. This lets the kit drive
  an agent product's real tool path without a real model, and every later request the product
  sends to the "model" is a record of what the agent observed.

Read what it saw with `GET /__records`; clear it with `POST /__reset`.
"""
from __future__ import annotations

import argparse
import json
import socket
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional


class _State:
    def __init__(self, clock: Optional[Any] = None) -> None:
        self.lock = threading.Lock()
        self.records: List[Dict[str, Any]] = []
        self.tcp: List[Dict[str, Any]] = []
        self.script: List[Dict[str, Any]] = []
        self.keyed: Dict[str, List[Dict[str, Any]]] = {}
        self.clock = clock or time.monotonic
        self.holds: Dict[str, float] = {}
        """ref -> Retry-After seconds, for the next effect carrying that ref (one-shot)."""

    def take_hold(self, ref: Any) -> Optional[float]:
        with self.lock:
            return self.holds.pop(str(ref), None) if ref is not None else None

    def add(self, rec: Dict[str, Any]) -> None:
        with self.lock:
            self.records.append(rec)

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {"http": list(self.records), "tcp": list(self.tcp)}

    def reset(self) -> None:
        with self.lock:
            self.records.clear()
            self.tcp.clear()
            self.script.clear()
            self.keyed.clear()

    def next_scripted(self, body: str = "") -> Optional[Dict[str, Any]]:
        with self.lock:
            for key, queue in self.keyed.items():
                if queue and key in body:
                    return queue.pop(0)
            return self.script.pop(0) if self.script else None


def _handler(state: _State):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # The response's headers and body go out as two writes. With Nagle's algorithm on, the
        # second waits for the client's delayed ACK of the first, about 40 ms per request on a
        # kept-alive Linux connection (not on macOS loopback). No reading depends on it; it only
        # made the known-bad gate fifty times slower on Linux.
        disable_nagle_algorithm = True

        def log_message(self, *a: Any) -> None:  # quiet
            pass

        def _body(self) -> str:
            n = int(self.headers.get("Content-Length") or 0)
            self._raw = self.rfile.read(n) if n else b""
            return self._raw.decode("utf-8", "replace")

        def _send(self, code: int, obj: Any) -> None:
            raw = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_chat_stream(self, model: str, msg: Dict[str, Any]) -> None:
            """Emit the small OpenAI SSE subset used by the scripted agent targets."""
            completion_id = f"chatcmpl-{uuid.uuid4().hex}"
            created = int(time.time())
            delta: Dict[str, Any] = {"role": "assistant"}
            if msg.get("tool_calls"):
                delta["tool_calls"] = [
                    {"index": i, **call} for i, call in enumerate(msg["tool_calls"])
                ]
                finish = "tool_calls"
            else:
                delta["content"] = msg.get("content") or ""
                finish = "stop"
            chunks = [
                {"id": completion_id, "object": "chat.completion.chunk", "created": created,
                 "model": model,
                 "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                {"id": completion_id, "object": "chat.completion.chunk", "created": created,
                 "model": model,
                 "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                 "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}},
            ]
            raw = b"".join(f"data: {json.dumps(chunk)}\n\n".encode() for chunk in chunks)
            raw += b"data: [DONE]\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_responses_stream(self, model: str, msg: Dict[str, Any]) -> None:
            """Emit the small Responses-API SSE subset a local model provider consumes.

            The scripted queue deliberately remains shared with Chat Completions: target adapters
            can drive either wire API without a second mock or a real model endpoint.
            """
            response_id = f"resp-{uuid.uuid4().hex}"
            events: List[Dict[str, Any]] = [
                {"type": "response.created", "response": {"id": response_id,
                 "object": "response", "model": model, "status": "in_progress", "output": []}}
            ]
            output: List[Dict[str, Any]] = []
            for i, call in enumerate(msg.get("tool_calls", [])):
                fun = call.get("function", {})
                item = {"id": call.get("id", f"call-{uuid.uuid4().hex}"),
                        "type": "function_call", "call_id": call.get("id", f"call-{i}"),
                        "name": fun.get("name", ""), "arguments": fun.get("arguments", "{}")}
                events.append({"type": "response.output_item.added", "output_index": i,
                               "item": {**item, "arguments": ""}})
                events.append({"type": "response.function_call_arguments.delta", "output_index": i,
                               "item_id": item["id"], "delta": item["arguments"]})
                events.append({"type": "response.function_call_arguments.done", "output_index": i,
                               "item_id": item["id"], "arguments": item["arguments"]})
                events.append({"type": "response.output_item.done", "output_index": i, "item": item})
                output.append(item)
            if msg.get("content"):
                i = len(output)
                item = {"id": f"msg-{uuid.uuid4().hex}", "type": "message", "role": "assistant",
                        "content": [{"type": "output_text", "text": msg["content"]}]}
                events.append({"type": "response.output_item.added", "output_index": i, "item": item})
                events.append({"type": "response.output_text.delta", "output_index": i,
                               "item_id": item["id"], "delta": msg["content"]})
                events.append({"type": "response.output_item.done", "output_index": i, "item": item})
                output.append(item)
            events.append({"type": "response.completed", "response": {"id": response_id,
                           "object": "response", "model": model, "status": "completed", "output": output,
                           "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}})
            raw = b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _handle(self, method: str) -> None:
            self._raw = b""     # a kept-alive connection reuses the handler
            body = self._body() if method in ("POST", "PUT", "PATCH") else ""
            path = self.path
            if path.startswith("/__records"):
                return self._send(200, state.snapshot())
            if path.startswith("/__reset"):
                state.reset()
                return self._send(200, {"ok": True})
            if path.startswith("/__script"):
                req = json.loads(body or "{}")
                with state.lock:
                    if req.get("key"):
                        state.keyed.setdefault(req["key"], []).extend(req.get("messages", []))
                    else:
                        state.script.extend(req.get("messages", []))
                return self._send(200, {"queued": len(state.script)})
            rec = {"t": time.time(), "t_kit": state.clock(), "method": method, "path": path,
                   "headers": {k: v for k, v in self.headers.items()},
                   "body": body, "client": self.client_address[0]}
            if "/effect" in path:
                rec.update(_effect_fields(getattr(self, "_raw", b""), self.headers))
                ref = (rec.get("effect") or {}).get("ref")
                wait = state.take_hold(ref)
                if wait is not None:
                    rec.update(held=True, answered=503, retry_after_s=wait)
                    state.add(rec)
                    raw = json.dumps({"error": "unavailable", "retry_after_s": wait}).encode()
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Retry-After", str(int(round(wait))))
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
            state.add(rec)
            if path.rstrip("/").endswith("/chat/completions"):
                model, offers_tools, stream = "mock", False, False
                try:
                    parsed = json.loads(body)
                    model, offers_tools = parsed.get("model", model), bool(parsed.get("tools"))
                    stream = bool(parsed.get("stream"))
                except Exception:
                    pass
                # Only a request that offers tools consumes the script: products also make
                # side calls (title generation, summaries) that must not eat a scripted step.
                msg = (state.next_scripted(body) if offers_tools else None) or {"content": "mock reply"}
                if stream:
                    return self._send_chat_stream(model, msg)
                message = {"role": "assistant", "content": msg.get("content")}
                if msg.get("tool_calls"):
                    message["tool_calls"] = msg["tool_calls"]
                return self._send(200, {
                    "id": f"chatcmpl-{uuid.uuid4().hex}", "object": "chat.completion", "created": int(time.time()),
                    "model": model,
                    "choices": [{"index": 0, "message": message,
                                 "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}})
            if path.rstrip("/").endswith("/responses"):
                model = "mock"
                try:
                    parsed = json.loads(body)
                    model = parsed.get("model", model)
                except Exception:
                    pass
                # Some Responses clients describe their built-in tools out of band,
                # so their request has no top-level `tools` field.  A keyed script is explicit
                # test setup and is safe to consume on this wire format.
                msg = state.next_scripted(body) or {"content": "mock reply"}
                return self._send_responses_stream(model, msg)
            if path.rstrip("/").endswith("/models"):
                return self._send(200, {"object": "list", "data": [{"id": "mock", "object": "model"}]})
            return self._send(200, {"ok": True, "path": path})

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PUT(self) -> None:
            self._handle("PUT")

        def do_DELETE(self) -> None:
            self._handle("DELETE")

    return H


def _effect_fields(raw: bytes, headers: Any) -> Dict[str, Any]:
    """What the recorder keeps of one effect (KRK-18): the body's bytes, its members when it is
    a JSON object, and when the caller's executor says it began."""
    import base64
    out: Dict[str, Any] = {"raw_b64": base64.b64encode(raw).decode("ascii"), "effect": None,
                           "began_at": None}
    try:
        doc = json.loads(raw.decode("utf-8")) if raw else None
    except (ValueError, UnicodeDecodeError):
        doc = None
    if isinstance(doc, dict):
        out["effect"] = doc
        if isinstance(doc.get("began_at"), (int, float)):
            out["began_at"] = float(doc["began_at"])
    if out["began_at"] is None:
        try:
            out["began_at"] = float(headers.get("X-Began-At"))
        except (TypeError, ValueError):
            pass
    return out


def effects(records: Dict[str, Any], prefix: str = "", *, held: bool = False
            ) -> List[Dict[str, Any]]:
    """The effects among `records` (a `records()` snapshot) whose path starts with `prefix`,
    oldest first: ``path``, ``t`` (when the recorder received it), ``t_kit`` (the same on the
    kit's clock), ``began_at``, ``effect`` (the body's members, or None) and ``raw`` (the body's
    bytes). An attempt the recorder held (`MockServer.hold`) committed nothing and is left out,
    unless `held` is true, which returns only those."""
    import base64
    out = []
    for r in records.get("http", []):
        if "raw_b64" not in r or not r["path"].startswith(prefix):
            continue
        if bool(r.get("held")) != held:
            continue
        out.append({"path": r["path"], "t": r["t"], "t_kit": r.get("t_kit"),
                    "began_at": r.get("began_at"), "effect": r.get("effect"),
                    "raw": base64.b64decode(r["raw_b64"])})
    return out


def _tcp_listener(state: _State, port: int, host: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(16)
    while True:
        conn, addr = srv.accept()
        conn.settimeout(2)
        try:
            data = conn.recv(256)
        except Exception:
            data = b""
        with state.lock:
            state.tcp.append({"t": time.time(), "client": addr[0],
                              "first_bytes": data.decode("utf-8", "replace")})
        try:
            conn.sendall(b"conformance-kit-tcp-ok\n")
        except Exception:
            pass
        conn.close()


class MockServer:
    """In-process instance, for tests and for host-side listeners."""

    def __init__(self, host: Optional[str] = None, port: int = 0,
                 tcp_port: Optional[int] = None, clock: Optional[Any] = None) -> None:
        from . import netbind
        host = netbind.bind_host(host)          # 127.0.0.1 unless ACK_BIND_HOST says otherwise
        self.state = _State(clock)
        self.httpd = netbind.server_class(host)((host, port), _handler(self.state))
        self.host, self.port = self.httpd.server_address[0], self.httpd.server_address[1]
        self.advertised = netbind.advertise_host(self.host)
        self.tcp_port = tcp_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        if tcp_port is not None:
            threading.Thread(target=_tcp_listener, args=(self.state, tcp_port, host),
                             daemon=True).start()

    @property
    def url(self) -> str:
        from . import netbind
        return f"http://{netbind.url_host(self.advertised)}:{self.port}"

    def records(self) -> Dict[str, Any]:
        return self.state.snapshot()

    def effects(self, prefix: str = "") -> List[Dict[str, Any]]:
        """Every effect received under `prefix` (module docstring, the recorder)."""
        return effects(self.state.snapshot(), prefix)

    def effects_after(self, index: int, prefix: str = "") -> "tuple[List[Dict[str, Any]], int]":
        """The effects among records ``index`` onwards (held attempts left out), and the index to
        read from next time, so a long run reads each record once."""
        with self.state.lock:
            recs = self.state.records[index:]
            nxt = len(self.state.records)
        return effects({"http": recs}, prefix), nxt

    def held(self, prefix: str = "") -> List[Dict[str, Any]]:
        """Every effect attempt under `prefix` the recorder held and did not commit."""
        return effects(self.state.snapshot(), prefix, held=True)

    def hold(self, ref: str, retry_after_s: float) -> None:
        """Answer the next effect whose body's ``ref`` is `ref` with 503 and ``Retry-After``,
        committing nothing (design §3.1 ``in_flight``)."""
        with self.state.lock:
            self.state.holds[str(ref)] = float(retry_after_s)

    def reset(self) -> None:
        self.state.reset()

    def close(self) -> None:
        self.httpd.shutdown()


class RemoteMock:
    """Client for a mockserver running elsewhere (a container next to the target)."""

    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def records(self) -> Dict[str, Any]:
        with urllib.request.urlopen(f"{self.url}/__records", timeout=10) as r:
            return json.loads(r.read())

    def reset(self) -> None:
        req = urllib.request.Request(f"{self.url}/__reset", data=b"{}", method="POST")
        urllib.request.urlopen(req, timeout=10).read()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--tcp-port", type=int, default=None)
    a = ap.parse_args()
    state = _State()
    if a.tcp_port:
        threading.Thread(target=_tcp_listener, args=(state, a.tcp_port, a.host), daemon=True).start()
    ThreadingHTTPServer((a.host, a.port), _handler(state)).serve_forever()


if __name__ == "__main__":
    main()
