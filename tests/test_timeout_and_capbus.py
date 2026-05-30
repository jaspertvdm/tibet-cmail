"""Tests for 0.2.2: TimeoutError handling + optional cap-bus runtime POST."""

from __future__ import annotations

import json
import socket
import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tibet_cmail.audit import (
    CAPBUS_URL_ENV,
    _maybe_post_to_capbus,
    build_sent_event,
    log_event,
)
from tibet_cmail.cli import _is_timeout
from tibet_cmail.envelope import build_envelope


# ─── _is_timeout detection ────────────────────────────────────────


def test_is_timeout_detects_direct_timeout():
    assert _is_timeout(TimeoutError("x")) is True


def test_is_timeout_walks_cause_chain():
    inner = TimeoutError("inner")
    outer = OSError("wrapper")
    outer.__cause__ = inner
    assert _is_timeout(outer) is True


def test_is_timeout_false_for_other_errors():
    assert _is_timeout(ValueError("x")) is False
    assert _is_timeout(ConnectionRefusedError("x")) is False


# ─── cap-bus POST opt-in ──────────────────────────────────────────


class _Receiver(BaseHTTPRequestHandler):
    captured: list[dict] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            self.__class__.captured.append(json.loads(body.decode()))
        except Exception:
            pass
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, fmt, *args):  # silence
        pass


@pytest.fixture
def capbus_endpoint():
    _Receiver.captured = []
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = HTTPServer(("127.0.0.1", port), _Receiver)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_no_env_var_no_post(monkeypatch):
    """No CMAIL_CAPBUS_URL set → POST not attempted."""
    monkeypatch.delenv(CAPBUS_URL_ENV, raising=False)
    e = build_sent_event(build_envelope(from_="a", to="b", subject="s", body="x"))
    # Should not raise
    _maybe_post_to_capbus(e)


def test_env_var_triggers_post(monkeypatch, capbus_endpoint):
    monkeypatch.setenv(CAPBUS_URL_ENV, capbus_endpoint)
    e = build_sent_event(build_envelope(from_="a", to="b", subject="s", body="hi"))
    _maybe_post_to_capbus(e)
    # Server receives 1 event
    assert len(_Receiver.captured) == 1
    assert _Receiver.captured[0]["intent"] == "cmail.message.sent"
    assert _Receiver.captured[0]["agent_id"] == "a"


def test_offline_endpoint_does_not_raise(monkeypatch):
    """A wrong/offline CMAIL_CAPBUS_URL must not crash the audit-log path."""
    monkeypatch.setenv(CAPBUS_URL_ENV, "http://127.0.0.1:1")
    e = build_sent_event(build_envelope(from_="a", to="b", subject="s", body="x"))
    # Must complete without raising
    _maybe_post_to_capbus(e)


def test_log_event_also_posts(monkeypatch, tmp_path, capbus_endpoint):
    """Live integration: log_event() also POSTs when env is set."""
    monkeypatch.setenv(CAPBUS_URL_ENV, capbus_endpoint)
    audit = tmp_path / "audit.jsonl"
    e = build_sent_event(build_envelope(from_="alice", to="bob", subject="s", body="hi"))
    log_event(e, audit)
    # JSONL is written
    assert audit.exists()
    assert len(audit.read_text().splitlines()) == 1
    # AND endpoint received the event
    assert len(_Receiver.captured) == 1
    assert _Receiver.captured[0]["envelope_id"] == e["envelope_id"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
