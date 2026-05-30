"""Tests for tibet_cmail.audit — gateway-event.v1 emit + JSONL log."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make tibet_cap_bus importable for cross-contract validation
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "tibet-cap-bus" / "src"),
)

from tibet_cmail.audit import (
    CMAIL_RECEIVED_INTENT,
    CMAIL_SENT_INTENT,
    build_received_event,
    build_sent_event,
    log_event,
    try_validate,
)
from tibet_cmail.envelope import build_envelope


def _envelope():
    return build_envelope(
        from_="alice.aint",
        to="bob.aint",
        subject="lunch?",
        body="12:30",
    )


def test_sent_event_has_correct_intent_and_actor():
    e = _envelope()
    ev = build_sent_event(e, latency_ms=42.5)
    assert ev["intent"] == CMAIL_SENT_INTENT
    assert ev["agent_id"] == "alice.aint"
    assert ev["actor_aint"] == "alice.aint"
    assert ev["latency_ms"] == pytest.approx(42.5)
    assert ev["payload"]["to"] == "bob.aint"
    assert ev["payload"]["content_hash"] == e.content_hash
    assert ev["envelope_id"] == e.message_id


def test_received_event_has_correct_intent_and_recipient():
    e = _envelope()
    ev = build_received_event(e, recipient="bob")
    assert ev["intent"] == CMAIL_RECEIVED_INTENT
    assert ev["agent_id"] == "bob"
    assert ev["actor_aint"] == "bob"
    assert ev["payload"]["from"] == "alice.aint"
    assert ev["payload"]["to"] == "bob.aint"


def test_emitter_and_layers_are_canonical():
    e = _envelope()
    sent = build_sent_event(e)
    received = build_received_event(e, recipient="bob")
    for ev in (sent, received):
        assert ev["_emitter"] == "tibet-cmail"
        assert ev["observation_layer"] == "tibet-gateway"
        assert ev["attestation_layer"] == "jis"
        assert ev["lane_class"] == "human-message"


def test_event_id_unique_per_emit():
    e = _envelope()
    a = build_sent_event(e)
    b = build_sent_event(e)
    assert a["event_id"] != b["event_id"]


def test_operation_id_stable_per_envelope():
    """Same envelope → same operation_id, so send + receive correlate."""
    e = _envelope()
    sent = build_sent_event(e)
    received = build_received_event(e, recipient="bob")
    assert sent["operation_id"] == received["operation_id"]
    assert sent["operation_id"].endswith(e.message_id)


def test_log_event_appends_jsonl(tmp_path):
    audit = tmp_path / "audit.jsonl"
    e = _envelope()
    ev1 = build_sent_event(e)
    ev2 = build_received_event(e, recipient="bob")

    path1 = log_event(ev1, audit)
    path2 = log_event(ev2, audit)
    assert path1 == audit
    assert path2 == audit

    lines = audit.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    rec1 = json.loads(lines[0])
    rec2 = json.loads(lines[1])
    assert rec1["intent"] == CMAIL_SENT_INTENT
    assert rec2["intent"] == CMAIL_RECEIVED_INTENT


def test_log_event_creates_parent_dir(tmp_path):
    audit = tmp_path / "deep" / "nested" / "audit.jsonl"
    assert not audit.parent.exists()
    log_event(build_sent_event(_envelope()), audit)
    assert audit.exists()


def test_sent_event_validates_against_cap_bus_contract():
    """Cross-package: every emitted event must pass cap-bus validation."""
    e = _envelope()
    ev = build_sent_event(e)
    errors = try_validate(ev)
    assert errors == [], f"sent event failed cap-bus validation: {errors}"


def test_received_event_validates_against_cap_bus_contract():
    e = _envelope()
    ev = build_received_event(e, recipient="bob.aint")
    errors = try_validate(ev)
    assert errors == [], f"received event failed cap-bus validation: {errors}"


def test_try_validate_safe_when_cap_bus_missing(monkeypatch):
    """If cap-bus is not installed, try_validate returns []."""
    import builtins
    real_import = builtins.__import__

    def blocking_import(name, *args, **kwargs):
        if name == "tibet_cap_bus":
            raise ImportError("simulated: cap-bus not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocking_import)
    errors = try_validate(build_sent_event(_envelope()))
    assert errors == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
