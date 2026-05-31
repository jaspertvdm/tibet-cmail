"""Tests for tibet_cmail.posture_watcher — verdict.v1 → autonomous cmail."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tibet_cmail.posture_watcher import (
    DEFAULT_OPERATOR,
    POSTURE_CMAIL_SENDER,
    VERDICT_KIND,
    PostureTransition,
    build_posture_envelope,
    detect_transition,
    is_verdict_record,
    iter_jsonl_records,
    load_state,
    save_state,
    scan_for_transitions,
)


# Re-use cap-bus verdict.v1 fixtures
FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "tibet-cap-bus"
    / "fixtures"
    / "airlock-runtime-verdict.v1.example.json"
)


def _fixtures():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _verdict(mode: str) -> dict:
    return next(v for v in _fixtures() if v["runtime_mode"] == mode)


# ─── kind detection ───────────────────────────────────────────────


def test_is_verdict_record_true_for_v1():
    assert is_verdict_record(_verdict("embedded_online")) is True


def test_is_verdict_record_false_for_gateway_event():
    assert is_verdict_record({"kind": "gateway-event.v1"}) is False


def test_is_verdict_record_false_for_non_dict():
    assert is_verdict_record("not a dict") is False


# ─── transition detection ─────────────────────────────────────────


def test_cold_start_counts_as_transition():
    t = detect_transition(_verdict("embedded_online"), last_known=None)
    assert t is not None
    assert t.is_cold_start is True
    assert t.previous_runtime_mode is None
    assert t.current_runtime_mode == "embedded_online"


def test_same_record_is_not_transition():
    v = _verdict("embedded_online")
    t = detect_transition(v, last_known=v)
    assert t is None


def test_mode_change_is_transition():
    healthy = _verdict("embedded_online")
    degraded = _verdict("python_fallback")
    t = detect_transition(degraded, last_known=healthy)
    assert t is not None
    assert t.is_cold_start is False
    assert t.previous_runtime_mode == "embedded_online"
    assert t.current_runtime_mode == "python_fallback"
    assert t.previous_snaft_posture == "normal_zero_trust"
    assert t.current_snaft_posture == "quarantine_external_ai"


def test_posture_change_with_same_mode_is_transition():
    """Hypothetical: same runtime_mode but different snaft_posture flips."""
    a = dict(_verdict("kernel_online"))
    b = dict(_verdict("kernel_online"))
    b["snaft_posture"] = "quarantine_external_ai"  # forced different
    t = detect_transition(b, last_known=a)
    assert t is not None
    assert t.previous_snaft_posture == "normal_zero_trust"
    assert t.current_snaft_posture == "quarantine_external_ai"


def test_non_verdict_record_returns_none():
    t = detect_transition({"kind": "something.else"}, last_known=None)
    assert t is None


# ─── envelope shape ───────────────────────────────────────────────


def test_cold_start_envelope_subject():
    t = detect_transition(_verdict("embedded_online"), last_known=None)
    env = build_posture_envelope(t)
    assert "cold-start" in env.subject
    assert "embedded_online" in env.subject
    assert "[INFO]" in env.subject


def test_degradation_envelope_subject():
    healthy = _verdict("embedded_online")
    degraded = _verdict("python_fallback")
    t = detect_transition(degraded, last_known=healthy)
    env = build_posture_envelope(t)
    assert "embedded_online → python_fallback" in env.subject
    assert "[WARNING]" in env.subject


def test_offline_envelope_is_critical():
    fallback = _verdict("python_fallback")
    offline = _verdict("offline")
    t = detect_transition(offline, last_known=fallback)
    env = build_posture_envelope(t)
    assert "[CRITICAL]" in env.subject
    assert "offline" in env.subject


def test_envelope_body_carries_full_verdict_context():
    t = detect_transition(_verdict("python_fallback"), last_known=_verdict("embedded_online"))
    env = build_posture_envelope(t)
    assert "rust_airlock" in env.body
    assert "trust_kernel" in env.body
    assert "external_ai_inbound" in env.body
    assert "deny" in env.body  # python_fallback denies external AI
    assert "Reason:" in env.body
    assert "Verdict ID:" in env.body


def test_envelope_defaults_to_root_idd_operator():
    t = detect_transition(_verdict("embedded_online"), last_known=None)
    env = build_posture_envelope(t)
    assert env.to == DEFAULT_OPERATOR
    assert env.from_ == POSTURE_CMAIL_SENDER


def test_envelope_custom_operator():
    t = detect_transition(_verdict("embedded_online"), last_known=None)
    env = build_posture_envelope(t, operator="oncall.aint")
    assert env.to == "oncall.aint"


# ─── state persistence + scan ─────────────────────────────────────


def test_state_round_trip(tmp_path):
    state = tmp_path / "posture-state.json"
    v = _verdict("embedded_online")
    save_state(v, state)
    loaded = load_state(state)
    assert loaded == v


def test_load_state_returns_none_when_missing(tmp_path):
    assert load_state(tmp_path / "no-such.json") is None


def test_iter_jsonl_records_yields_all(tmp_path):
    f = tmp_path / "events.jsonl"
    a = _verdict("embedded_online")
    b = _verdict("kernel_online")
    f.write_text(json.dumps(a) + "\n" + json.dumps(b) + "\n", encoding="utf-8")
    records = list(iter_jsonl_records(f))
    assert len(records) == 2
    assert records[0]["runtime_mode"] == "embedded_online"
    assert records[1]["runtime_mode"] == "kernel_online"


def test_iter_jsonl_skips_blank_and_invalid_lines(tmp_path):
    f = tmp_path / "events.jsonl"
    f.write_text("\n  \n{not json\n" + json.dumps(_verdict("embedded_online")) + "\n",
                 encoding="utf-8")
    records = list(iter_jsonl_records(f))
    assert len(records) == 1


def test_scan_for_transitions_full_journey(tmp_path):
    """End-to-end: 4-mode journey should yield 4 transitions on cold-start scan."""
    f = tmp_path / "verdicts.jsonl"
    state = tmp_path / "state.json"
    fixtures = _fixtures()
    # Write all 4 fixtures in order (embedded → kernel → python_fallback → offline)
    ordered_modes = ["embedded_online", "kernel_online", "python_fallback", "offline"]
    with f.open("w", encoding="utf-8") as out:
        for mode in ordered_modes:
            out.write(json.dumps(_verdict(mode)) + "\n")
    transitions = list(scan_for_transitions(f, state_path=state, follow=False))
    assert len(transitions) == 4
    assert transitions[0].is_cold_start is True
    assert transitions[0].current_runtime_mode == "embedded_online"
    assert transitions[1].current_runtime_mode == "kernel_online"
    assert transitions[2].current_runtime_mode == "python_fallback"
    assert transitions[3].current_runtime_mode == "offline"
    # State should now point at the last verdict
    assert load_state(state)["runtime_mode"] == "offline"


def test_scan_resumes_from_state(tmp_path):
    """Running scan a second time only emits new transitions since last state."""
    f = tmp_path / "verdicts.jsonl"
    state = tmp_path / "state.json"
    # First pass: just the healthy verdict
    f.write_text(json.dumps(_verdict("embedded_online")) + "\n", encoding="utf-8")
    transitions = list(scan_for_transitions(f, state_path=state, follow=False))
    assert len(transitions) == 1

    # Append a degraded verdict
    with f.open("a", encoding="utf-8") as out:
        out.write(json.dumps(_verdict("python_fallback")) + "\n")

    # Second pass: only the new one should yield (healthy re-read is no-op)
    transitions = list(scan_for_transitions(f, state_path=state, follow=False))
    assert len(transitions) == 1
    assert transitions[0].current_runtime_mode == "python_fallback"
    assert transitions[0].previous_runtime_mode == "embedded_online"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
