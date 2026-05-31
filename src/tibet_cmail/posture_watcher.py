"""
Autonomous posture-cmail — emit a cmail when the airlock-runtime posture
transitions.

Closes the loop from yesterday's immune-switch keten:

    tibet-pol observes runtime state
       → emits airlock_runtime_verdict.v1 (gisteren's contract)
            → tibet-cmail posture-watch detects transition
                 → builds a cmail envelope (subject + body)
                      → sends to the operator (root_idd / on-call)

Two integration paths:

1. Standalone watcher (this module + `tibet-cmail posture-watch` CLI):
   tails a JSONL file of verdict.v1 records, keeps last-seen state in
   ~/.cmail/posture-state.json, emits a cmail when (runtime_mode,
   snaft_posture) changes. No daemon coupling required.

2. Library hook (`build_posture_envelope` + `is_transition`):
   snaft / tibet-pol can call this directly from `consume_verdict()`
   to emit a cmail inline. Tighter coupling, but no separate process.

Jasper 2026-05-30 reply: "Zodra jij in de toekomst een afwijkende posture of
een W3C-incident via de cap-bus registreert, verwacht ik autonoom een cmail
in deze inbox, exact op de milliseconde dat SNAFT de Airlock dichttimmert."
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

from .envelope import Envelope, build_envelope


VERDICT_KIND = "airlock_runtime_verdict.v1"
DEFAULT_STATE_PATH = Path.home() / ".cmail" / "posture-state.json"
DEFAULT_OPERATOR = "root_idd.aint"
POSTURE_CMAIL_SENDER = "jis:humotica:tibet-pol"


@dataclass(frozen=True)
class PostureTransition:
    """A detected change in (runtime_mode, snaft_posture) since last seen."""
    verdict: dict[str, Any]
    previous_runtime_mode: Optional[str]
    current_runtime_mode: str
    previous_snaft_posture: Optional[str]
    current_snaft_posture: str
    is_cold_start: bool  # True when no previous state existed


def is_verdict_record(record: dict[str, Any]) -> bool:
    """True if the record is an airlock_runtime_verdict.v1."""
    return isinstance(record, dict) and record.get("kind") == VERDICT_KIND


def detect_transition(
    record: dict[str, Any], last_known: Optional[dict[str, Any]],
) -> Optional[PostureTransition]:
    """Return a PostureTransition if record represents a change from last_known.

    Cold-start (last_known is None) counts as transition. Same (runtime_mode,
    snaft_posture) as last_known is *not* a transition (heartbeat refresh).
    """
    if not is_verdict_record(record):
        return None
    current_mode = record.get("runtime_mode")
    current_posture = record.get("snaft_posture")
    if current_mode is None or current_posture is None:
        return None

    if last_known is None:
        return PostureTransition(
            verdict=record,
            previous_runtime_mode=None,
            current_runtime_mode=current_mode,
            previous_snaft_posture=None,
            current_snaft_posture=current_posture,
            is_cold_start=True,
        )

    prev_mode = last_known.get("runtime_mode")
    prev_posture = last_known.get("snaft_posture")
    if prev_mode == current_mode and prev_posture == current_posture:
        return None  # heartbeat refresh, no transition

    return PostureTransition(
        verdict=record,
        previous_runtime_mode=prev_mode,
        current_runtime_mode=current_mode,
        previous_snaft_posture=prev_posture,
        current_snaft_posture=current_posture,
        is_cold_start=False,
    )


def build_posture_envelope(
    transition: PostureTransition,
    operator: str = DEFAULT_OPERATOR,
    sender: str = POSTURE_CMAIL_SENDER,
) -> Envelope:
    """Compose a cmail envelope from a PostureTransition.

    Subject reads at-a-glance: "Posture change: kernel_online → python_fallback".
    Body has the full verdict context for an operator to act on or audit later.
    """
    new_mode = transition.current_runtime_mode
    new_posture = transition.current_snaft_posture
    prev_mode = transition.previous_runtime_mode or "(cold start)"
    verdict = transition.verdict

    severity = {
        "normal_zero_trust": "INFO",
        "quarantine_external_ai": "WARNING",
        "hard_quarantine": "CRITICAL",
    }.get(new_posture, "INFO")

    subject = (
        f"[{severity}] Posture change: {prev_mode} → {new_mode}"
        if not transition.is_cold_start
        else f"[{severity}] Posture cold-start: {new_mode}"
    )

    body_lines = [
        f"Runtime posture transition detected.",
        "",
        f"  Previous mode:    {prev_mode}",
        f"  New mode:         {new_mode}",
        f"  New posture:      {new_posture}",
        f"  Severity:         {severity}",
        "",
        f"  Layer states:",
        f"    rust_airlock          = {verdict.get('rust_airlock')}",
        f"    trust_kernel          = {verdict.get('trust_kernel')}",
        f"    python_fallback       = {verdict.get('python_fallback')}",
        "",
        f"  Active enforcement:",
        f"    external_ai_inbound   = {verdict.get('external_ai_inbound')}",
        f"    execution_policy      = {verdict.get('execution_policy')}",
        "",
        f"  Reason:",
        f"    {verdict.get('reason', '(none)')}",
        "",
        f"  Verdict ID:       {verdict.get('verdict_id', '?')}",
        f"  Emitter:          {verdict.get('emitter', '?')}",
        f"  Timestamp:        {verdict.get('timestamp', '?')}",
        f"  Attestation ref:  {verdict.get('attestation_ref', '(none)')}",
        "",
        f"— tibet-cmail posture-watch (auto-emit on verdict.v1 transition)",
    ]

    return build_envelope(
        from_=sender,
        to=operator,
        subject=subject,
        body="\n".join(body_lines),
    )


def load_state(state_path: Optional[Path] = None) -> Optional[dict[str, Any]]:
    """Return the last-seen verdict record, or None if no state yet."""
    target = Path(state_path) if state_path else DEFAULT_STATE_PATH
    if not target.exists():
        return None
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_state(record: dict[str, Any], state_path: Optional[Path] = None) -> Path:
    """Persist the most recent verdict record for future transition detection."""
    target = Path(state_path) if state_path else DEFAULT_STATE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def iter_jsonl_records(path: Path, *, follow: bool = False, poll_seconds: float = 1.0) -> Iterator[dict[str, Any]]:
    """Yield JSONL records from path. If follow=True, tail forever (like `tail -F`).

    For one-shot scan, yields all existing records then stops. For follow,
    yields existing records then keeps polling for appends.
    """
    target = Path(path)
    if not target.exists() and not follow:
        return
    # Yield existing content first
    if target.exists():
        with target.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    if not follow:
        return
    # Tail loop
    last_size = target.stat().st_size if target.exists() else 0
    while True:
        time.sleep(poll_seconds)
        if not target.exists():
            continue
        cur_size = target.stat().st_size
        if cur_size <= last_size:
            continue
        with target.open("r", encoding="utf-8") as f:
            f.seek(last_size)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        last_size = cur_size


def scan_for_transitions(
    source_path: Path,
    *,
    state_path: Optional[Path] = None,
    follow: bool = False,
) -> Iterator[PostureTransition]:
    """Yield PostureTransition for every verdict.v1 record that changes state.

    Stateful: persists last-seen verdict to state_path so a subsequent call
    only emits transitions since last run. Use follow=True for live watching.
    """
    last_known = load_state(state_path)
    for record in iter_jsonl_records(Path(source_path), follow=follow):
        transition = detect_transition(record, last_known)
        if transition is not None:
            save_state(record, state_path)
            last_known = record
            yield transition
