"""
Cmail audit-trail — gateway-event.v1 emitters for cmail.message.sent/received.

Every cmail action lands as a `gateway-event.v1` record. The events match the
canonical cmail-event fixtures in `tibet-cap-bus 0.1.3+` (`cmail-events.v1.json`)
so a downstream cap-bus consumer can reconstruct the full message journey.

Light Mode v0.1.1 writes events to a local JSONL audit log (default
`~/.cmail/audit.jsonl`). Future versions (0.2.x+) will also POST the event to a
cap-bus runtime when one is reachable. Lazy validation against
`tibet_cap_bus.validate_gateway_event_record` is best-effort: if cap-bus is not
installed, the events are still well-formed and validate-able later.

The shape of the gateway-event.v1 record is fixed; this module only sets the
cmail-specific fields. See `tibet_cap_bus.event_contract` for the canonical
field list.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .envelope import Envelope


# Intent strings — match cap-bus cmail-event fixtures verbatim.
CMAIL_SENT_INTENT = "cmail.message.sent"
CMAIL_RECEIVED_INTENT = "cmail.message.received"

DEFAULT_AUDIT_PATH = Path.home() / ".cmail" / "audit.jsonl"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _event_id(prefix: str) -> str:
    return f"evt_{prefix}_{uuid.uuid4().hex[:12]}"


def _operation_id(envelope: Envelope) -> str:
    """One operation per message, derived from the envelope's message_id."""
    return f"op_{envelope.message_id}"


def _base_event(
    *,
    intent: str,
    envelope: Envelope,
    actor: str,
    status: str,
    latency_ms: float,
    surface: str,
    extra_payload: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build a gateway-event.v1 record with cmail-specific fields filled in."""
    payload: dict[str, Any] = {
        "intent": intent,
        "to": envelope.to,
        "envelope_kind": "message",
        "content_hash": envelope.content_hash,
    }
    if extra_payload:
        payload.update(extra_payload)

    return {
        # REQUIRED_GATEWAY_FIELDS
        "event_id": _event_id(intent.split(".")[-1]),
        "observation_layer": "tibet-gateway",
        "timestamp": _utcnow_iso(),
        "operation_id": _operation_id(envelope),
        "agent_id": actor,
        "intent": intent,
        "provider": "user-direct",
        "model": "user-direct",
        "route_class": "direct",
        "surface": surface,
        "transport": "ipoll-http",
        "status": status,
        "latency_ms": latency_ms,
        "lane_class": "human-message",
        "lane_collision_policy": "queue",
        "coffee_lane_policy": "sip_anyway",
        "attestation_layer": "jis",
        "_emitter": "tibet-cmail",
        # Useful optional fields (validate as object/string when present)
        "actor_aint": actor,
        "actor_jis_pubkey": None,
        "verified": True,
        "envelope_id": envelope.message_id,
        "content_hash": envelope.content_hash,
        "attestation_ref": f"attest:{envelope.message_id}",
        "gateway_actor": "jis:tibet-cmail",
        "payload": payload,
    }


def build_sent_event(envelope: Envelope, latency_ms: float = 0.0) -> dict[str, Any]:
    """gateway-event.v1 record for an outbound cmail."""
    return _base_event(
        intent=CMAIL_SENT_INTENT,
        envelope=envelope,
        actor=envelope.from_,
        status="cmail-pushed",
        latency_ms=latency_ms,
        surface=f"cmail.sent:{envelope.to}",
    )


def build_received_event(envelope: Envelope, recipient: str) -> dict[str, Any]:
    """gateway-event.v1 record for an inbound cmail observation."""
    return _base_event(
        intent=CMAIL_RECEIVED_INTENT,
        envelope=envelope,
        actor=recipient,
        status="cmail-observed",
        latency_ms=0.0,
        surface=f"cmail.received:{recipient}",
        extra_payload={"from": envelope.from_},
    )


def log_event(event: dict[str, Any], path: Optional[Path | str] = None) -> Path:
    """Append a gateway-event.v1 record to the local JSONL audit log.

    Creates the parent directory if needed. Returns the path that was written
    so callers can show it to the user.
    """
    target = Path(path) if path is not None else DEFAULT_AUDIT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    return target


def try_validate(event: dict[str, Any]) -> list[str]:
    """Best-effort validation against `tibet_cap_bus.validate_gateway_event_record`.

    Returns a list of error strings (empty = pass, or = "cap-bus not installed").
    Never raises: the audit-log is the source of truth; validation is for tests/CI.
    """
    try:
        from tibet_cap_bus import validate_gateway_event_record  # type: ignore
    except ImportError:
        return []
    try:
        return list(validate_gateway_event_record(event))
    except Exception as e:  # pragma: no cover — pathological
        return [f"validation raised: {e!r}"]
