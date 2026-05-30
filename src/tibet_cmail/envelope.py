"""
Cmail envelope — the shape of a Light Mode cmail.

A cmail envelope is a JSON object that travels inside an I-Poll PUSH content
field. It carries the human-readable fields (from/to/subject/body/sent_at)
plus a unique message_id and a content_hash so receivers can verify integrity
without opening the body. Auditors who hold the corresponding
`gateway-event.v1` on cap-bus can cross-reference the message_id.

Shape (v0.1):

    {
        "kind": "cmail.message.v1",
        "message_id": "cmail_<uuid4>",
        "from": "alice.aint",
        "to": "bob.aint",
        "subject": "Re: lunch?",
        "body": "...",
        "body_class": "text/plain",
        "sent_at": "2026-05-30T08:00:00+00:00",
        "content_hash": "sha256:..."
    }

Sealed Mode (v0.2) will add tbz_envelope_ref + attestation_ref + JIS-signed
fields. The kind string changes to `cmail.message.sealed.v1` to differentiate.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


CMAIL_KIND = "cmail.message.v1"


def hash_body(body: str) -> str:
    """Return sha256:<hex> for the given body (canonical UTF-8 encoding)."""
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Envelope:
    """A Light Mode cmail envelope."""

    from_: str
    to: str
    subject: str
    body: str
    message_id: str = field(default_factory=lambda: f"cmail_{uuid.uuid4().hex[:16]}")
    sent_at: str = field(default_factory=_utcnow_iso)
    body_class: str = "text/plain"
    content_hash: str = ""
    kind: str = CMAIL_KIND

    def __post_init__(self):
        if not self.content_hash:
            self.content_hash = hash_body(self.body)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # JSON-friendly: rename `from_` → `from`
        d["from"] = d.pop("from_")
        # Stable key order matters for hash-stable serialisation
        ordered_keys = ("kind", "message_id", "from", "to", "subject",
                        "body", "body_class", "sent_at", "content_hash")
        return {k: d[k] for k in ordered_keys}

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Envelope":
        return cls(
            from_=data["from"],
            to=data["to"],
            subject=data.get("subject", ""),
            body=data["body"],
            message_id=data.get("message_id", ""),
            sent_at=data.get("sent_at", ""),
            body_class=data.get("body_class", "text/plain"),
            content_hash=data.get("content_hash", ""),
            kind=data.get("kind", CMAIL_KIND),
        )

    @classmethod
    def from_json(cls, payload: str) -> "Envelope":
        return cls.from_dict(json.loads(payload))

    def verify(self) -> bool:
        """True iff the content_hash matches the body."""
        return self.content_hash == hash_body(self.body)


def build_envelope(
    *,
    from_: str,
    to: str,
    subject: str,
    body: str,
    body_class: str = "text/plain",
) -> Envelope:
    """Build a fresh envelope. message_id, sent_at, content_hash are auto-filled."""
    return Envelope(
        from_=from_,
        to=to,
        subject=subject,
        body=body,
        body_class=body_class,
    )
