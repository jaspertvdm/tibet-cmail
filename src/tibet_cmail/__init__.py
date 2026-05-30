"""
tibet-cmail — capsulated email + command hub for HumoticaOS.

Light Mode (v0.1.x):
    Transport:    I-Poll PUSH (over brain_api at localhost:8000 / api.ainternet.org)
    Envelope:     JSON with from/to/subject/body/sent_at/message_id/content_hash
    Evidence:     cap-bus gateway-event.v1 (intent=cmail.message.sent/received)

Sealed Mode (v0.2.x — future):
    Add TBZ-pack + tibet-continuityd inbox routing + SAM-binding for non-AI recipients.

Three pillars (mirrors `cmail-as-hub` anchor doc):
    INBOX    — read inbound cmails
    COMPOSE  — write + send
    AUDIT    — open trace via cap-bus events

Public API:
    from tibet_cmail.envelope import Envelope, build_envelope, hash_body
    from tibet_cmail.cli import main as cli_main
"""

__version__ = "0.1.0"

from .envelope import Envelope, build_envelope, hash_body

__all__ = ["Envelope", "build_envelope", "hash_body", "__version__"]
