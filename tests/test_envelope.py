"""Tests for tibet_cmail.envelope — Light Mode v0.1 shape + hashing."""

from __future__ import annotations

import json
import re

import pytest

from tibet_cmail.envelope import CMAIL_KIND, Envelope, build_envelope, hash_body


def test_hash_body_stable():
    h1 = hash_body("hello world")
    h2 = hash_body("hello world")
    assert h1 == h2
    assert h1.startswith("sha256:")
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", h1)


def test_hash_body_changes_with_content():
    assert hash_body("a") != hash_body("b")


def test_build_envelope_autofills():
    e = build_envelope(
        from_="alice.aint",
        to="bob.aint",
        subject="Re: lunch?",
        body="how about 12:30?",
    )
    assert e.from_ == "alice.aint"
    assert e.to == "bob.aint"
    assert e.subject == "Re: lunch?"
    assert e.body == "how about 12:30?"
    assert e.message_id.startswith("cmail_")
    assert len(e.message_id) > len("cmail_")
    assert e.kind == CMAIL_KIND
    assert e.body_class == "text/plain"
    assert e.content_hash == hash_body("how about 12:30?")
    assert e.sent_at  # ISO timestamp present


def test_envelope_id_unique_per_build():
    e1 = build_envelope(from_="a", to="b", subject="x", body="x")
    e2 = build_envelope(from_="a", to="b", subject="x", body="x")
    assert e1.message_id != e2.message_id


def test_envelope_verify_true_when_intact():
    e = build_envelope(from_="a", to="b", subject="s", body="hello")
    assert e.verify() is True


def test_envelope_verify_false_when_body_tampered():
    e = build_envelope(from_="a", to="b", subject="s", body="hello")
    e.body = "tampered"
    assert e.verify() is False


def test_envelope_roundtrip_json():
    original = build_envelope(
        from_="alice.aint",
        to="bob.aint",
        subject="Réservé",  # non-ASCII to verify utf-8 path
        body="Bonjour 👋",
    )
    js = original.to_json()
    restored = Envelope.from_json(js)
    assert restored.message_id == original.message_id
    assert restored.from_ == original.from_
    assert restored.to == original.to
    assert restored.subject == original.subject
    assert restored.body == original.body
    assert restored.content_hash == original.content_hash
    assert restored.verify() is True


def test_envelope_json_uses_from_not_from_underscore():
    """The wire-format uses `from`, not the Python-safe `from_`."""
    e = build_envelope(from_="a", to="b", subject="s", body="x")
    d = e.to_dict()
    assert "from" in d
    assert "from_" not in d


def test_envelope_json_has_stable_key_order():
    """Top-level keys come in a canonical order so audit-side tooling can pin them."""
    e = build_envelope(from_="a", to="b", subject="s", body="x")
    keys = list(e.to_dict().keys())
    expected = ["kind", "message_id", "from", "to", "subject",
                "body", "body_class", "sent_at", "content_hash"]
    assert keys == expected


def test_from_dict_accepts_minimal_payload():
    """Receivers should be tolerant: missing optional fields take defaults."""
    minimal = {
        "kind": CMAIL_KIND,
        "from": "x.aint",
        "to": "y.aint",
        "body": "hi",
    }
    e = Envelope.from_dict(minimal)
    assert e.from_ == "x.aint"
    assert e.body == "hi"
    assert e.subject == ""
    assert e.body_class == "text/plain"


def test_explicit_message_id_honored():
    """Tests/dev can pin a stable message_id."""
    e = Envelope(
        from_="a",
        to="b",
        subject="s",
        body="x",
        message_id="cmail_test_pinned",
    )
    assert e.message_id == "cmail_test_pinned"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
