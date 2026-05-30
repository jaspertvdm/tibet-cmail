"""
tibet-cmail — command-line interface (Light Mode, v0.1).

Commands:
    tibet-cmail send <to> <subject> <body> --from <agent>
                                          send a cmail via I-Poll (Light Mode)
    tibet-cmail inbox <agent>             list inbound cmails (preview)
    tibet-cmail read <agent> <msg-id>     read one cmail body in full
    tibet-cmail status                    backend status

Routing (mirrors ipoll discipline):
    --local       http://localhost:8000          your local brain_api
    --ainternet   https://api.ainternet.org      primary public hub
    --brein       https://brein.jaspervandemeent.nl  secondary fallback

Light Mode = no encryption. Sealed Mode (v0.2.x) will add TBZ + continuityd routing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

import time

from . import __version__
from .audit import (
    DEFAULT_AUDIT_PATH,
    build_received_event,
    build_sent_event,
    log_event,
)
from .envelope import CMAIL_KIND, Envelope, build_envelope


LOCAL_URL = "http://localhost:8000"
AINTERNET_URL = "https://api.ainternet.org"
BREIN_URL = "https://brein.jaspervandemeent.nl"
DEFAULT_URL = os.environ.get("CMAIL_API_URL", LOCAL_URL)
_USER_AGENT = f"tibet-cmail/{__version__}"


def _is_connection_refused(exc: BaseException) -> bool:
    cause = exc.__cause__ or exc.__context__
    while cause is not None:
        if isinstance(cause, ConnectionRefusedError):
            return True
        cause = cause.__cause__ or cause.__context__
    if isinstance(exc, urllib.error.URLError):
        return isinstance(getattr(exc, "reason", None), ConnectionRefusedError)
    return isinstance(exc, ConnectionRefusedError)


def _explain_unreachable(url: str, exc: BaseException) -> str:
    if _is_connection_refused(exc):
        return (
            f"tibet-cmail: backend at {url} is not running (connection refused).\n"
            f"  - Start a local brain_api on port 8000 (private/fast), or\n"
            f"  - retry with --ainternet for the public hub ({AINTERNET_URL}), or\n"
            f"  - retry with --brein for the secondary fallback ({BREIN_URL}), or\n"
            f"  - set CMAIL_API_URL / use --url <host>:<port>."
        )
    reason = getattr(exc, "reason", exc)
    return f"tibet-cmail: cannot reach {url}: {reason}"


def _get_json(url: str, timeout: float = 5.0) -> dict[str, Any]:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json(url: str, payload: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def cmd_send(args: argparse.Namespace) -> int:
    """Send a cmail via I-Poll PUSH (Light Mode)."""
    envelope = build_envelope(
        from_=args.from_agent,
        to=args.to,
        subject=args.subject,
        body=args.body,
    )
    payload = {
        "from_agent": envelope.from_,
        "to_agent": envelope.to,
        "content": envelope.to_json(),
        "poll_type": "PUSH",
    }
    url = f"{args.url.rstrip('/')}/api/ipoll/push"
    t0 = time.perf_counter()
    try:
        data = _post_json(url, payload, timeout=args.timeout)
    except urllib.error.HTTPError as e:
        print(f"tibet-cmail: send failed: HTTP {e.code}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(_explain_unreachable(args.url, e), file=sys.stderr)
        return 2
    latency_ms = (time.perf_counter() - t0) * 1000.0

    # Emit + log a gateway-event.v1 (cmail.message.sent) audit record.
    audit_path = None
    audit_err = None
    if not args.no_audit:
        try:
            event = build_sent_event(envelope, latency_ms=latency_ms)
            audit_path = log_event(event, args.audit_log)
        except Exception as e:  # never let audit break a send
            audit_err = str(e)

    if args.json:
        print(json.dumps({
            "envelope": envelope.to_dict(),
            "i_poll": data,
            "audit_log": str(audit_path) if audit_path else None,
        }, indent=2, ensure_ascii=False))
        return 0

    poll_id = data.get("id") or data.get("poll_id") or "?"
    print(f"cmail sent: {envelope.message_id}")
    print(f"  from={envelope.from_}  to={envelope.to}")
    print(f"  subject: {envelope.subject}")
    print(f"  content_hash: {envelope.content_hash}")
    print(f"  latency: {latency_ms:.1f}ms")
    print(f"  i-poll envelope: {poll_id}")
    if audit_path:
        print(f"  audit: {audit_path} (gateway-event.v1: cmail.message.sent)")
    elif audit_err:
        print(f"  audit: SKIPPED ({audit_err})")
    return 0


def _is_cmail_envelope(content_str: str) -> bool:
    """Heuristic: True if I-Poll PUSH content looks like a Light Mode cmail."""
    try:
        d = json.loads(content_str)
    except (ValueError, TypeError):
        return False
    return isinstance(d, dict) and d.get("kind") == CMAIL_KIND


def _fetch_polls(args: argparse.Namespace, mark_read: bool) -> tuple[int, list[dict]]:
    url = (
        f"{args.url.rstrip('/')}/api/ipoll/pull/{args.agent}"
        f"?mark_read={'true' if mark_read else 'false'}"
    )
    try:
        data = _get_json(url, timeout=args.timeout)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"tibet-cmail: agent '{args.agent}' not found", file=sys.stderr)
            return 4, []
        if e.code == 401:
            print(
                f"tibet-cmail: inbox-pull requires authentication at this backend (HTTP 401). "
                f"Use --local with a brain_api you control.",
                file=sys.stderr,
            )
            return 5, []
        print(f"tibet-cmail: pull failed: HTTP {e.code}", file=sys.stderr)
        return 1, []
    except urllib.error.URLError as e:
        print(_explain_unreachable(args.url, e), file=sys.stderr)
        return 2, []
    return 0, data.get("polls", [])


def cmd_inbox(args: argparse.Namespace) -> int:
    """List inbound cmails (filters non-cmail I-Polls out)."""
    rc, polls = _fetch_polls(args, mark_read=False)
    if rc != 0:
        return rc
    cmails: list[Envelope] = []
    for p in polls:
        content = p.get("content", "")
        if _is_cmail_envelope(content):
            try:
                cmails.append(Envelope.from_json(content))
            except Exception:
                continue

    # Emit + log a gateway-event.v1 (cmail.message.received) per observed cmail.
    audit_events = 0
    if not args.no_audit and cmails:
        for e in cmails:
            try:
                event = build_received_event(e, recipient=args.agent)
                log_event(event, args.audit_log)
                audit_events += 1
            except Exception:
                pass

    if args.json:
        print(json.dumps([e.to_dict() for e in cmails], indent=2, ensure_ascii=False))
        return 0
    if not cmails:
        non_cmail = len(polls)
        print(f"  (no cmails for {args.agent}; {non_cmail} non-cmail I-Poll(s) skipped)")
        return 0
    print(f"inbox for {args.agent} ({len(cmails)} cmail{'s' if len(cmails) != 1 else ''}):")
    for e in cmails:
        subject = e.subject or "(no subject)"
        if len(subject) > 50:
            subject = subject[:47] + "..."
        print(f"  [{e.message_id}]  from={e.from_:<18}  {subject}")
    if audit_events:
        print(f"  ({audit_events} cmail.message.received audit event(s) logged)")
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    """Read one cmail in full by message_id (uses inbox preview, no mark-read)."""
    rc, polls = _fetch_polls(args, mark_read=False)
    if rc != 0:
        return rc
    for p in polls:
        content = p.get("content", "")
        if not _is_cmail_envelope(content):
            continue
        e = Envelope.from_json(content)
        if e.message_id == args.message_id:
            if args.json:
                print(e.to_json(indent=2))
            else:
                print(f"From:    {e.from_}")
                print(f"To:      {e.to}")
                print(f"Sent:    {e.sent_at}")
                print(f"Subject: {e.subject}")
                print(f"Hash:    {e.content_hash} ({'verified' if e.verify() else 'MISMATCH'})")
                print()
                print(e.body)
            return 0
    print(f"tibet-cmail: no cmail with message_id '{args.message_id}' in {args.agent}'s inbox",
          file=sys.stderr)
    return 4


def cmd_status(args: argparse.Namespace) -> int:
    url = f"{args.url.rstrip('/')}/api/ipoll/status"
    try:
        data = _get_json(url, timeout=args.timeout)
    except urllib.error.URLError as e:
        print(_explain_unreachable(args.url, e), file=sys.stderr)
        return 2
    print(f"tibet-cmail backend: {args.url}")
    print(f"  transport status:  {data.get('status', 'unknown')}")
    print(f"  cmail mode:        Light (I-Poll transport, no seal)")
    print(f"  envelope kind:     {CMAIL_KIND}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tibet-cmail",
        description="Cmail — capsulated email + command hub. Light Mode (I-Poll transport).",
    )
    parser.add_argument("--url", default=DEFAULT_URL,
                        help=f"backend URL (default: {DEFAULT_URL}; env CMAIL_API_URL overrides)")
    parser.add_argument("--local", action="store_true",
                        help=f"shortcut for --url {LOCAL_URL}")
    parser.add_argument("--ainternet", action="store_true",
                        help=f"shortcut for --url {AINTERNET_URL}")
    parser.add_argument("--brein", action="store_true",
                        help=f"shortcut for --url {BREIN_URL}")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="HTTP timeout in seconds (default: 5.0)")
    parser.add_argument("--json", action="store_true",
                        help="emit raw JSON instead of human output")
    parser.add_argument("--no-audit", action="store_true",
                        help="skip the gateway-event.v1 audit-log append")
    parser.add_argument("--audit-log", default=None,
                        help=f"path to the cmail audit-log (default: {DEFAULT_AUDIT_PATH})")
    parser.add_argument("--version", action="version", version=f"tibet-cmail {__version__}")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_send = sub.add_parser("send", help="send a cmail via I-Poll (Light Mode)")
    p_send.add_argument("to", help="recipient .aint agent")
    p_send.add_argument("subject", help="cmail subject line")
    p_send.add_argument("body", help="cmail body (use quotes for multi-word)")
    p_send.add_argument("--from", dest="from_agent", required=True,
                        help="sender agent id")
    p_send.set_defaults(func=cmd_send)

    p_inbox = sub.add_parser("inbox", help="list inbound cmails (preview, no mark-read)")
    p_inbox.add_argument("agent", help="agent name (without .aint suffix)")
    p_inbox.set_defaults(func=cmd_inbox)

    p_read = sub.add_parser("read", help="read one cmail in full by message_id")
    p_read.add_argument("agent", help="recipient agent name")
    p_read.add_argument("message_id", help="cmail message_id (cmail_<hex>)")
    p_read.set_defaults(func=cmd_read)

    p_status = sub.add_parser("status", help="show backend + cmail-mode status")
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "local", False):
        args.url = LOCAL_URL
    elif getattr(args, "ainternet", False):
        args.url = AINTERNET_URL
    elif getattr(args, "brein", False):
        args.url = BREIN_URL
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
