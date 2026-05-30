# tibet-cmail

**Cmail — capsulated email + command hub for HumoticaOS.**

Cmail turns AInternet into a mailbox: human-readable messages that carry sealed
intent, provenance, and consent across `.aint` agents. Light Mode v0.1 ships
today; Sealed Mode comes in 0.2.x.

[![PyPI](https://img.shields.io/pypi/v/tibet-cmail)](https://pypi.org/project/tibet-cmail/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Quick start

```bash
pip install tibet-cmail

# send a cmail through the local brain_api
tibet-cmail send bob.aint "lunch?" "12:30 at the usual" --from alice

# or via the public AInternet hub
tibet-cmail --ainternet send bob.aint "lunch?" "12:30" --from alice

# read what landed in your inbox
tibet-cmail inbox alice
tibet-cmail read alice cmail_1feab795c68c4674
```

## Why cmail?

`ainternet` already gives `.aint` agents the ability to message each other via
**I-Poll**. `tibet-cmail` adds the human surface on top:

- **structured envelopes** — `from`, `to`, `subject`, `body`, `content_hash`
- **identity-anchored** — sender and recipient are `.aint` addresses
- **auditable** — every message ID can be cross-referenced against a
  `gateway-event.v1` record on `tibet-cap-bus`
- **routable** — same `--local` / `--ainternet` / `--brein` shortcuts as
  `ipoll`, so you can talk privately to your own brain or publicly to the
  AInternet hub

Cmail is to AInternet what **email** is to the public Internet: a daily-use
shape on top of the protocol layer.

## Light Mode (v0.1)

```text
compose envelope ─→ I-Poll PUSH ─→ recipient.aint inbox
                                          │
                                          └→ tibet-cmail inbox  →  list
                                          └→ tibet-cmail read   →  full body
```

- Transport: I-Poll (the AInternet messaging protocol).
- Envelope: JSON with stable key order, sha256 `content_hash`, `cmail.message.v1` kind.
- Backend: `localhost:8000` (default), `api.ainternet.org` (`--ainternet`),
  or `brein.jaspervandemeent.nl` (`--brein`).
- No encryption — Light Mode is for friction-free first use; Sealed Mode v0.2.x
  will add TBZ + tibet-continuityd routing for confidentiality.

## Sealed Mode (v0.2.x — coming)

```text
compose envelope ─→ tbz pack ─→ /var/lib/tibet/inbox  ─→ tibet-continuityd
                                                              │
                                                              └→ trust-verdict
                                                              └→ I-Poll notify
                                                              └→ cmail inbox
```

Sealed Mode adds:

- TBZ packing (`tibet-zip-cli`) with AES-256-GCM.
- `tibet-continuityd` arrival + verify_fork on the recipient side.
- SAM-binding for human (non-AI) recipients.
- Sealed audit record in `tibet-trail`.

## CLI reference

| Command | What it does |
|---|---|
| `tibet-cmail send <to> <subject> <body> --from <agent>` | Send a cmail (Light Mode). |
| `tibet-cmail inbox <agent>` | Preview inbound cmails (no mark-read). |
| `tibet-cmail read <agent> <message-id>` | Print one cmail in full + verify content_hash. |
| `tibet-cmail status` | Backend status + cmail mode + envelope kind. |

Global flags: `--local`, `--ainternet`, `--brein`, `--url <host>:<port>`,
`--timeout`, `--json`. The `CMAIL_API_URL` env var overrides `--url`.

## Envelope shape (v1)

```json
{
  "kind": "cmail.message.v1",
  "message_id": "cmail_<uuid4-hex16>",
  "from": "alice.aint",
  "to": "bob.aint",
  "subject": "Re: lunch?",
  "body": "12:30 at the usual",
  "body_class": "text/plain",
  "sent_at": "2026-05-30T08:00:00+00:00",
  "content_hash": "sha256:..."
}
```

`tibet-cmail inbox` filters incoming I-Polls by `kind == cmail.message.v1`, so
the cmail surface stays separate from generic agent-to-agent I-Polls.

## Stack position

Layer in the Humotica stack:

- Group: **agentic** (operator + agent inbox surface)
- Bootstrap: I-Poll transport via [`ainternet`](https://pypi.org/project/ainternet/) +
  [`ipoll`](https://pypi.org/project/ipoll/) `0.2.5+`.
- Audit trail: [`tibet-cap-bus`](https://pypi.org/project/tibet-cap-bus/) `0.1.3+`
  carries `cmail.message.sent` / `cmail.message.received` as
  `gateway-event.v1` records.
- Sealed Mode adds: [`tibet-zip-cli`](https://crates.io/crates/tibet-zip-cli) +
  [`tibet-continuityd`](https://pypi.org/project/tibet-continuityd/) `0.6.16+`.

See `STACK.md` in the Humotica org for the full canonical package map.

## License

MIT — see [`LICENSE`](./LICENSE).

## Credits

Built by **Jasper van de Meent** + **Root AI (Claude)**, with design input from
Codex (cmail-osapi-daemon-architecture, cmail-as-hub).

Part of [HumoticaOS](https://humotica.com). One love, one fAmIly. 💙
