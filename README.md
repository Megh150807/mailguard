# MailGuard

MailGuard is an SMTP gateway that screens email attachments **before they reach a mailbox**. It sits in front of your mail server, looks at what every attachment *really* is (not what it claims to be), applies a written policy, and answers the sending server with the result: delivered, held for review, or refused.

```
 sender ──SMTP──▶ MailGuard ──SMTP──▶ your mail server ──▶ inbox / webmail / mail app
                     │
                     ├─ refused (550)            dangerous attachment, failed DMARC p=reject
                     └─ held in quarantine/      for a reviewer to release or reject
```

Because it works at the SMTP level, every client behind it (webmail, desktop and phone apps) is protected without installing anything on them.

## Contents

- [What it checks](#what-it-checks)
- [Install](#install)
- [Quick start](#quick-start)
- [Running in front of a mail server](#running-in-front-of-a-mail-server)
- [The policy](#the-policy)
- [Reviewing quarantined mail](#reviewing-quarantined-mail)
- [Sender authentication (SPF, DKIM, DMARC)](#sender-authentication-spf-dkim-dmarc)
- [Analysing a file by hand](#analysing-a-file-by-hand)
- [Configuration reference](#configuration-reference)
- [Security model and limits](#security-model-and-limits)
- [Project layout](#project-layout)

## What it checks

| Area | What MailGuard does |
| --- | --- |
| **MIME structure** | Lists every part, including inline ones; holds mail with missing boundaries, duplicate or conflicting headers, invalid base64 or quoted-printable, unknown transfer encodings, or `filename` / `filename*` / `name` disagreements. |
| **True file type** | Identifies files by their first bytes (Windows/Linux/macOS executables, scripts, shortcuts, ZIP/7z/RAR/gzip, Office, PDF, images, text), never by extension or `Content-Type`. |
| **Disguise** | Double extensions (`invoice.pdf.exe`), names that disagree with content, archives hidden inside other files, right-to-left override characters and path tricks in filenames. |
| **Archives** | Opens ZIPs recursively within limits on depth, member count, unpacked size and compression ratio (zip bombs), measured on bytes actually read. Encrypted archives are held. |
| **Office documents** | Reads VBA macro code (oletools `olevba`) and refuses macros that run automatically *and* execute, write or download (`mraptor`); holds other macros, Excel 4 macro sheets and DDE fields. |
| **PDF** | Holds PDFs with JavaScript, launch actions, embedded files, RichMedia or XFA (including `#xx`-escaped names). |
| **Scripts in text files** | YARA rules for encoded PowerShell, Windows script host, download cradles and autorun keys, also after unwrapping base64, PowerShell `-enc`, `[char]` codes and split strings. |
| **Sender authentication** | Optional SPF, DKIM and DMARC; enforces the sender domain's DMARC policy and adds an `Authentication-Results` header. |
| **Evidence for reviewers** | Blocked executables get a static triage report: hashes, format, sections and entropy, imports mapped to capabilities, packer signs, entry-point disassembly and YARA matches. Nothing is ever executed. |

## Install

Requirements: Linux, macOS or Windows (x86-64 or ARM64) and an internet connection for the first install. You do **not** need Python installed: the installer uses [uv](https://docs.astral.sh/uv/) to fetch the pinned Python version and the locked dependencies.

**Linux and macOS**

```bash
git clone https://github.com/Megh150807/mailguard.git
cd mailguard
./install.sh
```

**Windows** (PowerShell)

```powershell
git clone https://github.com/Megh150807/mailguard.git
cd mailguard
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The installer:

1. installs uv if it is missing (it asks first; pass `--yes` / `-Yes` to skip the question),
2. installs Python and the exact dependency versions from `uv.lock`,
3. runs `python -m mailguard.selfcheck`, which checks the policy, the isolated analyzer and a real SMTP round trip, and prints `READY`.

Run the self-check again at any time:

```bash
uv run python -m mailguard.selfcheck
```

## Quick start

Try it on one machine with a throwaway "mail server" that just prints what it receives.

```bash
# Terminal 1 - stand-in for your mail server
uv run python -m aiosmtpd -n -l 127.0.0.1:1026

# Terminal 2 - MailGuard in front of it
uv run python -m mailguard.relay --port 1025 --downstream 127.0.0.1:1026
```

Then send mail to `127.0.0.1:1025` with any SMTP client, for example from Python:

```python
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg["From"], msg["To"], msg["Subject"] = "alice@example.org", "bob@example.org", "test"
msg.set_content("see attached")
msg.add_attachment(b"not really a program", maintype="application",
                   subtype="octet-stream", filename="invoice.pdf.exe")

with smtplib.SMTP("127.0.0.1", 1025) as s:
    s.send_message(msg)   # raises SMTPDataError: 550 5.7.1 Message rejected by policy R05
```

A clean attachment appears in terminal 1; the `.exe` is refused; an encrypted ZIP is accepted with `250 ... held for review` and lands in `./quarantine/`.

## Running in front of a mail server

MailGuard is a store-and-forward relay: it accepts a message, decides, and only then forwards it.

```bash
uv run python -m mailguard.relay \
    --port 1025 \
    --downstream 127.0.0.1:25 \
    --quarantine /var/lib/mailguard/quarantine \
    --auth dns
```

Typical placements:

- **Separate gateway host**: point your domain's MX record (or your upstream filter) at MailGuard, and set `--downstream` to your real mail server.
- **Same host as the mail server**: run your MTA's public listener on port 25 and relay to MailGuard on a local port, then forward back to an internal port (for Postfix, a `content_filter` / re-injection port).

SMTP replies:

| Outcome | Reply | Meaning for the sender |
| --- | --- | --- |
| allow | `250` after the downstream server accepted it | delivered |
| quarantine | `250` after it is stored | accepted, held for review |
| reject | `550 5.7.1` | permanently refused |
| internal error, downstream unreachable, DNS failure | `451 4.x.x` | try again later; nothing is lost |

The relay binds to `127.0.0.1` by design. Inside a container whose port is published only on loopback, `--container` lets it listen on the container's interfaces. For internet-facing use, put it behind an MTA that handles TLS and connection limits; MailGuard itself does not terminate TLS.

## The policy

The policy lives in [`Policy.yaml`](Policy.yaml). Each file in a message is checked against the rules from top to bottom and the first match decides that file; the most severe file decides the message (reject > quarantine > allow).

| Rule | When | Verdict |
| --- | --- | --- |
| R00 | A required check did not finish (parse error, analyzer crash, timeout) | quarantine |
| R01 | Known signature (EICAR test string) | reject |
| R02 | Malformed or contradictory MIME | quarantine |
| R03 | Unsafe filename (path parts, control or bidi characters, empty) | quarantine |
| R04 | True type is an executable, script or shortcut, whatever its name | reject |
| R05 | Dangerous final extension (55 types, including Gmail's published list) | reject |
| R18 | Macro that runs automatically and executes, writes or downloads | reject |
| R06 | Name and true type disagree, or an archive hidden in another file | quarantine |
| R07 | Encrypted archive | quarantine |
| R08 | Over limits (attachment size, archive depth, members, unpacked size, ratio) | quarantine |
| R09 | An archive member is rejected | reject |
| R10 | An archive member is quarantined | quarantine |
| R11 | Any other macro (VBA, Excel 4 sheets, legacy Office, macro extensions) | quarantine |
| R12 | HTML or SVG attachment | quarantine |
| R15 | PDF with active content | quarantine |
| R16 | High-confidence script signature, also after decoding | quarantine |
| R17 | DDE field in an Office document | quarantine |
| R13 | Allow-listed type (`pdf png jpg gif txt csv docx xlsx pptx zip`) whose true type matches | allow |
| R14 | Everything else (default deny) | quarantine |

Principles: judge content not labels; allow-list with default deny; fail closed; every non-allow verdict has a way forward (quarantine review).

You can edit lists and limits (`dangerous_extensions`, `allowlisted_extensions`, `limits`, ...) and the order of rules. A rule's `when:` must name a predicate the engine knows; an unknown predicate stops MailGuard from starting rather than silently ignoring the rule. Use a different policy file with `MAILGUARD_POLICY=/path/to/policy.yaml`.

Script and content signatures are YARA rules in [`mailguard/rules/`](mailguard/rules). Add `.yar` files there; each rule's `meta` sets its `category` and `weight` (20 or more triggers R16).

## Reviewing quarantined mail

Held messages are stored as `<id>.eml` (the original message) and `<id>.json` (verdict, reasons, envelope, static report).

```bash
uv run python -m mailguard.quarantine --dir quarantine list
uv run python -m mailguard.quarantine --dir quarantine show <id>
uv run python -m mailguard.quarantine --dir quarantine release <id> --approver "j.doe" --ticket "SEC-142" --downstream 127.0.0.1:25
uv run python -m mailguard.quarantine --dir quarantine reject  <id> --approver "j.doe" --ticket "SEC-142"
uv run python -m mailguard.quarantine --dir quarantine delete  <id> --approver "j.doe" --ticket "SEC-142"
```

A release re-scans the message first and is refused if it now matches a reject rule; it adds an `X-MailGuard-Released` header, forwards only to the original recipients, and moves the message out of quarantine only after the downstream server accepted it. Every action is appended to `quarantine/audit.jsonl`. Two reviewers cannot release the same message twice.

## Sender authentication (SPF, DKIM, DMARC)

Off by default (a test machine has no real DNS to check against). Enable it with `--auth dns`:

- **SPF** (RFC 7208) checks the connecting IP against the envelope sender's domain.
- **DKIM** (RFC 6376) verifies signatures; the signing domain is taken from the verified signature only.
- **DMARC** (RFC 7489) requires SPF or DKIM to pass *and* align with the visible `From:` domain (organisational domains from the Public Suffix List; `adkim`, `aspf` and `sp` honoured). Messages with no or several `From:` headers fail.

A DMARC failure under the domain's `p=reject` is refused, under `p=quarantine` held. A DNS timeout gives `451` (retry later), never a pass. Delivered mail carries an RFC 8601 `Authentication-Results: mailguard; ...` header; any such header already present on arrival is removed so it cannot be forged.

## Analysing a file by hand

```bash
uv run python -m mailguard.static suspicious.exe          # readable, stage by stage
uv run python -m mailguard.static --json suspicious.exe   # full JSON report
uv run python -m mailguard.office document.docm           # macros, DDE, Excel 4 sheets (JSON)
```

The static report runs nine stages: hashes, identification (PE, ELF, Mach-O), strings, structure and entropy, imports mapped to capabilities, packing, entry-point disassembly, YARA rules, and a heuristic score with reasons. The score is triage evidence for a person, not a malware verdict. Files are read, never run.

## Configuration reference

`python -m mailguard.relay`

| Option | Default | Meaning |
| --- | --- | --- |
| `--port` | `1025` | SMTP port to listen on (`127.0.0.1`) |
| `--downstream` | `127.0.0.1:1026` | `host:port` of the next mail server |
| `--quarantine` | `quarantine` | directory for held messages and the audit log |
| `--auth` | `off` | `dns` enables SPF, DKIM and DMARC |
| `--container` | off | listen on all interfaces of a container (publish the port on loopback only) |

| Environment variable | Meaning |
| --- | --- |
| `MAILGUARD_POLICY` | path to an alternative policy file |

Limits (in `Policy.yaml`): attachment 25 MB, archive depth 3, 100 archive members, 50 MB unpacked, compression ratio 100, analyzer timeout 10 s.

## Security model and limits

- **Fail closed.** If any check cannot finish, the file is held, never delivered.
- **Isolation.** Native binary parsers (LIEF, Capstone) and the Office analyzer run in a separate process with a timeout (plus memory and CPU limits on Linux), so a crash or hang on a hostile file cannot stop the gateway.
- **Logs** contain message hashes, rule ids and attachment names, never message content.
- **Not included:** sandbox detonation, content disarm and reconstruction, antivirus signatures beyond the EICAR test string, TLS termination, and rate limiting. Static checks can be evaded by determined obfuscation; MailGuard reduces risk, it does not guarantee that no malware gets through.
- **False positives** are expected for HTML attachments, macro documents, encrypted archives and archives with unusual member types; that is what the quarantine review is for.

## Project layout

```
mailguard/
  relay.py        SMTP gateway (aiosmtpd)
  engine.py       evaluate(raw_message) -> verdict, SMTP code, reasons
  inventory.py    MIME tree, defects, decoding checks
  filetype.py     true type from content
  policy.py       loads Policy.yaml, applies the rules, isolates analyzers
  signatures.py   YARA-X scanning and the decoding layer
  office.py       macros, DDE, Excel 4 sheets
  static.py       static triage report for executables
  auth.py         SPF, DKIM, DMARC
  quarantine.py   review command line
  selfcheck.py    installation self-check
  rules/          YARA rules
Policy.yaml       the policy
install.sh        setup for Linux and macOS
install.ps1       setup for Windows
.github/workflows/setup.yml   runs both installers on Linux, macOS and Windows
```
