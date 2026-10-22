"""Quarantine review : list, show, release, reject, delete.

Release is scoped to the stored envelope, needs an approver and a ticket, re-scans the
message first (never skips R01), forwards it, and is logged to audit.jsonl. A message is
only moved out of quarantine after the downstream server has accepted it."""
import argparse
import json
import logging
import os
import re
import shutil
import smtplib
import time
from pathlib import Path

from mailguard.engine import evaluate

_ID = re.compile(r"[0-9a-f]{32}")
_FIELD = re.compile(r"[\w .@-]{1,64}")
FOLDERS = ("released", "rejected")
log = logging.getLogger(__name__)


class ReleaseRefused(Exception):
    """The re-scan rejected the message; it stays in quarantine."""


def _paths(qdir: Path, mid: str, folder: str | None = None) -> tuple[Path, Path]:
    if not _ID.fullmatch(mid):
        raise ValueError("invalid quarantine id")
    base = Path(qdir) / folder if folder else Path(qdir)
    return base / f"{mid}.eml", base / f"{mid}.json"


def _audit(qdir: Path, **entry) -> None:
    fd = os.open(Path(qdir) / "audit.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **entry}) + "\n")


def _require(approver: str, ticket: str) -> None:
    if not (_FIELD.fullmatch(approver or "") and _FIELD.fullmatch(ticket or "")):
        raise ValueError("approver and ticket are required: letters, digits, space . @ - _ (max 64)")


def _move(qdir: Path, mid: str, folder: str) -> None:
    dest = Path(qdir) / folder
    dest.mkdir(exist_ok=True, mode=0o700)
    for src in _paths(qdir, mid):
        shutil.move(src, dest / src.name)


def list_held(qdir: Path) -> list[dict]:
    qdir = Path(qdir)
    if not qdir.exists():
        return []
    out = []
    for p in sorted(qdir.glob("*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except (ValueError, OSError):
            log.warning("skipping unreadable quarantine record %s", p.name)
    return out


def show(qdir: Path, mid: str) -> dict:
    eml, meta = _paths(qdir, mid)
    return {**json.loads(meta.read_text()), "size": eml.stat().st_size}


def release(qdir: Path, mid: str, downstream: tuple[str, int], approver: str, ticket: str) -> dict:
    _require(approver, ticket)
    eml, meta = _paths(qdir, mid)
    lock = Path(qdir) / f"{mid}.lock"
    try:  # claim the message so two reviewers cannot release it twice
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except FileExistsError:
        raise ReleaseRefused("release already in progress") from None
    try:
        return _release(qdir, mid, eml, meta, downstream, approver, ticket)
    finally:
        lock.unlink(missing_ok=True)


def _release(qdir, mid, eml, meta, downstream, approver, ticket) -> dict:
    record, raw = json.loads(meta.read_text()), eml.read_bytes()
    rescan = evaluate(raw)
    if rescan.verdict == "reject":
        _audit(qdir, action="release-refused", id=mid, approver=approver, ticket=ticket, rule=rescan.deciding_rule)
        raise ReleaseRefused(f"re-scan rejected the message ({rescan.deciding_rule})")
    stamped = f"X-MailGuard-Released: {ticket} by {approver}\r\n".encode() + raw
    with smtplib.SMTP(*downstream, timeout=30) as s:  # raises if downstream is down: message stays held
        s.sendmail(record["mail_from"], record["rcpt_tos"], stamped)
    _move(qdir, mid, "released")
    _audit(qdir, action="release", id=mid, approver=approver, ticket=ticket,
           rescan=rescan.verdict, rule=rescan.deciding_rule)
    return {"id": mid, "forwarded": True, "rescan": rescan.verdict}


def reject(qdir: Path, mid: str, approver: str, ticket: str) -> None:
    _require(approver, ticket)
    eml, meta = _paths(qdir, mid)
    if not (eml.exists() and meta.exists()):
        raise FileNotFoundError(f"no held message {mid}")
    _move(qdir, mid, "rejected")
    _audit(qdir, action="reject", id=mid, approver=approver, ticket=ticket)


def delete(qdir: Path, mid: str, approver: str, ticket: str, folder: str | None = None) -> None:
    _require(approver, ticket)
    if folder is not None and folder not in FOLDERS:
        raise ValueError("unknown folder")
    for p in _paths(qdir, mid, folder):
        p.unlink(missing_ok=True)
    _audit(qdir, action="delete", id=mid, approver=approver, ticket=ticket, folder=folder or "held")


def main() -> None:
    ap = argparse.ArgumentParser(description="MailGuard quarantine review")
    ap.add_argument("--dir", default="quarantine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    for name in ("show", "release", "reject", "delete"):
        p = sub.add_parser(name)
        p.add_argument("id")
        if name != "show":
            p.add_argument("--approver", required=True)
            p.add_argument("--ticket", required=True)
        if name == "release":
            p.add_argument("--downstream", default="127.0.0.1:3025")
    a = ap.parse_args()
    if a.cmd == "list":
        for r in list_held(a.dir):
            names = ", ".join(p["name"] for p in r["parts"])
            print(f"{r['id']}  {r['verdict']:<10} {r['rule']:<4} to {','.join(r['rcpt_tos'])}  [{names}]")
    elif a.cmd == "show":
        print(json.dumps(show(a.dir, a.id), indent=2))
    elif a.cmd == "release":
        host, port = a.downstream.rsplit(":", 1)
        print(json.dumps(release(a.dir, a.id, (host, int(port)), a.approver, a.ticket)))
    elif a.cmd == "reject":
        reject(a.dir, a.id, a.approver, a.ticket)
    else:
        delete(a.dir, a.id, a.approver, a.ticket)


if __name__ == "__main__":
    main()
