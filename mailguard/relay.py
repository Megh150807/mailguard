"""MailGuard SMTP relay: the store-and-forward mail gateway of textbook §9.1.1 (Fig. 9.1),
with the policy engine in the DATA step. Localhost only.

    sender --SMTP--> relay (evaluate) --SMTP--> downstream server
                       '-> quarantine/<id>.eml + <id>.json
"""
import argparse
import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import smtplib
import time
import uuid
from pathlib import Path

from aiosmtpd.controller import Controller

from mailguard.auth import authenticate
from mailguard.engine import evaluate

log = logging.getLogger(__name__)


AUTHSERV = "mailguard"
_OWN = re.compile(rb"^(x-mailguard-released\s*:|authentication-results\s*:\s*" + AUTHSERV.encode() + rb"\b)", re.IGNORECASE)


def strip_own_headers(raw: bytes) -> bytes:
    """Drop inbound headers that claim to be ours (RFC 8601 §5), including continuation lines."""
    end = raw.find(b"\r\n\r\n")
    if end < 0:
        return raw
    out, skipping = [], False
    for line in raw[:end].split(b"\r\n"):
        if line[:1] in (b" ", b"\t"):
            if not skipping:
                out.append(line)
            continue
        skipping = bool(_OWN.match(line))
        if not skipping:
            out.append(line)
    return b"\r\n".join(out) + raw[end:]


def peer_ip(session) -> str:
    return session.peer[0] if session.peer else "127.0.0.1"


class MailGuardHandler:
    def __init__(self, downstream: tuple[str, int], quarantine_dir: Path, resolver=None):
        self.downstream = downstream
        self.quarantine_dir = Path(quarantine_dir)
        self.resolver = resolver  # None = sender authentication off (e.g. a lab without DNS)

    async def handle_DATA(self, server, session, envelope) -> str:
        raw = strip_own_headers(envelope.original_content or envelope.content)
        start = time.perf_counter()
        auth = None
        if self.resolver is not None:  # DNS and scanning run in worker threads: one slow sender can't stall others
            auth = await asyncio.to_thread(authenticate, raw, envelope.mail_from, peer_ip(session),
                                           session.host_name or "", self.resolver)
            if auth.dmarc == "temperror":
                return "451 4.7.0 Sender authentication temporarily unavailable; try again later"
        d = await asyncio.to_thread(evaluate, raw)
        verdict, rule = d.verdict, d.deciding_rule
        if auth and auth.dmarc == "fail" and auth.policy in ("reject", "quarantine"):
            order = ["allow", "strip", "quarantine", "reject"]
            if order.index(auth.policy) > order.index(verdict):
                verdict, rule = auth.policy, "DMARC"
        record = {
            "id": uuid.uuid4().hex, "sha256": hashlib.sha256(raw).hexdigest(),
            "verdict": verdict, "rule": rule,
            **({"auth": {"spf": auth.spf, "dkim": auth.dkim, "dmarc": auth.dmarc, "p": auth.policy}} if auth else {}),
            "parts": [{"name": p.filename, "verdict": p.verdict, "rule": p.rule,
                       **({"static": p.analysis} if p.analysis else {})} for p in d.parts],
            "elapsed_ms": round((time.perf_counter() - start) * 1000, 2),
        }
        log.info("verdict %s", json.dumps(record))  # hashes and names only, never content
        if d.smtp_code == 451:
            return "451 4.3.0 Inspection failed; try again later"
        if verdict == "reject":
            return f"550 5.7.1 Message rejected by policy {rule}"
        if verdict == "quarantine":
            try:  # envelope is needed for a later release; kept in the record, never in the log
                self._store({**record, "mail_from": envelope.mail_from, "rcpt_tos": list(envelope.rcpt_tos)}, raw)
            except OSError:
                log.exception("quarantine write failed")
                return "451 4.3.0 Could not store message; try again later"
            return f"250 2.0.0 Accepted and held for review ({rule})"
        if auth:  # RFC 8601 header, added on top so existing DKIM signatures stay valid
            raw = (auth.header(AUTHSERV) + "\r\n").encode() + raw
        try:  # allow: forward first, and only then accept responsibility (RFC 5321 §4.2.5)
            await asyncio.to_thread(self._forward, envelope.mail_from, envelope.rcpt_tos, raw)
        except (OSError, smtplib.SMTPException):
            log.exception("forward failed")
            return "451 4.4.1 Downstream server unavailable; try again later"
        return "250 2.0.0 Delivered"

    def _forward(self, mail_from, rcpt_tos, raw: bytes) -> None:
        with smtplib.SMTP(*self.downstream, timeout=30) as s:
            s.sendmail(mail_from, rcpt_tos, raw)

    def _store(self, record: dict, raw: bytes) -> None:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.quarantine_dir / f"{record['id']}.eml").write_bytes(raw)
        (self.quarantine_dir / f"{record['id']}.json").write_text(json.dumps(record, indent=2))


def start_relay(host: str, port: int, downstream: tuple[str, int], quarantine_dir: Path,
                in_container: bool = False, resolver=None) -> Controller:
    """Loopback only, unless in_container: inside a pod the network namespace is private and
    the host publishes the port on 127.0.0.1 only, so listening on the pod's interfaces is safe."""
    if not ipaddress.ip_address(host).is_loopback and not in_container:
        raise ValueError("MailGuard is a lab tool: bind to a loopback address only")
    ctl = Controller(MailGuardHandler(downstream, quarantine_dir, resolver), hostname=host, port=port,
                     data_size_limit=60 * 2**20)
    ctl.start()
    return ctl


def main() -> None:
    ap = argparse.ArgumentParser(description="MailGuard localhost SMTP relay")
    ap.add_argument("--port", type=int, default=1025)
    ap.add_argument("--downstream", default="127.0.0.1:1026", help="host:port of the next mail server")
    ap.add_argument("--quarantine", default="quarantine")
    ap.add_argument("--auth", choices=["off", "dns"], default="off",
                    help="sender authentication (SPF/DKIM/DMARC) against real DNS; off in the lab")
    ap.add_argument("--container", action="store_true",
                    help="listen on all pod interfaces (only inside a container whose port is published on 127.0.0.1)")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    host, port = a.downstream.rsplit(":", 1)
    bind = "0.0.0.0" if a.container else "127.0.0.1"
    resolver = None
    if a.auth == "dns":
        from mailguard.auth import DnsResolver
        resolver = DnsResolver()
    ctl = start_relay(bind, a.port, (host, int(port)), Path(a.quarantine), in_container=a.container,
                      resolver=resolver)
    print(f"MailGuard on {bind}:{a.port} -> {a.downstream}  (Ctrl+C to stop)", flush=True)
    try:
        asyncio.run(asyncio.Event().wait())
    except KeyboardInterrupt:
        ctl.stop()


if __name__ == "__main__":
    main()
