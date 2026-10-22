"""Installation self-check: `python -m mailguard.selfcheck`. Exit code 0 = ready.

Uses only harmless data (no malware test strings, so antivirus does not interfere)."""
import platform
import smtplib
import socket
import sys
import tempfile
from email.message import EmailMessage
from pathlib import Path


def _mail(name: str, data: bytes) -> bytes:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "selfcheck@example.org", "you@example.org", "MailGuard self-check"
    m.set_content("self-check")
    m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    from email import policy as email_policy
    return m.as_bytes(policy=email_policy.SMTP)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    from aiosmtpd.controller import Controller

    from mailguard.engine import evaluate
    from mailguard.policy import find_policy, run_isolated
    from mailguard.relay import start_relay

    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}{' - ' + detail if detail else ''}")

    print(f"MailGuard self-check on {platform.system()} {platform.machine()}, Python {platform.python_version()}")
    check("policy file", find_policy().exists(), str(find_policy()))
    clean = evaluate(_mail("notes.txt", b"hello\n"))
    check("clean text is delivered", clean.verdict == "allow", f"{clean.verdict} {clean.deciding_rule}")
    exe = evaluate(_mail("invoice.pdf.exe", b"not a program"))
    check("double extension is refused", exe.verdict == "reject", f"{exe.verdict} {exe.deciding_rule}")
    iso = run_isolated(b"plain text", argv=[sys.executable, "-m", "mailguard.static", "--json", "-"])
    check("isolated analyzer runs", "hashes" in iso, iso.get("error", "static report produced"))

    inbox = []

    class Sink:
        async def handle_DATA(self, server, session, envelope):
            inbox.append(envelope.content)
            return "250 OK"

    sink_port, relay_port = _free_port(), _free_port()
    sink = Controller(Sink(), hostname="127.0.0.1", port=sink_port)
    sink.start()
    relay = start_relay("127.0.0.1", relay_port, ("127.0.0.1", sink_port), Path(tempfile.mkdtemp()))
    try:
        with smtplib.SMTP("127.0.0.1", relay_port, timeout=30) as s:
            s.sendmail("selfcheck@example.org", ["you@example.org"], _mail("notes.txt", b"hello\n"))
        check("SMTP relay forwards clean mail", len(inbox) == 1)
        try:
            with smtplib.SMTP("127.0.0.1", relay_port, timeout=30) as s:
                s.sendmail("selfcheck@example.org", ["you@example.org"], _mail("setup.exe", b"x"))
            check("SMTP relay refuses blocked mail", False, "was accepted")
        except smtplib.SMTPDataError as e:
            check("SMTP relay refuses blocked mail", e.smtp_code == 550, f"SMTP {e.smtp_code}")
    finally:
        relay.stop()
        sink.stop()

    ok = all(checks)
    print("READY" if ok else "NOT READY: see failures above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
