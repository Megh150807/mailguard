"""evaluate(raw) -> Decision: one verdict per message, the worst over all parts (the README)."""
import logging
from dataclasses import dataclass, field
from functools import cache

from mailguard.inventory import inventory
from mailguard.policy import FileVerdict, Policy

SMTP = {"allow": 250, "strip": 250, "quarantine": 250, "reject": 550}
log = logging.getLogger(__name__)


@cache
def _default_policy() -> Policy:
    return Policy.load()


@dataclass
class Decision:
    verdict: str
    deciding_rule: str | None
    smtp_code: int
    parts: list = field(default_factory=list)
    message_defects: list = field(default_factory=list)

    def explain(self) -> str:
        lines = [f"{self.verdict} by {self.deciding_rule} (SMTP {self.smtp_code}) msg_defects={self.message_defects}"]
        for p in self.parts:
            lines.append(f"  {p.filename!r}: {p.verdict} {p.rule} [{p.true_type}] {p.reason}")
            if p.analysis and "level" in p.analysis:
                a = p.analysis
                lines.append(f"    static: {a['format']} {a['arch']} risk={a['level']} ({a['score']}) {a['findings']}")
            lines += [f"    member {m.filename!r}: {m.verdict} {m.rule}" for m in p.members]
        return "\n".join(lines)


def evaluate(raw: bytes, policy: Policy | None = None) -> Decision:
    try:
        policy = policy or _default_policy()
        if len(raw) > policy.limits["max_unpacked_mb"] * 2**20:  # cap before parsing copies it
            return Decision("quarantine", "R08", 250,
                            [FileVerdict("<message>", "quarantine", "R08", "message over size limit")])
        msg_defects, parts = inventory(raw)
        results = []
        for p in parts:
            if p.is_body:
                r = policy.evaluate_body(p.data, p.defects + msg_defects)
                if r:
                    results.append(r)
            else:
                results.append(policy.evaluate_file(p.filename, p.data,
                                                    mime_defect=bool(p.defects or msg_defects)))
        if msg_defects and not results:  # broken structure with no parts recovered
            results.append(FileVerdict("<message>", "quarantine", "R02", "malformed MIME structure"))
    except Exception as exc:  # fail closed: system error, nothing forwarded (RFC 5321 §4.2.5)
        log.exception("evaluate failed")
        return Decision("quarantine", "R00", 451,
                        [FileVerdict("<message>", "quarantine", "R00", f"inspection failed: {type(exc).__name__}")])
    if not results:
        return Decision("allow", None, 250, [], msg_defects)
    worst = policy.worst([r.verdict for r in results])
    decider = next(r for r in results if r.verdict == worst)
    return Decision(worst, decider.rule, SMTP[worst], results, msg_defects)
