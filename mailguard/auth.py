"""Sender authentication: SPF (RFC 7208, pyspf), DKIM (RFC 6376, dkimpy), DMARC (RFC 7489).

DNS goes through a resolver so the same code runs against real DNS (DnsResolver) or a
stub with lab records (StubResolver). Organisational domains come from the Public Suffix
List. Not implemented: the pct= tag (treated as 100) and DMARC reporting (rua/ruf)."""
import re
import threading
from dataclasses import dataclass
from email import message_from_bytes
from email.utils import parseaddr
from functools import cache

import dkim
import spf
from publicsuffixlist import PublicSuffixList

_TAG = re.compile(r"\s*([a-z]+)\s*=\s*([^;]*)")
_SPF_LOCK = threading.Lock()  # pyspf's DNS hook is a module global


class TempDNSError(Exception):
    """DNS lookup failed temporarily (timeout, no nameserver): never treated as 'no record'."""


@cache
def _psl() -> PublicSuffixList:
    return PublicSuffixList()


class StubResolver:
    """Lab DNS: {name: [TXT strings]}. Only TXT is served (SPF ip4/ip6, DKIM keys, DMARC)."""

    def __init__(self, records: dict[str, list[str]]):
        self.records = {k.lower().rstrip("."): v for k, v in records.items()}

    def txt(self, name: str) -> list[str]:
        return self.records.get(name.lower().rstrip("."), [])

    def spf_lookup(self, name, qtype, tcpfallback=True, timeout=30):  # pyspf DNSLookup signature
        if qtype in ("TXT", "SPF"):
            return [((name, "TXT"), [t.encode()]) for t in self.txt(name)]
        return []


class DnsResolver:
    """Real DNS via dnspython; pyspf performs its own lookups."""
    spf_lookup = None

    def txt(self, name: str) -> list[str]:
        import dns.exception
        import dns.resolver
        try:
            ans = dns.resolver.resolve(name, "TXT", lifetime=5)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.DNSException, OSError) as exc:
            raise TempDNSError(name) from exc
        return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]


@dataclass
class AuthResult:
    spf: str
    dkim: str
    dmarc: str
    policy: str
    from_domain: str
    spf_domain: str
    dkim_domain: str

    def header(self, authserv: str) -> str:
        return (f"Authentication-Results: {authserv}; spf={self.spf} smtp.mailfrom={self.spf_domain or 'none'}; "
                f"dkim={self.dkim} header.d={self.dkim_domain or 'none'}; "
                f"dmarc={self.dmarc} (p={self.policy}) header.from={self.from_domain or 'none'}")


def _org(domain: str) -> str:
    domain = domain.lower().rstrip(".")
    return _psl().privatesuffix(domain) or domain


def _aligned(a: str, b: str, strict: bool = False) -> bool:
    if not (a and b):
        return False
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    return a == b if strict else _org(a) == _org(b)


def _spf(ip: str, mail_from: str, helo: str, resolver) -> str:
    if resolver.spf_lookup is None:
        return spf.check2(i=ip, s=mail_from, h=helo)[0]
    with _SPF_LOCK:
        original = spf.DNSLookup
        spf.DNSLookup = resolver.spf_lookup
        try:
            return spf.check2(i=ip, s=mail_from, h=helo)[0]
        finally:
            spf.DNSLookup = original


def _dkim(raw: bytes, resolver) -> tuple[str, str]:
    """Domain is taken from the signature dkimpy actually verified, never parsed separately."""
    if b"dkim-signature:" not in raw[:65536].lower():
        return "none", ""

    def dnsfunc(name, timeout=5):
        records = resolver.txt(name.decode().rstrip("."))
        return records[0].encode() if records else None

    d = dkim.DKIM(raw)
    try:
        ok = d.verify(dnsfunc=dnsfunc)
    except dkim.DKIMException:
        ok = False
    domain = d.domain.decode().lower() if ok and d.domain else ""
    return ("pass" if ok else "fail"), domain


def _dmarc_record(from_domain: str, resolver) -> dict | None:
    """RFC 7489 §6.6.3: the From domain's record, else the organisational domain's (where sp= applies)."""
    org = _org(from_domain)
    for name, is_org in ((f"_dmarc.{from_domain}", False), (f"_dmarc.{org}", True)):
        recs = [{k: v.strip().lower() for k, v in _TAG.findall(r)} for r in resolver.txt(name)]
        recs = [t for t in recs if t.get("v") == "dmarc1"]
        if len(recs) > 1:
            return None  # multiple records: treated as no policy (RFC 7489 §6.6.3)
        if recs:
            tags = recs[0]
            policy = tags.get("sp", tags.get("p", "none")) if is_org and from_domain != org else tags.get("p", "none")
            return {"p": policy, "adkim": tags.get("adkim", "r"), "aspf": tags.get("aspf", "r")}
        if from_domain == org:
            break
    return None


def authenticate(raw: bytes, mail_from: str, ip: str, helo: str, resolver) -> AuthResult:
    froms = message_from_bytes(raw).get_all("From") or []
    from_domain = parseaddr(froms[0])[1].rpartition("@")[2].lower() if len(froms) == 1 else ""
    spf_domain = (mail_from or "").rpartition("@")[2].lower() or helo
    try:
        spf_result = _spf(ip, mail_from or f"postmaster@{helo}", helo, resolver)
        dkim_result, dkim_domain = _dkim(raw, resolver)
        if not from_domain:  # zero, several or unparseable From headers (RFC 7489 §6.6.1)
            return AuthResult(spf_result, dkim_result, "fail", "quarantine", "", spf_domain, dkim_domain)
        rec = _dmarc_record(from_domain, resolver)
    except TempDNSError:
        return AuthResult("temperror", "temperror", "temperror", "none", from_domain, spf_domain, "")
    if rec is None:
        return AuthResult(spf_result, dkim_result, "none", "none", from_domain, spf_domain, dkim_domain)
    passed = (spf_result == "pass" and _aligned(spf_domain, from_domain, rec["aspf"] == "s")) or \
             (dkim_result == "pass" and _aligned(dkim_domain, from_domain, rec["adkim"] == "s"))
    return AuthResult(spf_result, dkim_result, "pass" if passed else "fail", rec["p"], from_domain,
                      spf_domain, dkim_domain)
