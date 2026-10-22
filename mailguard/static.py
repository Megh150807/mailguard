"""Serial reverse-engineering triage pipeline (static only; nothing is ever executed).

Follows the basic-static and advanced-static phases analysts use: each stage reads the
shared context and adds to it; a failing stage is recorded and the rest still run.

    hashes -> identify -> strings -> structure -> imports -> packing
           -> disassemble -> rules -> verdict

PE, ELF and Mach-O are parsed with LIEF, entry points disassembled with Capstone,
and YARA rules (mailguard/rules/*.yar) run with YARA-X. The score is a transparent
heuristic for a human reviewer, not a malware verdict."""
import hashlib
import itertools
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

import capstone
import lief
import yara_x

from mailguard import signatures

lief.logging.disable()

DISASM_BYTES, DISASM_INSNS = 256, 40
SCAN_CAP = 8 * 2**20       # bytes given to the string and rule stages
LIST_CAP = 64              # max sections/libraries kept in a report
RULE_TIMEOUT_S = 5
PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")

# Imports grouped by behaviour: (weight, plain-language capability, APIs).
PE_API = {
    "process-injection": (30, "can inject code into other processes",
                          {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                           "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext"}),
    "downloader": (20, "can download files from the internet",
                   {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW",
                    "WinHttpOpen", "InternetReadFile"}),
    "keylogging": (20, "can record keystrokes",
                   {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"}),
    "persistence": (10, "can make itself start automatically",
                    {"RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW"}),
    "anti-debugging": (10, "checks whether it is being debugged",
                       {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}),
    "encryption": (10, "can encrypt data", {"CryptEncrypt", "BCryptEncrypt"}),
    "execution": (5, "can start other programs",
                  {"ShellExecuteA", "ShellExecuteW", "WinExec", "CreateProcessA", "CreateProcessW"}),
}
UNIX_API = {
    "anti-debugging": (15, "checks whether it is being debugged", {"ptrace"}),
    "execution": (5, "can start other programs", {"execve", "execl", "execvp", "system", "popen"}),
    "networking": (5, "can open network connections", {"socket", "connect"}),
    "dynamic-loading": (5, "loads code at run time", {"dlopen"}),
}
PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1",
                   ".mpress1", ".petite"}

# LIEF architecture name -> (Capstone arch, mode, short family name)
ARCH = {
    "AMD64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64, "x86"),
    "X86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64, "x86"),
    "I386": (capstone.CS_ARCH_X86, capstone.CS_MODE_32, "x86"),
    "X86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32, "x86"),
    "ARM64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, "arm64"),
    "AARCH64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, "arm64"),
    "ARM": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, "arm"),
    "ARMNT": (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB, "arm"),
}


@dataclass
class Report:
    size: int = 0
    hashes: dict = field(default_factory=dict)
    format: str = "unknown"
    arch: str = ""
    entry_point: str = ""
    sections: list[dict] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    strings_sample: list[str] = field(default_factory=list)
    disassembly: list[str] = field(default_factory=list)
    yara_matches: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    score: int = 0
    level: str = "low"
    stages: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["imports"] = d["imports"][:50]
        d["sections"] = d["sections"][:LIST_CAP]
        d["libraries"] = d["libraries"][:LIST_CAP]
        return d


@dataclass
class _Ctx:
    data: bytes
    report: Report
    binary: object = None
    feats: dict = field(default_factory=lambda: {
        "imports": [], "max_entropy": 0.0, "packer_sections": [], "wx_sections": [], "overlay": 0,
        "malformed": False, "unix": False, "entry": [], "yara": []})


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


# ---------------------------------------------------------------- stages
def _hashes(c: _Ctx) -> str:
    c.report.size = len(c.data)
    c.report.hashes = {n: hashlib.new(n, c.data).hexdigest() for n in ("md5", "sha1", "sha256")}
    return f"sha256 {c.report.hashes['sha256'][:16]}..."


_MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")


def _identify(c: _Ctx) -> str:
    if not c.data.startswith(_MAGIC):
        return "not a native executable; string and rule stages only"
    c.binary = lief.parse(c.data)
    if c.binary is None:
        c.feats["malformed"] = True
        return "executable magic, but the header could not be parsed"
    b, r = c.binary, c.report
    if isinstance(b, lief.PE.Binary):
        r.format, r.arch = "PE", b.header.machine.name
        r.entry_point = hex(b.optional_header.imagebase + b.optional_header.addressof_entrypoint)
    elif isinstance(b, lief.ELF.Binary):
        r.format, r.arch, r.entry_point = "ELF", b.header.machine_type.name, hex(b.entrypoint)
        c.feats["unix"] = True
    else:
        r.format, r.arch, r.entry_point = "MachO", b.header.cpu_type.name, hex(b.entrypoint)
        c.feats["unix"] = True
    return f"{r.format} {r.arch}, entry {r.entry_point}"


def _strings(c: _Ctx) -> str:
    it = PRINTABLE.finditer(c.data[:SCAN_CAP])
    c.report.strings_sample = [m.group(0).decode("ascii") for m in itertools.islice(it, 25)]
    more = sum(1 for _ in itertools.islice(it, 100_000))
    return f"{len(c.report.strings_sample) + more} printable strings (first 25 kept, count capped)"


def _structure(c: _Ctx) -> str:
    b = c.binary
    if b is None:
        return "skipped (not parsed)"
    for s in itertools.islice(b.sections, LIST_CAP):
        size = s.size
        code = _is_code(b, s)
        c.report.sections.append({"name": s.name, "size": size, "entropy": round(s.entropy, 2), "code": code})
        if size >= 512 and code:  # packing shows in code; compressed data/debug sections are normal
            c.feats["max_entropy"] = max(c.feats["max_entropy"], s.entropy)
        if s.name.lower() in PACKER_SECTIONS:
            c.feats["packer_sections"].append(s.name)
    if isinstance(b, lief.PE.Binary):
        ch = lief.PE.Section.CHARACTERISTICS
        c.feats["wx_sections"] = [s.name for s in b.sections
                                  if s.has_characteristic(ch.MEM_WRITE) and s.has_characteristic(ch.MEM_EXECUTE)]
        c.feats["overlay"] = len(b.overlay)
    return f"{len(c.report.sections)} sections, max code entropy {c.feats['max_entropy']:.2f}"


def _is_code(b, s) -> bool:
    if isinstance(b, lief.PE.Binary):
        return s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
    if isinstance(b, lief.ELF.Binary):
        return s.has(lief.ELF.Section.FLAGS.EXECINSTR)
    return getattr(s, "segment_name", "") == "__TEXT"  # Mach-O


def _imports(c: _Ctx) -> str:
    b = c.binary
    if b is None:
        return "skipped (not parsed)"
    if isinstance(b, lief.PE.Binary):
        c.report.libraries = [i.name for i in b.imports]
        c.report.imports = [e.name for i in b.imports for e in i.entries if e.name]
    else:
        c.report.libraries = [lib if isinstance(lib, str) else lib.name for lib in b.libraries]
        c.report.imports = [f.name for f in b.imported_functions]
    c.feats["imports"] = c.report.imports
    c.report.capabilities = capabilities(c.report.imports, c.feats["unix"])
    return f"{len(c.report.imports)} imports from {len(c.report.libraries)} libraries; " \
           f"{len(c.report.capabilities)} capabilities"


def _packing(c: _Ctx) -> str:
    f = c.feats
    if f["packer_sections"]:
        return f"packer sections {f['packer_sections']}"
    return "high entropy, likely packed" if f["max_entropy"] > 7.2 else "no packing signs"


def _disassemble(c: _Ctx) -> str:
    b, r = c.binary, c.report
    if b is None or r.arch not in ARCH:
        return "skipped (no parsed entry point or unsupported architecture)"
    arch, mode, family = ARCH[r.arch]
    ep = int(r.entry_point, 16)
    code = bytes(b.get_content_from_virtual_address(ep, DISASM_BYTES))
    md = capstone.Cs(arch, mode)
    r.disassembly = [f"{i.address:#x} {i.mnemonic} {i.op_str}".rstrip()
                     for i in list(md.disasm(code, ep))[:DISASM_INSNS]]
    c.feats["entry"] = entry_anomalies(code, family)
    if isinstance(b, lief.PE.Binary):
        sec = b.section_from_rva(b.optional_header.addressof_entrypoint)
        if sec is not None and sec.name in c.feats["wx_sections"]:
            c.feats["entry"].append(f"entry point in writable+executable section {sec.name}")
        elif sec is None:
            c.feats["entry"].append("entry point outside every section")
    return f"{len(r.disassembly)} instructions at entry; {len(c.feats['entry'])} anomalies"


def _rules(c: _Ctx) -> str:
    scanner = yara_x.Scanner(signatures.compiled())
    scanner.set_timeout(RULE_TIMEOUT_S)
    results = scanner.scan(c.data[:SCAN_CAP])
    for m in results.matching_rules:
        meta = dict(m.metadata)
        sample = ""
        for p in m.patterns:
            for match in p.matches:
                sample = c.data[match.offset: match.offset + min(match.length, 80)].decode("latin-1")
                break
            if sample:
                break
        c.report.yara_matches.append(m.identifier)
        c.feats["yara"].append((meta.get("category", m.identifier), int(meta.get("weight", 0)),
                                sample or meta.get("description", "")))
    return f"{len(c.report.yara_matches)} rules matched"


def _verdict(c: _Ctx) -> str:
    r = c.report
    r.score, r.findings = score(c.feats)
    r.level = "high" if r.score >= 50 else "medium" if r.score >= 20 else "low"
    return f"risk {r.level} ({r.score}/100)"


STAGES = [("hashes", _hashes), ("identify", _identify), ("strings", _strings), ("structure", _structure),
          ("imports", _imports), ("packing", _packing), ("disassemble", _disassemble), ("rules", _rules),
          ("verdict", _verdict)]
STAGE_NAMES = [n for n, _ in STAGES]


# ---------------------------------------------------------------- helpers
def capabilities(imports: list[str], unix: bool) -> list[str]:
    have = set(imports)
    return [desc for _, desc, apis in (UNIX_API if unix else PE_API).values() if have & apis]


def entry_anomalies(code: bytes, family: str) -> list[str]:
    """Byte patterns at the entry point that analysts treat as red flags (x86 only)."""
    if family != "x86":
        return []
    out = []
    if code[:1] == b"\x60":
        out.append("pushad at entry (typical of packers such as UPX)")
    i = code.find(b"\xe8\x00\x00\x00\x00")
    if 0 <= i < 32 and 0x58 <= code[i + 5] <= 0x5F:
        out.append("getpc: call $+5 / pop (position-independent shellcode)")
    return out


def score(feats: dict) -> tuple[int, list[str]]:
    total, findings = 0, []
    if feats.get("malformed"):
        total += 30
        findings.append("malformed: malformed executable header (parser could not read it)")
    imports = set(feats.get("imports", []))
    for cat, (weight, _, apis) in (UNIX_API if feats.get("unix") else PE_API).items():
        hit = sorted(imports & apis)
        if hit:
            total += weight
            findings.append(f"{cat}: imports {', '.join(hit)}")
    yara_cats = {cat for cat, _, _ in feats.get("yara", [])}
    if feats.get("packer_sections"):
        total += 25
        findings.append(f"packed: packer section names {feats['packer_sections']}")
    elif feats.get("max_entropy", 0) > 7.2 and "packed" not in yara_cats:
        total += 25
        findings.append(f"packed: section entropy {feats['max_entropy']:.2f} > 7.2 (compressed/encrypted code)")
    if feats.get("wx_sections"):
        total += 15
        findings.append(f"wx-section: writable and executable {feats['wx_sections']}")
    if feats.get("overlay"):
        total += 10
        findings.append(f"overlay: {feats['overlay']} bytes appended after the image")
    for note in feats.get("entry", []):
        total += 15
        findings.append(f"entry-point: {note}")
    for cat, weight, sample in feats.get("yara", []):
        total += weight
        findings.append(f"{cat}: {sample!r}")
    return min(total, 100), findings


# ---------------------------------------------------------------- API
def analyze(data: bytes) -> Report:
    c = _Ctx(data, Report())
    for name, fn in STAGES:
        try:
            c.report.stages.append({"stage": name, "ok": True, "summary": fn(c)})
        except Exception as exc:  # noqa: BLE001 -- one broken stage must not hide the others
            c.report.stages.append({"stage": name, "ok": False, "summary": f"error: {type(exc).__name__}"})
    return c.report


def summary(r: Report) -> str:
    lines = [f"{'#':>2} {'stage':<12} result"]
    lines += [f"{i:>2} {s['stage']:<12} {'' if s['ok'] else 'FAILED '}{s['summary']}"
              for i, s in enumerate(r.stages, 1)]
    if r.capabilities:
        lines.append("capabilities: " + "; ".join(r.capabilities))
    if r.disassembly:
        lines.append("entry point:")
        lines += [f"   {line}" for line in r.disassembly[:8]]
    lines.append(f"findings ({r.level}, {r.score}/100):")
    lines += [f" - {f}" for f in r.findings] or [" - none"]
    return "\n".join(lines)


def main() -> None:
    import argparse
    import json
    ap = argparse.ArgumentParser(description="MailGuard static RE triage (never executes the file)")
    ap.add_argument("files", nargs="+", help="paths, or - to read one file from stdin")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    a = ap.parse_args()
    for path in a.files:
        data = sys.stdin.buffer.read(64 * 2**20) if path == "-" else Path(path).read_bytes()[: 64 * 2**20]
        r = analyze(data)
        print(json.dumps({"file": path, **r.as_dict()}, indent=2) if a.json else f"== {path}\n{summary(r)}\n")


if __name__ == "__main__":
    main()
