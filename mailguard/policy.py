"""Loads Policy.yaml and decides one file. Rules are first-match, in YAML order;
each YAML `when` string must map to a predicate below, or loading fails."""
import io
import logging
import re
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mailguard import signatures
from mailguard.filetype import detect, has_embedded_archive, ooxml_has_vba


def find_policy() -> Path:
    """$MAILGUARD_POLICY, else Policy.yaml next to the package (release layout) or one level up (dev layout)."""
    import os
    if os.environ.get("MAILGUARD_POLICY"):
        return Path(os.environ["MAILGUARD_POLICY"])
    here = Path(__file__).resolve()
    for root in (here.parents[1], here.parents[2]):
        if (root / "Policy.yaml").exists():
            return root / "Policy.yaml"
    raise FileNotFoundError("Policy.yaml not found; set MAILGUARD_POLICY")


DEFAULT_POLICY = find_policy()
EICAR = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
log = logging.getLogger(__name__)


@dataclass
class FileVerdict:
    filename: str
    verdict: str
    rule: str
    reason: str
    true_type: str = ""
    members: list = field(default_factory=list)
    analysis: dict | None = None  # static-analysis report for blocked executables/scripts


@dataclass
class Facts:
    filename: str
    ext: str
    true_type: str = "unknown"
    cls: str = "unknown"
    mime_defect: bool = False
    incomplete: bool = False
    eicar: bool = False
    unsafe_name: bool = False
    embedded_archive: bool = False
    vba: bool = False
    encrypted: bool = False
    exceeds: bool = False
    worst_member: str = "allow"
    members: list = field(default_factory=list)
    pdf_active: list = field(default_factory=list)
    office: dict = field(default_factory=dict)
    script_hits: list = field(default_factory=list)


# Active-content names counted by pdfid; '#xx' escapes are decoded first (/J#61vaScript).
# /OpenAction and /AA alone are normal (open at a page, set zoom): they only matter as the
# trigger for a script or launch, which these names already catch (benign-file measurement).
_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|EmbeddedFile|RichMedia|XFA)(?![A-Za-z])")
_PDF_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")


def pdf_active_content(data: bytes) -> list[str]:
    decoded = _PDF_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), data[: 8 * 2**20])
    return sorted({m.group(1).decode() for m in _PDF_ACTIVE.finditer(decoded)})


def extension(filename: str) -> str:
    """Final extension decides (invoice.pdf.exe -> exe)."""
    name = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def unsafe_filename(name: str, archive_member: bool = False) -> bool:
    """Display name only, never a path (RFC 2183 §5). Archive members may use folders,
    but never '..', absolute paths or drive letters (zip slip)."""
    if not name or any(unicodedata.category(c) in ("Cc", "Cf") for c in name):
        return True  # control chars and bidi overrides such as U+202E
    segments = name.replace("\\", "/").split("/")
    if ".." in segments:
        return True
    if archive_member:
        return name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":")
    return len(segments) > 1


class Policy:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.order = cfg["verdict_order"]
        self.limits = cfg["limits"]
        self.file_types = [(n, [bytes.fromhex(m) for m in t["magic"]], t["class"])
                           for n, t in cfg["file_types"].items()]
        self.family = cfg.get("extension_family", {})
        lists = {k: set(cfg[k]) for k in
                 ("dangerous_extensions", "macro_extensions", "html_like_extensions", "allowlisted_extensions")}
        fam = lambda f: self.family.get(f.ext)
        preds = {
            "inspection_incomplete": lambda f: f.incomplete,
            "eicar_signature_found": lambda f: f.eicar,
            "mime_defect": lambda f: f.mime_defect,
            "unsafe_filename": lambda f: f.unsafe_name,
            "true_type_class in [executable, script, shortcut]": lambda f: f.cls in ("executable", "script", "shortcut"),
            "extension in dangerous_extensions": lambda f: f.ext in lists["dangerous_extensions"],
            "extension_family != true_type_class or has_embedded_archive":
                lambda f: (fam(f) is not None and fam(f) != f.cls) or f.embedded_archive,
            "archive_encrypted": lambda f: f.encrypted,
            "archive_exceeds_limits": lambda f: f.exceeds,
            "worst_archive_member_verdict == reject": lambda f: f.worst_member == "reject",
            "worst_archive_member_verdict == quarantine": lambda f: f.worst_member == "quarantine",
            "extension in macro_extensions or ooxml_has_vba_project or true_type_class == legacy_office":
                lambda f: f.ext in lists["macro_extensions"] or f.vba or f.cls == "legacy_office",
            "extension in html_like_extensions": lambda f: f.ext in lists["html_like_extensions"],
            "pdf_active_content": lambda f: bool(f.pdf_active),
            "office_macro_suspicious": lambda f: bool(f.office.get("suspicious")),
            "office_dde_field": lambda f: bool(f.office.get("dde")),
            "high_confidence_script_signature": lambda f: bool(f.script_hits),
            "extension in allowlisted_extensions and extension_family == true_type_class":
                lambda f: f.ext in lists["allowlisted_extensions"] and fam(f) == f.cls,
            "always": lambda f: True,
        }
        if not cfg["rules"] or cfg["rules"][-1]["when"] != "always":
            raise ValueError("policy must end with a catch-all ('when: always') rule")
        self.rules = []
        for r in cfg["rules"]:
            if r["when"] not in preds or r["action"] not in self.order:
                raise ValueError(f"policy rule {r['id']}: unknown 'when' or action")
            self.rules.append((r["id"], preds[r["when"]], r["action"], r.get("reason", "")))

    @classmethod
    def load(cls, path=DEFAULT_POLICY):
        with open(path, encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    def worst(self, verdicts) -> str:
        return max(verdicts, key=self.order.index, default=self.order[0])

    def evaluate_body(self, data: bytes, defects: list[str]) -> FileVerdict | None:
        """Message text: never an attachment, but still signature-scanned and defect-checked."""
        if EICAR in data:
            return FileVerdict("<body>", "reject", "R01", "signature found in message body")
        if defects:
            return FileVerdict("<body>", "quarantine", "R02", f"malformed body part: {defects}")
        return None

    def evaluate_file(self, filename: str, data: bytes, mime_defect: bool = False, depth: int = 0,
                      budget: dict | None = None) -> FileVerdict:
        budget = budget if budget is not None else {"members": 0, "bytes": 0}
        f = Facts(filename=filename, ext=extension(filename), mime_defect=mime_defect)
        reason_extra = ""
        try:
            f.unsafe_name = unsafe_filename(filename, archive_member=depth > 0)
            f.eicar = EICAR in data
            f.true_type, f.cls = detect(data, self.file_types)
            f.embedded_archive = has_embedded_archive(data, f.cls)
            if f.cls in ("office_ooxml", "legacy_office"):
                f.office = _office_report(data)
                if "error" in f.office or f.office.get("incomplete"):
                    f.incomplete = True  # analyzer crashed, timed out or could not read everything (R00)
                elif f.office.get("xlm"):
                    f.vba = True  # Excel 4 macro sheet counts as a macro (R11)
            if f.true_type == "pdf":
                f.pdf_active = pdf_active_content(data)
            hits, decoded_all = signatures.scan_layers_checked(data)
            f.script_hits = [h for h in hits if h.weight >= signatures.HIGH_CONFIDENCE and h.category != "signature"]
            if not decoded_all:
                f.incomplete = True  # decoding budget exhausted (decoy flooding): fail closed
            if len(data) > self.limits["max_attachment_mb"] * 2**20:
                f.exceeds = True  # check before any expensive inspection
            elif f.cls == "office_ooxml":
                f.vba = ooxml_has_vba(data)
                self._scan_ooxml_members(f, data)
            elif f.true_type == "zip":
                self._inspect_zip(f, data, depth, budget)
            elif f.cls == "archive":
                f.incomplete = True  # 7z/rar/gzip: cannot inspect, so fail closed
        except Exception as exc:  # any inspection failure is R00, never allow
            log.warning("inspection failed for %r: %s", filename, exc, exc_info=True)
            f.incomplete = True
            reason_extra = f" ({type(exc).__name__})"
        for rule_id, pred, action, reason in self.rules:
            if pred(f):
                detail = ""
                if rule_id == "R15":
                    detail = f" [{', '.join(f.pdf_active)}]"
                elif rule_id == "R18":
                    detail = f" [autoexec: {', '.join(f.office.get('autoexec', [])) or '-'}]"
                elif rule_id == "R17":
                    detail = f" [{'; '.join(f.office['dde'][:2])}]"
                elif rule_id == "R16":
                    detail = f" [{', '.join(h.rule for h in f.script_hits)}]"
                fv = FileVerdict(filename, action, rule_id, reason + detail + reason_extra, f.true_type, f.members)
                if f.cls in ("executable", "script", "shortcut") or rule_id == "R05":
                    fv.analysis = _static_report(data)  # extra evidence only; never changes the verdict
                return fv
        raise AssertionError("policy has no catch-all rule")

    def _scan_ooxml_members(self, f: Facts, data: bytes) -> None:
        """Office files are ZIPs: a signature or executable inside rejects them (R01/R09)."""
        cap = self.limits["max_unpacked_mb"] * 2**20
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if len(z.infolist()) > self.limits["max_archive_members"]:
                f.exceeds = True
                return
            for info in z.infolist():
                with z.open(info) as fh:
                    member = fh.read(cap)
                    cap -= len(member)
                if EICAR in member:
                    f.eicar = True
                if detect(member, self.file_types)[1] in ("executable", "script", "shortcut"):
                    f.worst_member = "reject"
                if cap <= 0:
                    f.exceeds = True
                    return

    def _inspect_zip(self, f: Facts, data: bytes, depth: int, budget: dict) -> None:
        lim = self.limits
        if depth + 1 > lim["max_archive_depth"]:
            f.exceeds = True
            return
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if len(z.infolist()) > lim["max_archive_members"]:  # count every entry, dirs included
                f.exceeds = True
                return
            for info in z.infolist():
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    f.encrypted = True
                    continue
                budget["members"] += 1
                budget["bytes"] += info.file_size
                ratio = info.file_size / max(info.compress_size, 1)
                if (budget["members"] > lim["max_archive_members"]
                        or budget["bytes"] > lim["max_unpacked_mb"] * 2**20
                        or ratio > lim["max_compression_ratio"]):
                    f.exceeds = True
                    return
                # Header sizes are attacker-controlled: cap the bytes actually read.
                allowed = lim["max_unpacked_mb"] * 2**20 - (budget["bytes"] - info.file_size)
                with z.open(info) as fh:
                    member = fh.read(allowed + 1)
                if len(member) > allowed:
                    f.exceeds = True
                    return
                mv = self.evaluate_file(info.filename, member, depth=depth + 1, budget=budget)
                f.members.append(mv)
                if mv.rule == "R08":  # a nested archive over the limits makes this one over too
                    f.exceeds = True
        f.worst_member = self.worst([m.verdict for m in f.members])


ANALYZER_TIMEOUT_S = 10
ANALYZER_MEMORY = 1 * 2**30  # 1 GiB address space


def _posix_limits_supported() -> bool:
    import os
    return os.name == "posix"


def _limit_child() -> None:  # runs in the child before exec (POSIX only)
    import resource
    for limit, value in ((resource.RLIMIT_AS, ANALYZER_MEMORY), (resource.RLIMIT_CPU, ANALYZER_TIMEOUT_S)):
        try:
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):  # e.g. macOS refuses RLIMIT_AS; the wall-clock timeout still applies
            pass


def run_isolated(data: bytes, argv: list[str] | None = None, timeout: float = ANALYZER_TIMEOUT_S) -> dict:
    """Run the static analyzer in a separate, resource-limited process, so a native crash
    or hang in LIEF/Capstone/YARA-X cannot take down the gateway."""
    import json
    import subprocess
    import sys
    argv = argv or [sys.executable, "-m", "mailguard.static", "--json", "-"]
    try:
        out = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, check=False,
                             preexec_fn=_limit_child if _posix_limits_supported() else None)
    except subprocess.TimeoutExpired:
        log.warning("static analysis timed out")
        return {"error": "analyzer timed out"}
    if out.returncode != 0:
        log.warning("static analysis exited with code %s", out.returncode)
        return {"error": "analyzer crashed"}
    try:
        return json.loads(out.stdout)
    except ValueError:
        return {"error": "analyzer output unreadable"}


def _office_report(data: bytes) -> dict:
    import sys
    return run_isolated(data, argv=[sys.executable, "-m", "mailguard.office", "-"])


def _static_report(data: bytes) -> dict:
    """Extra evidence only; never changes the verdict."""
    return run_isolated(data)
