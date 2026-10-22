"""YARA-X signature scanning shared by the policy (every file) and the static RE pipeline.
YARA-X is written in Rust, so scanning untrusted bytes in-process is low-risk; the native
binary parsers (LIEF, Capstone) stay isolated in a subprocess (see policy.run_isolated)."""
import base64
import binascii
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yara_x

RULES_DIR = Path(__file__).parent / "rules"
SCAN_CAP = 8 * 2**20
TIMEOUT_S = 5
HIGH_CONFIDENCE = 20  # rule weight at or above which a hit alone justifies quarantine (R16)
DECODE_DEPTH = 2          # layers of unwrapping (e.g. base64 inside base64)
DECODE_BUDGET = 2 * 2**20  # total decoded bytes per file

_B64 = re.compile(rb"[A-Za-z0-9+/][A-Za-z0-9+/\r\n]{31,}={0,2}")  # line breaks anywhere (wrapped base64)
_WS = re.compile(rb"\s+")
_CHARS = re.compile(rb"(?:\[char\][ \t]{0,8}\d{1,3}[ \t+,]{0,8}){4,}", re.IGNORECASE)  # bounded: no ReDoS
_SPLIT = re.compile(rb"""(['"])\s*\+\s*\1""")  # 'Down'+'load' -> 'Download'
_NUM = re.compile(rb"\d{1,3}")


@dataclass(frozen=True)
class Hit:
    rule: str
    category: str
    weight: int
    sample: str


@cache
def compiled() -> yara_x.Rules:
    return yara_x.compile("\n".join(p.read_text() for p in sorted(RULES_DIR.glob("*.yar"))))


def scan(data: bytes) -> list[Hit]:
    scanner = yara_x.Scanner(compiled())
    scanner.set_timeout(TIMEOUT_S)
    hits = []
    for m in scanner.scan(data[:SCAN_CAP]).matching_rules:
        meta = dict(m.metadata)
        sample = next((data[x.offset: x.offset + min(x.length, 80)].decode("latin-1")
                       for p in m.patterns for x in p.matches), meta.get("description", ""))
        hits.append(Hit(m.identifier, meta.get("category", m.identifier), int(meta.get("weight", 0)), sample))
    return hits


def _printable(b: bytes) -> bool:
    return bool(b) and sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b) >= 0.5


def _unwrap(data: bytes) -> list[bytes]:
    """One layer of common script disguises."""
    out = []
    joined = _SPLIT.sub(b"", data)
    if joined != data:
        out.append(joined)
    for m in _CHARS.finditer(data):
        out.append(bytes(int(n) for n in _NUM.findall(m.group(0)) if int(n) < 256))
    for m in _B64.finditer(data):
        blob = _WS.sub(b"", m.group(0))
        try:
            raw = base64.b64decode(blob + b"=" * (-len(blob) % 4))
        except (binascii.Error, ValueError):
            continue
        if len(raw) > 4 and raw[1::2].count(0) > len(raw) // 4:  # UTF-16LE, PowerShell -enc
            raw = raw.decode("utf-16-le", "ignore").encode("latin-1", "ignore")
        if _printable(raw):
            out.append(raw)
    return out


def decode_layers_checked(data: bytes) -> tuple[list[bytes], bool]:
    """Decoded layers, and whether everything was decoded (False if the budget ran out)."""
    layers, frontier, budget = [], [data[:SCAN_CAP]], DECODE_BUDGET
    for _ in range(DECODE_DEPTH):
        nxt = []
        for blob in frontier:
            for layer in _unwrap(blob):
                if len(layer) > budget:
                    return layers, False
                budget -= len(layer)
                layers.append(layer)
                nxt.append(layer)
        frontier = nxt
    return layers, True


def decode_layers(data: bytes) -> list[bytes]:
    return decode_layers_checked(data)[0]


def scan_layers_checked(data: bytes) -> tuple[list[Hit], bool]:
    """Signature hits on the raw bytes and on every decoded layer, plus completeness."""
    hits = scan(data)
    layers, complete = decode_layers_checked(data)
    for layer in layers:
        hits += [Hit(h.rule, h.category, h.weight, f"(decoded) {h.sample}") for h in scan(layer)]
    return hits, complete


def scan_layers(data: bytes) -> list[Hit]:
    return scan_layers_checked(data)[0]
