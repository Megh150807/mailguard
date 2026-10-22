"""Office content analysis: reads VBA code (olevba), decides with mraptor (auto-run AND
write/execute/download = suspicious), and finds DDE fields and Excel 4 macro sheets.
Never opens or runs the document. Called in an isolated process (policy.run_isolated)."""
import io
import re
import sys
import warnings
import xml.etree.ElementTree as ET
import zipfile

warnings.filterwarnings("ignore")  # oletools emits pyparsing deprecation warnings on import
from oletools.mraptor import MacroRaptor
from oletools.olevba import VBA_Parser

_DDE = re.compile(r"\bDDE(?:AUTO)?\b.*", re.IGNORECASE)
MAX_PARTS, PART_CAP = 500, 4 * 2**20


def macro_is_suspicious(code: str) -> bool:
    mr = MacroRaptor(code)
    mr.scan()
    return bool(mr.suspicious)


def _ooxml_parts(data: bytes) -> tuple[dict[str, bytes], bool]:
    """XML parts of an OOXML file, each read with a cap; complete=False if anything was cut."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = [n for n in z.namelist() if n.endswith((".xml", ".rels"))]
            parts, complete = {}, len(names) <= MAX_PARTS
            for n in names[:MAX_PARTS]:
                with z.open(n) as fh:
                    parts[n] = fh.read(PART_CAP + 1)
                if len(parts[n]) > PART_CAP:
                    complete = False
            return parts, complete
    except zipfile.BadZipFile:
        return {}, True


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _dde_fields(parts: dict[str, bytes]) -> tuple[list[str], bool]:
    """Field instructions via an XML parser: any namespace prefix, entities decoded."""
    found, complete = [], True
    for name, xml in parts.items():
        if not name.startswith(("word/", "xl/")):
            continue
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            complete = False
            continue
        instr = []
        for el in root.iter():
            local = _local(el.tag)
            if local == "instrText" and el.text:
                instr.append(el.text)
            elif local == "ddeLink":
                found.append(f"ddeLink in {name}")
            elif local == "f" and el.text and _DDE.search(el.text):  # DDE formula in a cell
                found.append(el.text.strip()[:120])
            instr += [v for k, v in el.attrib.items() if _local(k) == "instr"]
        found += [m.group(0).strip()[:120] for m in _DDE.finditer(" ".join(instr))]
    return found, complete


def analyze_office(data: bytes) -> dict:
    parts, parts_complete = _ooxml_parts(data)
    dde, dde_complete = _dde_fields(parts)
    report = {"vba": False, "xlm": any("macrosheets/" in n for n in parts), "autoexec": [],
              "suspicious_keywords": [], "suspicious": False, "dde": dde, "code_excerpt": "",
              "incomplete": not (parts_complete and dde_complete)}
    p = VBA_Parser(filename="attachment", data=data)
    try:
        if p.detect_vba_macros():
            report["vba"] = True
            code = "\n".join(c for _, _, _, c in p.extract_all_macros() if c)
            report["code_excerpt"] = code[:400]
            report["suspicious"] = macro_is_suspicious(code)
            for kind, keyword, _ in p.analyze_macros():
                if kind == "AutoExec":
                    report["autoexec"].append(keyword)
                elif kind in ("Suspicious", "IOC"):
                    report["suspicious_keywords"].append(keyword)
        if not parts and hasattr(p, "detect_xlm_macros"):
            report["xlm"] = bool(p.detect_xlm_macros())
    finally:
        p.close()
    return report


def main() -> None:
    import json
    from pathlib import Path
    data = sys.stdin.buffer.read(64 * 2**20) if sys.argv[-1] == "-" else Path(sys.argv[-1]).read_bytes()
    print(json.dumps(analyze_office(data)))


if __name__ == "__main__":
    main()
