"""True file type from content (Policy.yaml `file_types` and `refinements`)."""
import io
import zipfile

ZIP_EOCD = b"PK\x05\x06"  # end-of-central-directory record


def detect(data: bytes, file_types: list) -> tuple:
    """Return (type_name, class). Magic bytes first, then OOXML / text / unknown."""
    for name, magics, cls in file_types:
        if any(data.startswith(m) for m in magics):
            if name == "zip" and _is_ooxml(data):
                return "ooxml", "office_ooxml"
            return name, cls
    if b"\x00" not in data:
        try:
            data.decode("utf-8")
            return "text", "text"
        except UnicodeDecodeError:  # legacy 8-bit text (Latin-1 / Windows-1252 CSVs are common)
            sample = data[:65536]
            if sum(c >= 32 or c in (9, 10, 13) for c in sample) >= 0.97 * len(sample):
                return "text", "text"
    return "unknown", "unknown"


def _is_ooxml(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return "[Content_Types].xml" in z.namelist()
    except zipfile.BadZipFile:
        return False


def has_embedded_archive(data: bytes, cls: str) -> bool:
    """A ZIP appended to or hidden inside a non-archive file (ACSC email guidance)."""
    if cls == "legacy_office":
        return False  # OLE files legitimately embed OOXML fragments; the Office analyzer inspects them
    if cls in ("archive", "office_ooxml"):
        return data.count(ZIP_EOCD) > 1  # a second archive appended after the first
    return ZIP_EOCD in data


def ooxml_has_vba(data: bytes) -> bool:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = [n.lower() for n in z.namelist()]
        return any(n.endswith("vbaproject.bin") or "/macrosheets/" in f"/{n}" for n in names)
