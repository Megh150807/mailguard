"""Lists every MIME leaf part and the defects that make its parse untrustworthy."""
import base64
import binascii
import re
from dataclasses import dataclass
from email import message_from_bytes
from email.utils import collapse_rfc2231_value

_BAD_QP = re.compile(rb"=(?![0-9A-Fa-f]{2}|\r?\n|$)", re.MULTILINE)


@dataclass
class Part:
    filename: str
    data: bytes
    defects: list[str]
    is_body: bool = False  # message text, not an attachment: only signature + defect checks apply


def inventory(raw: bytes) -> tuple:
    """Return (message_defects, attachment_parts). Body text without a filename is not
    an attachment; every other leaf, inline or not, is."""
    msg = message_from_bytes(raw)  # compat32: keeps raw parameters and reports defects
    msg_defects = [type(d).__name__ for d in msg.defects]
    parts = []
    for part in msg.walk():
        if part.is_multipart():
            msg_defects += [type(d).__name__ for d in part.defects]
            continue
        defects = [type(d).__name__ for d in part.defects]
        for h in ("Content-Type", "Content-Disposition", "Content-Transfer-Encoding"):
            if len(part.get_all(h) or []) > 1:
                defects.append(f"Duplicate{h.replace('-', '')}")
        name, name_defect = _filename(part)
        if name_defect:
            defects.append(name_defect)
        is_body = (name is None and part.get_content_maintype() == "text"
                   and part.get_content_disposition() != "attachment")
        data, decode_defect = _decode(part)
        if decode_defect:
            defects.append(decode_defect)
        parts.append(Part(name or "", data, defects, is_body))
    return msg_defects, parts


def _filename(part):
    """compat32 reports both `filename` and RFC 2231 `filename*` under the key 'filename'
    (the latter as a tuple), so collect every value and flag disagreement (RFC 2231)."""
    names = []
    for header, wanted in (("content-disposition", "filename"), ("content-type", "name")):
        for key, value in part.get_params(header=header) or []:
            if key.lower() == wanted:
                names.append(collapse_rfc2231_value(value).strip('"'))
    if len(set(names)) > 1:
        return names[0], "FilenameConflict"
    return (names[0] if names else None), None


KNOWN_CTE = {"7bit", "8bit", "binary", "base64", "quoted-printable"}


def _decode(part):
    cte = (part.get("Content-Transfer-Encoding") or "7bit").strip().lower()
    if cte not in KNOWN_CTE:  # a client may decode it differently from us
        return part.get_payload(decode=True) or b"", "UnknownTransferEncoding"
    body = part.get_payload(decode=False)
    body = body.encode("latin-1", "replace") if isinstance(body, str) else (body or b"")
    if cte == "base64":
        compact = re.sub(rb"\s+", b"", body)
        try:
            return base64.b64decode(compact, validate=True), None
        except (binascii.Error, ValueError):
            return part.get_payload(decode=True) or b"", "InvalidBase64"
    if cte == "quoted-printable" and _BAD_QP.search(body):
        return part.get_payload(decode=True) or b"", "InvalidQuotedPrintable"
    return part.get_payload(decode=True) or b"", None
