"""Read-only decoding of base64 payloads found in an alert's command line (C6).

Two forms are recognised:
  * PowerShell encoded commands: -e, -ec, -enc, -encodedcommand (any case, any unambiguous prefix). PowerShell encodes these as
    UTF-16LE before base64, so that is tried first.
  * FromBase64String("...") literals, which are usually UTF-8 text.

Nothing is executed. The decoder is pure string and byte handling: no process is started, no script is evaluated and no
network call is made. The decoded text is data for an analyst to read, and it is labelled as such. Indicators found in it are
extracted by the enrichment agent with the source 'decoded_command_line', so they can be told apart from the original fields.
"""
import base64
import binascii
import re
from typing import Any, Dict, List

MAX_ENCODED_CHARS = 16384         # longer base64 values are reported as skipped, not decoded (UTF-16 text is ~2.7 chars per character)
MAX_DECODED_CHARS = 4096          # decoded text kept in the record; longer text is truncated and says so
MAX_PAYLOADS_PER_COMMAND = 5
PROVENANCE = ("Decoded from base64 text in the alert's command line. Analysis only: the decoded content was read as text "
              "and was NOT executed.")

_FULL_FLAG = "encodedcommand"
# Every prefix of -EncodedCommand from -e up to the full name, longest first so the full name wins where it is present.
_PS_FLAG = "|".join(sorted((re.escape(_FULL_FLAG[:n]) for n in range(1, len(_FULL_FLAG) + 1)), key=len, reverse=True))
_PS_ENCODED = re.compile(r"(?i)(?:(?<=\s)|^)-(?:" + _PS_FLAG + r")(?=\s)\s*[\"']?([A-Za-z0-9+/]{2,}={0,2})[\"']?")
_FROM_B64 = re.compile(r"(?i)FromBase64String\s*\(\s*[\"']([A-Za-z0-9+/=]{2,})[\"']\s*\)")


def _printable_enough(text: str) -> bool:
    if not text:
        return False
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return ok / len(text) >= 0.95


def _decode_bytes(raw: bytes, kind: str):
    """(encoding, text) for the first encoding that gives printable text, or (None, None)."""
    order = ("utf-16-le", "utf-8") if kind == "powershell_encoded_command" else ("utf-8", "utf-16-le")
    for encoding in order:
        try:
            text = raw.decode(encoding).lstrip("﻿")
        except UnicodeDecodeError:
            continue
        if _printable_enough(text):
            return encoding, text
    return None, None


def decode_value(encoded: str, kind: str) -> Dict[str, Any]:
    """Decode one base64 value. Never raises; the result says what happened."""
    base = {"kind": kind, "encoded_length": len(encoded), "executed": False, "evidence_type": "decoded_payload",
            "provenance": PROVENANCE}
    if len(encoded) > MAX_ENCODED_CHARS:
        return {**base, "status": "skipped", "reason": f"encoded value is longer than {MAX_ENCODED_CHARS} characters and was not decoded"}
    stripped = encoded.rstrip("=")
    if len(stripped) % 4 == 1 or "=" in stripped:
        return {**base, "status": "invalid_base64", "reason": "the value is not valid base64"}
    try:
        raw = base64.b64decode(stripped + "=" * (-len(stripped) % 4), validate=True)
    except (binascii.Error, ValueError):
        return {**base, "status": "invalid_base64", "reason": "the value is not valid base64"}
    encoding, text = _decode_bytes(raw, kind)
    if text is None:
        return {**base, "status": "not_text", "reason": "the decoded bytes are not printable text in UTF-16LE or UTF-8"}
    return {**base, "status": "decoded", "encoding": encoding, "decoded_length": len(text),
            "truncated": len(text) > MAX_DECODED_CHARS, "decoded_text": text[:MAX_DECODED_CHARS]}


def decode_command_line_payloads(command_line: Any) -> List[Dict[str, Any]]:
    """Every encoded PowerShell command and FromBase64String literal in a command line, in the order they appear."""
    if not command_line or not isinstance(command_line, str):
        return []
    found = []
    for match in _PS_ENCODED.finditer(command_line):
        found.append((match.start(), decode_value(match.group(1), "powershell_encoded_command")))
    for match in _FROM_B64.finditer(command_line):
        found.append((match.start(), decode_value(match.group(1), "from_base64_string")))
    found.sort(key=lambda item: item[0])
    return [payload for _, payload in found[:MAX_PAYLOADS_PER_COMMAND]]
