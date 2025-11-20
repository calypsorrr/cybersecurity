"""Lightweight payload inspections for media files and raw emails."""

from __future__ import annotations

import base64
import binascii
import mimetypes
import re
from email import message_from_string
from email.message import Message
from email.utils import parseaddr
from pathlib import Path
from typing import Dict, List, Tuple


ReadableIssue = Dict[str, str]
InspectionReport = Dict[str, object]


def _fingerprint_header(data: bytes) -> str:
    """Return a human label for known magic numbers."""

    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG image header"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image header"
    if data.startswith(b"GIF8"):
        return "GIF image header"
    if data.startswith(b"ID3") or data[:2] == b"\xff\xfb":
        return "MP3 audio header"
    if b"ftyp" in data[:16]:
        return "MP4 container header"
    if data.startswith(b"RIFF") and data[8:12] == b"AVI ":
        return "AVI container header"
    if data.startswith(b"\x00\x00\x00\x14ftypqt"):
        return "QuickTime container header"
    if data.startswith(b"MZ"):
        return "Windows PE header"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive header"

    return "Unknown/opaque header"


def _extension_family(ext: str) -> str:
    media_map = {
        ".mp4": "video",
        ".mov": "video",
        ".avi": "video",
        ".mp3": "audio",
        ".wav": "audio",
        ".png": "image",
        ".jpg": "image",
        ".jpeg": "image",
        ".gif": "image",
        ".bmp": "image",
        ".eml": "email",
    }
    return media_map.get(ext.lower(), "other")


def _append_issue(issues: List[ReadableIssue], issue_type: str, description: str, location: str, evidence: str | None = None) -> None:
    payload = {"type": issue_type, "description": description, "location": location}
    if evidence:
        payload["evidence"] = evidence
    issues.append(payload)


def _extract_text_window(text: str, match: re.Match[str], radius: int = 80) -> str:
    start = max(match.start() - radius, 0)
    end = min(match.end() + radius, len(text))
    return text[start:end].strip()


def analyze_uploaded_file(filename: str, data: bytes) -> InspectionReport:
    """Inspect an uploaded binary/text payload and flag suspicious traits."""

    issues: List[ReadableIssue] = []
    ext = Path(filename).suffix

    if ext.lower() == ".eml":
        try:
            email_text = data.decode("utf-8")
        except UnicodeDecodeError:
            email_text = data.decode("latin-1", errors="ignore")

        email_report = analyze_email_text(email_text)
        email_report["label"] = f"Email file: {Path(filename).name}"
        email_report.setdefault("metadata", {})
        email_report["metadata"].update(
            {"filename": Path(filename).name, "size_bytes": len(data)}
        )
        return email_report
    declared_type, _ = mimetypes.guess_type(filename)
    detected_header = _fingerprint_header(data)
    header_family = detected_header.split(" ")[0].lower()

    if ext:
        family = _extension_family(ext)
        if family in {"image", "audio", "video"} and "header" in detected_header and family not in detected_header.lower():
            _append_issue(
                issues,
                "Extension/header mismatch",
                f"File looks like {detected_header} but is named {ext}.",
                "header",
            )
        if detected_header == "Windows PE header" and family != "other":
            _append_issue(
                issues,
                "Executable masquerading as media",
                "Media-named file contains a Windows executable header.",
                "header",
            )

    ascii_text = "".join(chr(b) if 32 <= b <= 126 else " " for b in data)
    suspicious_patterns: List[Tuple[re.Pattern[str], str]] = [
        (re.compile(r"<\s*script", re.IGNORECASE), "Embedded script tag"),
        (re.compile(r"javascript:\s*", re.IGNORECASE), "JavaScript URI found"),
        (re.compile(r"powershell|cmd\.exe|wscript", re.IGNORECASE), "Command execution keywords"),
        (re.compile(r"onerror=|onload=", re.IGNORECASE), "HTML event handlers in payload"),
    ]

    for pattern, label in suspicious_patterns:
        for match in pattern.finditer(ascii_text):
            snippet = _extract_text_window(ascii_text, match)
            _append_issue(issues, label, "Suspicious scripting hint present.", "content", snippet)

    if re.search(r"[A-Za-z0-9+/]{160,}={0,2}", ascii_text):
        _append_issue(
            issues,
            "Embedded base64 blob",
            "Detected a large base64 block that could hide secondary payloads.",
            "content",
        )

    try:
        if data and base64.b64decode(data, validate=True):
            if len(data) > 1024:
                _append_issue(
                    issues,
                    "Pure base64 body",
                    "Entire file is valid base64; consider decoding before trusting it.",
                    "content",
                )
    except (binascii.Error, ValueError):
        pass

    metadata: Dict[str, object] = {
        "filename": Path(filename).name,
        "size_bytes": len(data),
        "declared_type": declared_type or "Unknown",
        "detected_header": detected_header,
    }

    critical_types = {"Executable masquerading as media", "Embedded script tag", "Command execution keywords"}
    risk_level = "info"
    if any(issue.get("type") in critical_types for issue in issues):
        risk_level = "high"
    elif len(issues) >= 3:
        risk_level = "high"
    elif issues:
        risk_level = "medium"

    return {
        "label": f"File: {metadata['filename']}",
        "issues": issues,
        "metadata": metadata,
        "risk_level": risk_level,
        "summary": "No obvious threats detected." if not issues else "Potentially malicious traits found.",
    }


def _compare_domains(addr_one: str, addr_two: str) -> bool:
    domain_one = addr_one.split("@")[-1].lower() if "@" in addr_one else ""
    domain_two = addr_two.split("@")[-1].lower() if "@" in addr_two else ""
    return domain_one == domain_two and domain_one != ""


def analyze_email_text(raw_email: str) -> InspectionReport:
    """Inspect a raw RFC822 email body and flag phishing or payload risks."""

    message: Message = message_from_string(raw_email)
    issues: List[ReadableIssue] = []

    from_addr = parseaddr(message.get("From", ""))[1]
    reply_to = parseaddr(message.get("Reply-To", ""))[1]
    subject = message.get("Subject", "").strip()

    if not from_addr:
        _append_issue(issues, "Missing From", "Sender header is empty or malformed.", "header")
    if reply_to and from_addr and not _compare_domains(from_addr, reply_to):
        _append_issue(
            issues,
            "Reply-To mismatch",
            "Reply-To domain differs from From domain, often used in phishing.",
            "header",
            f"From: {from_addr} | Reply-To: {reply_to}",
        )
    if not subject:
        _append_issue(issues, "Empty subject", "Messages without a subject are suspicious.", "header")

    body_chunks: List[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            charset = part.get_content_charset() or "utf-8"
            try:
                body_chunks.append(payload.decode(charset, errors="ignore"))
            except LookupError:
                body_chunks.append(payload.decode("utf-8", errors="ignore"))
            if part.get_filename():
                _append_issue(
                    issues,
                    "Attachment present",
                    f"Attachment named {part.get_filename()} detected; verify its safety before opening.",
                    "attachment",
                )
    else:
        body_chunks.append(message.get_payload(decode=True).decode("utf-8", errors="ignore") if message.get_payload() else "")

    body_text = "\n".join(body_chunks)

    phishing_keywords = ["urgent", "verify", "password", "wire", "gift card", "invoice", "payment"]
    for keyword in phishing_keywords:
        for match in re.finditer(keyword, body_text, flags=re.IGNORECASE):
            snippet = _extract_text_window(body_text, match)
            _append_issue(issues, "Phishing language", f"Keyword '{keyword}' found.", "body", snippet)

    for link in re.finditer(r"https?://[\w\.-]+", body_text):
        snippet = _extract_text_window(body_text, link, radius=40)
        _append_issue(issues, "Link present", "Email contains external link(s); verify destinations.", "body", snippet)

    metadata = {
        "from": from_addr or "Unknown",
        "reply_to": reply_to or "Not provided",
        "subject": subject or "(none)",
    }

    risk_level = "info"
    if len(issues) >= 4:
        risk_level = "high"
    elif issues:
        risk_level = "medium"

    return {
        "label": "Email content",
        "issues": issues,
        "metadata": metadata,
        "risk_level": risk_level,
        "summary": "No obvious phishing indicators." if not issues else "Email shows risky traits.",
    }
