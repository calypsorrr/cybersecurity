"""Lightweight payload inspections for media files and raw emails."""

from __future__ import annotations

import base64
import binascii
import json
import mimetypes
import re
import urllib.error
import urllib.request
from email import message_from_string
from email.message import Message
from email.utils import parseaddr
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from cybercheck.config import VIRUSTOTAL_API_KEY


ReadableIssue = Dict[str, str]
InspectionReport = Dict[str, object]


def _fingerprint_header(data: bytes) -> str:
    """Return a human label for known magic numbers."""

    trimmed = data.lstrip()
    if trimmed.startswith(b"<!DOCTYPE html") or trimmed.startswith(b"<html"):
        return "HTML document header"
    if trimmed.startswith(b"<?xml"):
        return "XML document header"
    if trimmed.startswith(b"%PDF"):
        return "PDF document header"
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


def _detect_media_integrity(data: bytes, ext: str, detected_header: str) -> List[ReadableIssue]:
    """Validate that common media containers look structurally sound."""

    issues: List[ReadableIssue] = []
    lower_header = detected_header.lower()
    lower_ext = ext.lower()

    if "jpeg" in lower_header or lower_ext in {".jpg", ".jpeg"}:
        if not data.rstrip().endswith(b"\xff\xd9"):
            _append_issue(
                issues,
                "Corrupted media body",
                "JPEG stream missing end-of-image marker; file may be truncated.",
                "content",
            )
    if "png" in lower_header or lower_ext == ".png":
        if b"IEND" not in data[-32:]:
            _append_issue(
                issues,
                "Corrupted media body",
                "PNG container missing IEND trailer; body looks incomplete.",
                "content",
            )
    if "gif" in lower_header or lower_ext == ".gif":
        if not data.rstrip().endswith(b"\x3b"):
            _append_issue(
                issues,
                "Corrupted media body",
                "GIF file missing terminator byte (0x3B); decode may fail.",
                "content",
            )
    if "mp4" in lower_header or lower_ext in {".mp4", ".mov"}:
        if b"moov" not in data[:4096].lower() and b"mdat" not in data.lower():
            _append_issue(
                issues,
                "Suspicious container",
                "MP4 container missing moov/mdat atoms; could be malformed or polyglot.",
                "content",
            )

    return issues


def _find_secondary_signatures(data: bytes) -> List[ReadableIssue]:
    """Search for hidden/embedded formats beyond the leading header."""

    issues: List[ReadableIssue] = []

    if b"PK\x03\x04" in data[1:]:
        _append_issue(
            issues,
            "Embedded archive",
            "ZIP header found deeper in the file; may be a polyglot payload.",
            "content",
        )
    if b"%PDF" in data[1:]:
        _append_issue(
            issues,
            "Embedded document",
            "PDF signature present alongside other content; review for polyglot tricks.",
            "content",
        )

    return issues


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
    declared_type, _ = mimetypes.guess_type(filename)
    detected_header = _fingerprint_header(data)
    header_family = detected_header.split(" ")[0].lower()

    issues.extend(_find_secondary_signatures(data))

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
    for issue in _detect_media_integrity(data, ext, detected_header):
        issues.append(issue)

    html_match = re.search(r"<!DOCTYPE html|<html", ascii_text, flags=re.IGNORECASE)
    if html_match and header_family not in {"html", "unknown"}:
        snippet = _extract_text_window(ascii_text, html_match)
        _append_issue(
            issues,
            "Embedded HTML content",
            "Binary content also contains HTML markup; could be a polyglot payload.",
            "content",
            snippet,
        )

    metadata_flags: List[str] = []
    if b"Exif" in data[:2048]:
        metadata_flags.append("EXIF metadata present")
    if b"JFIF" in data[:64]:
        metadata_flags.append("JFIF segment present")
    if b"ID3" in data[:10]:
        metadata_flags.append("ID3 audio tags present")
    if b"ftyp" in data[:64]:
        metadata_flags.append("MP4/ISO base media brand detected")
    if re.search(r"<meta ", ascii_text, flags=re.IGNORECASE):
        metadata_flags.append("HTML meta tags present")

    metadata_flags = metadata_flags or ["None detected"]
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
        "metadata_flags": metadata_flags,
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


# Known webmail spoofing services that frequently appear in forged headers.
FAKE_MAILER_MARKERS = {
    "emkei.cz": "Emkei anonymous emailer",
    "emkei.name": "Emkei anonymous emailer",
}


def analyze_email_text(raw_email: str) -> InspectionReport:
    """Inspect a raw RFC822 email body and flag phishing or payload risks."""

    message: Message = message_from_string(raw_email)
    issues: List[ReadableIssue] = []

    from_display, from_addr = parseaddr(message.get("From", ""))
    _, reply_to = parseaddr(message.get("Reply-To", ""))
    _, return_path = parseaddr(message.get("Return-Path", ""))
    subject = message.get("Subject", "").strip()

    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""

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
        risky_tlds = {"ru", "su", "cn", "top", "xyz", "biz"}
        from_root = ".".join(from_domain.split(".")[-2:]) if "." in from_domain else from_domain
        reply_root = ".".join(reply_domain.split(".")[-2:]) if "." in reply_domain else reply_domain
        if reply_root and reply_root != from_root and reply_root.split(".")[-1] in risky_tlds:
            _append_issue(
                issues,
                "Foreign Reply-To domain",
                "Reply-To routes to a different high-risk domain, common in fraud.",
                "header",
                f"From domain: {from_domain or 'unknown'} | Reply-To domain: {reply_domain}",
            )
    if return_path and from_addr and not _compare_domains(from_addr, return_path):
        _append_issue(
            issues,
            "Return-Path mismatch",
            "Return-Path domain differs from From domain; sender may be spoofed.",
            "header",
            f"From: {from_addr} | Return-Path: {return_path}",
        )

    auth_results = message.get_all("Authentication-Results", []) or []
    spf_received = message.get_all("Received-SPF", []) or []
    spf_lines = auth_results + spf_received
    for spf_line in spf_lines:
        match = re.search(r"spf=([a-z]+)", spf_line, flags=re.IGNORECASE)
        if match:
            spf_result = match.group(1).lower()
            if spf_result in {"fail", "softfail", "permerror"}:
                _append_issue(
                    issues,
                    "SPF validation failure",
                    f"SPF check returned '{spf_result}', indicating sender domain is not authorized.",
                    "header",
                    spf_line.strip(),
                )
            break

    dmarc_headers = auth_results + (message.get_all("DMARC-Filter", []) or [])
    for dmarc_line in dmarc_headers:
        match = re.search(r"dmarc=([a-z]+)", dmarc_line, flags=re.IGNORECASE)
        if match:
            dmarc_result = match.group(1).lower()
            if dmarc_result in {"fail", "quarantine", "reject", "permerror"}:
                _append_issue(
                    issues,
                    "DMARC validation failure",
                    f"DMARC check returned '{dmarc_result}', suggesting the domain policy was not met.",
                    "header",
                    dmarc_line.strip(),
                )
            break

    if not subject:
        _append_issue(issues, "Empty subject", "Messages without a subject are suspicious.", "header")

    header_blob = "\n".join(f"{key}: {value}" for key, value in message.items()).lower()
    for marker, label in FAKE_MAILER_MARKERS.items():
        if marker in header_blob:
            _append_issue(
                issues,
                "Fake emailer detected",
                f"Headers reference {label}; message may be anonymously forged.",
                "header",
                marker,
            )

    display_domains = re.findall(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", from_display)
    if from_display and from_domain:
        for disp_domain in display_domains:
            if from_domain not in disp_domain.lower():
                _append_issue(
                    issues,
                    "Display name/domain mismatch",
                    "Display name implies a different sender domain than the actual address.",
                    "header",
                    f"Display: {from_display} | Actual: {from_addr}",
                )
                break

    priority_headers = [message.get("X-Priority", ""), message.get("Priority", ""), message.get("Importance", "")]
    is_high_priority = any(re.search(r"(1|high|urgent)", header or "", flags=re.IGNORECASE) for header in priority_headers)

    body_chunks: List[str] = []
    attachment_names: List[str] = []
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
                attachment_names.append(part.get_filename())
                _append_issue(
                    issues,
                    "Attachment present",
                    f"Attachment named {part.get_filename()} detected; verify its safety before opening.",
                    "attachment",
                )
    else:
        body_chunks.append(message.get_payload(decode=True).decode("utf-8", errors="ignore") if message.get_payload() else "")

    body_text = "\n".join(body_chunks)

    phishing_keywords = ["verify", "password", "wire", "gift card", "invoice", "payment"]
    for keyword in phishing_keywords:
        for match in re.finditer(keyword, body_text, flags=re.IGNORECASE):
            snippet = _extract_text_window(body_text, match)
            _append_issue(issues, "Phishing language", f"Keyword '{keyword}' found.", "body", snippet)

    threatening_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"account (?:locked|suspended|closed)",
        r"legal action",
        r"final notice",
        r"respond within",
    ]
    for pattern in threatening_patterns:
        for match in re.finditer(pattern, body_text, flags=re.IGNORECASE):
            snippet = _extract_text_window(body_text, match)
            _append_issue(
                issues,
                "Urgent/threatening language",
                "Email tone pressures the reader with urgency or threats.",
                "body",
                snippet,
            )

    for link in re.finditer(r"https?://[\w\.-]+", body_text):
        snippet = _extract_text_window(body_text, link, radius=40)
        _append_issue(issues, "Link present", "Email contains external link(s); verify destinations.", "body", snippet)

    for anchor in re.finditer(r"<a [^>]*href=[\"']([^\"'>\s]+)[\"'][^>]*>(.*?)</a>", body_text, flags=re.IGNORECASE | re.DOTALL):
        href = anchor.group(1).strip()
        anchor_text = re.sub(r"\s+", " ", anchor.group(2)).strip()
        if re.search(r"https?://", anchor_text):
            href_domain = urlparse(href).netloc.lower()
            text_domain = urlparse(anchor_text).netloc.lower()
            if href_domain and text_domain and href_domain != text_domain:
                _append_issue(
                    issues,
                    "Misleading hyperlink",
                    "Link text implies a trusted site but points elsewhere.",
                    "body",
                    f"Text: {anchor_text} -> {href}",
                )

    metadata = {
        "from": from_addr or "Unknown",
        "reply_to": reply_to or "Not provided",
        "subject": subject or "(none)",
    }

    if is_high_priority and any("invoice" in (name or "").lower() for name in attachment_names):
        _append_issue(
            issues,
            "High-priority invoice attachment",
            "Message marked high priority while carrying an invoice-named attachment.",
            "attachment",
        )

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


def lookup_hash_reputation(hash_value: str) -> InspectionReport:
    normalized = hash_value.strip().lower()

    if not re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", normalized):
        return {
            "label": "Hash reputation",
            "risk_level": "info",
            "summary": "Provide an MD5, SHA1, or SHA256 hash for reputation checks.",
            "metadata": {"hash": normalized or "None"},
            "issues": [
                {
                    "type": "Invalid hash",
                    "description": "Hashes must be 32, 40, or 64 hexadecimal characters.",
                    "location": "input",
                }
            ],
        }

    if not VIRUSTOTAL_API_KEY:
        return {
            "label": "Hash reputation",
            "risk_level": "info",
            "summary": "VirusTotal API key not configured; cannot query reputation.",
            "metadata": {"hash": normalized},
            "issues": [],
        }

    url = f"https://www.virustotal.com/api/v3/files/{normalized}"
    request = urllib.request.Request(url, headers={"x-apikey": VIRUSTOTAL_API_KEY})

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "label": "Hash reputation",
                "risk_level": "info",
                "summary": "Hash not found in VirusTotal corpus.",
                "metadata": {"hash": normalized},
                "issues": [],
            }
        return {
            "label": "Hash reputation",
            "risk_level": "info",
            "summary": "VirusTotal lookup failed; try again later.",
            "metadata": {"hash": normalized, "status": exc.code},
            "issues": [],
        }
    except (urllib.error.URLError, TimeoutError) as exc:
        return {
            "label": "Hash reputation",
            "risk_level": "info",
            "summary": "Unable to reach VirusTotal.",
            "metadata": {"hash": normalized, "error": str(exc)},
            "issues": [],
        }

    data = payload.get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    last_results = attributes.get("last_analysis_results", {})

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))

    risk_level = "info"
    if malicious > 0:
        risk_level = "high"
    elif suspicious > 0:
        risk_level = "medium"

    positives = [
        res
        for res in last_results.values()
        if res.get("category") in {"malicious", "suspicious"}
    ]
    issues: List[ReadableIssue] = []
    for result in sorted(positives, key=lambda r: r.get("engine_name", ""))[:5]:
        issues.append(
            {
                "type": result.get("engine_name", "Engine"),
                "description": result.get("result", "Flagged"),
                "location": result.get("category", "analysis"),
            }
        )

    summary_parts = [
        f"Malicious: {malicious}",
        f"Suspicious: {suspicious}",
        f"Harmless: {harmless}",
        f"Undetected: {undetected}",
    ]
    summary = ", ".join(summary_parts)

    metadata: Dict[str, object] = {
        "hash": normalized,
        "reputation": attributes.get("reputation", 0),
        "type": attributes.get("type_description", "Unknown"),
        "first_submission": attributes.get("first_submission_date"),
        "last_submission": attributes.get("last_submission_date"),
    }

    return {
        "label": "Hash reputation",
        "risk_level": risk_level,
        "summary": summary,
        "metadata": metadata,
        "issues": issues,
    }
