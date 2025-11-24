"""Enhanced security utilities for input validation and threat detection."""

from __future__ import annotations

import re
import ipaddress
from typing import Tuple, Optional, List
from urllib.parse import urlparse


# Enhanced dangerous patterns
_DANGEROUS_PATTERNS = re.compile(
    r"[;&`]|\$\(|\|\||\n|\r|\>\>?|&&|```|<\s*script",
    re.IGNORECASE
)

# Path traversal patterns
_PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\|%2e%2e|%2E%2E")

# SQL injection patterns (basic detection)
_SQL_INJECTION = re.compile(
    r"(\bor\b|\band\b)\s+\d+\s*=\s*\d+|union\s+select|drop\s+table|exec\s*\(|--\s|/\*|\*/",
    re.IGNORECASE
)

# Command injection patterns
_COMMAND_INJECTION = re.compile(
    r"[;&`]|\$\{|`|\\x[0-9a-f]{2}",
    re.IGNORECASE
)


def validate_ip_address(ip_str: str) -> Tuple[bool, Optional[str]]:
    """Validate if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True, None
    except ValueError:
        return False, "Invalid IP address format"


def validate_cidr(cidr_str: str) -> Tuple[bool, Optional[str]]:
    """Validate if string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True, None
    except ValueError:
        return False, "Invalid CIDR notation"


def validate_url(url_str: str, allowed_schemes: Optional[List[str]] = None) -> Tuple[bool, Optional[str]]:
    """Validate if string is a valid URL."""
    if allowed_schemes is None:
        allowed_schemes = ['http', 'https', 'ftp']
    
    try:
        parsed = urlparse(url_str)
        if not parsed.scheme:
            return False, "URL must include a scheme (http/https)"
        if parsed.scheme.lower() not in allowed_schemes:
            return False, f"URL scheme must be one of: {', '.join(allowed_schemes)}"
        if not parsed.netloc:
            return False, "URL must include a valid hostname"
        return True, None
    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"


def validate_scan_target_enhanced(target: str, max_length: int = 512) -> Tuple[bool, Optional[str]]:
    """Enhanced target validation with multiple checks."""
    if not target or not target.strip():
        return False, "Target is required."

    candidate = target.strip()
    
    # Length check
    if len(candidate) > max_length:
        return False, f"Target value exceeds maximum length of {max_length} characters."

    # Path traversal check
    if _PATH_TRAVERSAL.search(candidate):
        return False, "Target contains path traversal patterns."

    # SQL injection attempt check
    if _SQL_INJECTION.search(candidate):
        return False, "Target contains potentially dangerous SQL patterns."

    # Command injection check
    if _COMMAND_INJECTION.search(candidate):
        return False, "Target contains potentially dangerous command injection patterns."

    # Dangerous shell patterns
    if _DANGEROUS_PATTERNS.search(candidate):
        return False, "Target contains potentially dangerous characters."

    # Try to validate as IP, CIDR, or URL
    ip_valid, ip_error = validate_ip_address(candidate)
    if ip_valid:
        return True, None
    
    cidr_valid, cidr_error = validate_cidr(candidate)
    if cidr_valid:
        return True, None
    
    url_valid, url_error = validate_url(candidate)
    if url_valid:
        return True, None
    
    # Domain/hostname validation (basic)
    domain_pattern = re.compile(
        r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$',
        re.IGNORECASE
    )
    if domain_pattern.match(candidate) or candidate.replace('.', '').replace('-', '').isalnum():
        return True, None

    # Allow if it looks safe (alphanumeric with dots, dashes, underscores, slashes)
    safe_pattern = re.compile(r'^[a-zA-Z0-9._/\-:]+$')
    if safe_pattern.match(candidate):
        return True, None

    return False, "Target format is not recognized (must be IP, CIDR, URL, or domain)."


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent directory traversal and injection."""
    # Remove path separators
    filename = filename.replace('/', '').replace('\\', '').replace('..', '')
    
    # Remove dangerous characters
    filename = re.sub(r'[<>:"|?*\x00-\x1f]', '', filename)
    
    # Limit length
    filename = filename[:255]
    
    # Ensure it's not empty
    if not filename:
        filename = "file"
    
    return filename


def detect_suspicious_activity(user_input: str) -> Tuple[bool, Optional[str]]:
    """Detect potentially malicious input patterns."""
    suspicious_patterns = [
        (r'eval\s*\(', "Potential code execution attempt"),
        (r'exec\s*\(', "Potential code execution attempt"),
        (r'system\s*\(', "Potential system command execution"),
        (r'subprocess', "Potential subprocess execution"),
        (r'import\s+os|import\s+subprocess', "Potential dangerous import"),
        (r'__import__', "Potential dynamic import"),
        (r'base64\.b64decode', "Potential obfuscated payload"),
        (r'pickle\.loads', "Potential deserialization attack"),
    ]
    
    for pattern, description in suspicious_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, description
    
    return False, None


def validate_port(port_str: str) -> Tuple[bool, Optional[str]]:
    """Validate port number."""
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return True, None
        return False, "Port must be between 1 and 65535"
    except ValueError:
        return False, "Port must be a valid integer"


def validate_port_range(port_range: str) -> Tuple[bool, Optional[str]]:
    """Validate port range (e.g., '80-443', '80,443,8080')."""
    # Single port
    if port_range.isdigit():
        return validate_port(port_range)
    
    # Range format: 80-443
    if '-' in port_range:
        parts = port_range.split('-')
        if len(parts) == 2:
            start_valid, start_error = validate_port(parts[0])
            end_valid, end_error = validate_port(parts[1])
            if start_valid and end_valid:
                if int(parts[0]) <= int(parts[1]):
                    return True, None
                return False, "Start port must be less than or equal to end port"
            return False, start_error or end_error
    
    # Comma-separated list
    if ',' in port_range:
        ports = port_range.split(',')
        for port in ports:
            valid, error = validate_port(port.strip())
            if not valid:
                return False, error
        return True, None
    
    return False, "Invalid port range format"


__all__ = [
    "validate_ip_address",
    "validate_cidr",
    "validate_url",
    "validate_scan_target_enhanced",
    "sanitize_filename",
    "detect_suspicious_activity",
    "validate_port",
    "validate_port_range",
]
