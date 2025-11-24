import os
import secrets
import warnings

from dotenv import load_dotenv

load_dotenv()


def _generate_dev_secret() -> str:
    return secrets.token_urlsafe(32)


def _require_secret() -> str:
    """Return a secure secret key with guardrails for production."""

    env_secret = os.environ.get("SECRET_KEY")
    env = os.environ.get("FLASK_ENV", "development").lower()

    if env_secret:
        if env_secret == "dev-secret":
            warnings.warn("Using weak default SECRET_KEY; set a strong value in production.")
        return env_secret

    if env == "production":
        raise RuntimeError("SECRET_KEY environment variable is required in production")

    generated = _generate_dev_secret()
    warnings.warn("SECRET_KEY not set; generated a temporary development key.")
    return generated


ENGAGEMENT_TOKEN: str | None = os.environ.get("ENGAGEMENT_TOKEN")
SECRET_KEY: str = _require_secret()
DATABASE: str = os.environ.get("DATABASE", "logs/cybercheck.db")
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

# CLI tools allowed
ALLOWED_TOOLS = [
    "nmap",
    "nikto",
    "bandit",
    "pip-audit",
    "safety",
    "scapy",
    "ettercap",
    # App/API security
    "zap-baseline.py",
    "zap-api-scan.py",
    "zap-full-scan.py",
    # Secrets and credential hygiene
    "gitleaks",
    "trufflehog",
    # Supply chain and IaC
    "trivy",
    "grype",
    "checkov",
    # Forensics
    "volatility3",
    # OSINT
    "sf",
]

# Timeout defaults (seconds)
DEFAULT_TIMEOUT = 300

# Predefined nmap profiles: label -> list(args)
NMAP_PROFILES = {
    "standard": ["-sV", "-Pn", "-T4"],
    "top-ports": ["--top-ports", "100", "-sV", "-Pn"],
    "full-tcp": ["-p-", "-sV", "-Pn", "-T3"],
    "udp": ["-sU", "-Pn", "-T3"],
    "quick": ["-F", "-sV", "-Pn"],
    "udp-discovery": ["-sU", "--top-ports", "50", "-Pn", "-T2"],
    "http-enum": ["-sV", "-p", "80,443,8080", "--script", "http-enum", "-Pn", "-T3"],
    # Potentially intrusive; only use with explicit authorization.
    "vuln-scan": ["-sV", "-Pn", "--script", "vuln", "-T3"],
}
