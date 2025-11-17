import os
from dotenv import load_dotenv

load_dotenv()

ENGAGEMENT_TOKEN: str | None = os.environ.get("ENGAGEMENT_TOKEN")
SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret")
DATABASE: str = os.environ.get("DATABASE", "logs/cybercheck.db")
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

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
