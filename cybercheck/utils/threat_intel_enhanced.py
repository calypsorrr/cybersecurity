"""Enhanced threat intelligence and monitoring utilities."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
import hashlib

from cybercheck.utils.logging import get_logger

logger = get_logger(__name__)

try:
    from datetime import UTC
except ImportError:
    from datetime import timezone as _tz
    UTC = _tz.utc


class ThreatIntelligence:
    """Enhanced threat intelligence collector and analyzer."""
    
    def __init__(self):
        self.ip_reputation: Dict[str, Dict] = {}
        self.domain_reputation: Dict[str, Dict] = {}
        self.malware_hashes: set = set()
        self.suspicious_patterns: deque = deque(maxlen=1000)
        self.attack_indicators: List[Dict] = []
        
    def analyze_network_activity(self, activity: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network activity for threat indicators."""
        indicators = []
        severity = "info"
        
        # Check for port scanning patterns
        if activity.get("port_scan_suspected"):
            indicators.append({
                "type": "port_scan",
                "description": "Potential port scanning activity detected",
                "severity": "medium"
            })
            severity = "medium"
        
        # Check for unusual traffic volume
        if activity.get("traffic_volume") > 10000:
            indicators.append({
                "type": "high_volume",
                "description": "Unusually high network traffic volume",
                "severity": "low"
            })
        
        # Check for known malicious IPs
        src_ip = activity.get("source_ip")
        if src_ip and src_ip in self.ip_reputation:
            rep = self.ip_reputation[src_ip]
            if rep.get("threat_score", 0) > 7:
                indicators.append({
                    "type": "malicious_ip",
                    "description": f"Traffic from known malicious IP: {src_ip}",
                    "severity": "high"
                })
                severity = "high"
        
        return {
            "indicators": indicators,
            "severity": severity,
            "timestamp": datetime.now(UTC).isoformat()
        }
    
    def check_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against known malware signatures."""
        hash_upper = file_hash.upper()
        hash_lower = file_hash.lower()
        
        # Check against known malware hashes (would integrate with VirusTotal, etc.)
        if hash_upper in self.malware_hashes or hash_lower in self.malware_hashes:
            return {
                "malicious": True,
                "confidence": "high",
                "reason": "Known malware hash",
                "timestamp": datetime.now(UTC).isoformat()
            }
        
        return {
            "malicious": False,
            "confidence": "low",
            "timestamp": datetime.now(UTC).isoformat()
        }
    
    def detect_anomalies(self, metrics: Dict[str, Any], baseline: Optional[Dict] = None) -> List[Dict]:
        """Detect anomalies in network or system metrics."""
        anomalies = []
        
        if baseline is None:
            baseline = {
                "avg_packet_rate": 100,
                "avg_connections": 50,
                "common_ports": [80, 443, 22, 53]
            }
        
        # Check packet rate anomalies
        if metrics.get("packet_rate", 0) > baseline["avg_packet_rate"] * 3:
            anomalies.append({
                "type": "high_packet_rate",
                "severity": "medium",
                "description": f"Packet rate ({metrics['packet_rate']}) significantly above baseline"
            })
        
        # Check for unusual ports
        if "active_ports" in metrics:
            unusual_ports = set(metrics["active_ports"]) - set(baseline["common_ports"])
            if unusual_ports:
                anomalies.append({
                    "type": "unusual_ports",
                    "severity": "low",
                    "description": f"Unusual ports detected: {unusual_ports}",
                    "ports": list(unusual_ports)
                })
        
        return anomalies


class AttackSurfaceAnalyzer:
    """Analyze attack surface and exposure."""
    
    def analyze_exposure(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results to determine attack surface."""
        exposure_score = 0
        findings = []
        
        # Open ports increase exposure
        open_ports = scan_results.get("open_ports", [])
        exposure_score += len(open_ports) * 2
        
        # High-risk ports
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 6379]
        exposed_high_risk = [p for p in open_ports if p in high_risk_ports]
        if exposed_high_risk:
            exposure_score += len(exposed_high_risk) * 5
            findings.append({
                "type": "high_risk_ports",
                "ports": exposed_high_risk,
                "severity": "high"
            })
        
        # Outdated services
        outdated_services = scan_results.get("outdated_services", [])
        if outdated_services:
            exposure_score += len(outdated_services) * 3
            findings.append({
                "type": "outdated_services",
                "services": outdated_services,
                "severity": "medium"
            })
        
        # Weak encryption
        weak_encryption = scan_results.get("weak_encryption", [])
        if weak_encryption:
            exposure_score += len(weak_encryption) * 4
            findings.append({
                "type": "weak_encryption",
                "details": weak_encryption,
                "severity": "high"
            })
        
        return {
            "exposure_score": min(exposure_score, 100),  # Cap at 100
            "findings": findings,
            "open_ports": open_ports,
            "recommendations": self._generate_recommendations(findings)
        }
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        for finding in findings:
            if finding["type"] == "high_risk_ports":
                recommendations.append(
                    f"Close or restrict access to high-risk ports: {', '.join(map(str, finding['ports']))}"
                )
            elif finding["type"] == "outdated_services":
                recommendations.append(
                    "Update outdated services to latest versions with security patches"
                )
            elif finding["type"] == "weak_encryption":
                recommendations.append(
                    "Upgrade to stronger encryption protocols (TLS 1.3, disable weak ciphers)"
                )
        
        return recommendations


# Global instances
threat_intel = ThreatIntelligence()
attack_surface_analyzer = AttackSurfaceAnalyzer()

