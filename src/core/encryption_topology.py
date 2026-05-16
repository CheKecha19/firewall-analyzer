"""
T4 — Protocol/Encryption Topology
Maps ports → encryption level (TLS 1.3, TLS 1.2, plaintext, unknown).
Calculates encryption coverage %.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


ENCRYPTION_LEVELS = {
    "TLS 1.3": 3,
    "TLS 1.2": 2,
    "TLS 1.1": 1,
    "TLS 1.0": 1,
    "SSL": 0,
    "PLAINTEXT": -1,
    "UNKNOWN": 0,
}


# Port → encryption level map
PORT_ENCRYPTION: Dict[int, str] = {
    # TLS 1.3 capable
    443: "TLS 1.3",
    8443: "TLS 1.3",
    636: "TLS 1.3",    # LDAPS
    3269: "TLS 1.3",   # GC LDAPS
    993: "TLS 1.3",    # IMAPS
    995: "TLS 1.3",    # POP3S
    465: "TLS 1.3",    # SMTPS
    # TLS 1.2
    587: "TLS 1.2",    # SMTP submission
    5061: "TLS 1.2",   # SIP TLS
    # Plaintext — common unencrypted ports
    80: "PLAINTEXT",
    8080: "PLAINTEXT",
    21: "PLAINTEXT",
    23: "PLAINTEXT",
    25: "PLAINTEXT",
    110: "PLAINTEXT",
    143: "PLAINTEXT",
    161: "PLAINTEXT",
    389: "PLAINTEXT",
    514: "PLAINTEXT",
    3306: "PLAINTEXT",
    5432: "PLAINTEXT",
    1433: "PLAINTEXT",
    1521: "PLAINTEXT",
    6379: "PLAINTEXT",
    27017: "PLAINTEXT",
    11211: "PLAINTEXT",
}


ENCRYPTION_COLORS = {
    "TLS 1.3": "#10b981",
    "TLS 1.2": "#34d399",
    "TLS 1.1": "#f59e0b",
    "TLS 1.0": "#f97316",
    "SSL": "#ef4444",
    "PLAINTEXT": "#e94560",
    "UNKNOWN": "#6b7280",
}


@dataclass
class EncryptionResult:
    nodes: List[Dict]
    edges: List[Dict]
    encryption_summary: Dict[str, int]
    coverage_percent: float
    total_edges: int


def classify_encryption(port: Any, service_name: str = "") -> str:
    """Classify a connection's encryption level based on port."""
    if port is not None:
        try:
            p = int(port)
            if p in PORT_ENCRYPTION:
                return PORT_ENCRYPTION[p]
        except (ValueError, TypeError):
            pass

    # Service name hints
    svc = (service_name or "").lower()
    if "https" in svc or "tls" in svc:
        return "TLS 1.3"
    if "ssh" in svc:
        return "TLS 1.3"
    if "http" in svc:
        return "PLAINTEXT"

    return "UNKNOWN"


def analyze_encryption(
    nodes: List[Dict],
    edges: List[Dict],
) -> EncryptionResult:
    """
    Analyze encryption coverage of all edges.

    Returns enriched edges with encryption level and coverage statistics.
    """
    enriched_edges: List[Dict] = []
    summary: Dict[str, int] = {}
    encrypted_count = 0
    total_with_classification = 0

    for edge in edges:
        src = edge.get("from", "")
        dst = edge.get("to", "")
        port = edge.get("port", None)
        svc = edge.get("service", "")
        risk = edge.get("risk", 0)

        enc_level = classify_encryption(port, svc)

        color = ENCRYPTION_COLORS.get(enc_level, "#6b7280")
        width = 2 if enc_level == "PLAINTEXT" else 1.5

        enriched = {
            "from": src,
            "to": dst,
            "encryption": enc_level,
            "color": color,
            "width": width,
            "risk": risk,
            "title": f"🔐 {enc_level} | Port: {port or 'any'} | Risk: {risk}",
        }
        enriched_edges.append(enriched)
        summary[enc_level] = summary.get(enc_level, 0) + 1
        total_with_classification += 1

        if enc_level in ("TLS 1.3", "TLS 1.2"):
            encrypted_count += 1

    coverage = round(encrypted_count / max(1, total_with_classification) * 100, 1) if total_with_classification else 0

    # Enrich nodes — mark nodes with mostly plaintext connections
    node_plaintext_ratio: Dict[str, float] = {}
    node_total: Dict[str, int] = {}
    for edge_data in enriched_edges:
        for nid in (edge_data["from"], edge_data["to"]):
            node_total[nid] = node_total.get(nid, 0) + 1
            if edge_data["encryption"] == "PLAINTEXT":
                node_plaintext_ratio[nid] = node_plaintext_ratio.get(nid, 0) + 1

    enriched_nodes: List[Dict] = []
    for node in nodes:
        nid = node["id"]
        total = node_total.get(nid, 0)
        plain = node_plaintext_ratio.get(nid, 0)
        ratio = plain / max(1, total)

        color = "#e94560" if ratio > 0.5 else \
                "#f59e0b" if ratio > 0.2 else \
                "#10b981" if total > 0 else \
                node.get("color", "#D3D3D3")

        enriched = dict(node)
        enriched["color"] = color
        enriched["plaintext_ratio"] = round(ratio, 2)
        enriched["title"] = f"{node.get('title', nid)}<br>Plaintext: {plain}/{total} edges"
        enriched_nodes.append(enriched)

    return EncryptionResult(
        nodes=enriched_nodes,
        edges=enriched_edges,
        encryption_summary=summary,
        coverage_percent=coverage,
        total_edges=len(enriched_edges),
    )
