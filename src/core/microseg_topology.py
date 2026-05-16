"""
T6 — Micro-segmentation Topology (Zero Trust)
Intra-zone analysis: inter-host connections within a zone.
Microseg readiness score, deny-rule generation for micro-segmentation.
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class IntraZoneConnection:
    source: str
    target: str
    zone: str
    risk: float
    ports: List[str]


@dataclass
class MicrosegResult:
    nodes: List[Dict]
    edges: List[Dict]
    readiness_score: float
    zone_analysis: Dict[str, Dict]
    generated_deny_rules: List[Dict]
    intra_zone_edges: int
    total_edges: int


def analyze_microseg(
    nodes: List[Dict],
    edges: List[Dict],
) -> MicrosegResult:
    """
    Analyze micro-segmentation readiness.

    Identifies intra-zone connections between hosts, calculates
    readiness score, and generates suggested deny rules for
    unnecessary intra-zone traffic.
    """
    # Build zone/type lookup
    node_zones: Dict[str, str] = {}
    node_types: Dict[str, str] = {}
    for node in nodes:
        nid = node.get("id", "")
        node_zones[nid] = node.get("group", node.get("zone", "unknown"))
        node_types[nid] = node.get("type", "unknown")

    # Classify edges
    intra_zone_connections: List[IntraZoneConnection] = []
    enriched_edges: List[Dict] = []
    zone_ew: Dict[str, int] = defaultdict(int)  # East-West per zone
    zone_all: Dict[str, int] = defaultdict(int)  # All edges per zone

    for edge in edges:
        src = edge.get("from", "")
        dst = edge.get("to", "")
        src_zone = node_zones.get(src, "unknown")
        dst_zone = node_zones.get(dst, "unknown")
        risk = edge.get("risk", 0)
        port = edge.get("port", "any")
        svc = edge.get("service", "")

        is_intra = src_zone == dst_zone
        is_host_to_host = (
            node_types.get(src) in ("host", "server")
            and node_types.get(dst) in ("host", "server")
        )

        zone_all[src_zone] += 1

        if is_intra and is_host_to_host:
            intra_zone_connections.append(IntraZoneConnection(
                source=src, target=dst, zone=src_zone,
                risk=risk, ports=[str(port)],
            ))
            zone_ew[src_zone] += 1

        color = "#e94560" if (is_intra and is_host_to_host and risk >= 5) else \
                "#f59e0b" if is_intra and is_host_to_host else \
                "#10b981" if is_intra else \
                edge.get("color", "#666")
        width = 3 if (is_intra and is_host_to_host) else 1

        enriched = {
            "from": src, "to": dst,
            "is_intra_zone": is_intra,
            "is_host_to_host": is_host_to_host,
            "zone": src_zone,
            "color": color, "width": width, "risk": risk,
            "title": f"{'🔬 Intra-Zone ' if is_intra and is_host_to_host else ''}"
                     f"{src} → {dst} | Zone: {src_zone} | Risk: {risk}",
        }
        enriched_edges.append(enriched)

    # Microseg readiness score: 100 - (unprotected E-W / total) * 100
    total_ew = sum(zone_ew.values())
    total_all = sum(zone_all.values())
    if total_all > 0:
        readiness = max(0, 100 - (total_ew / total_all) * 100)
    else:
        readiness = 100.0

    # Zone-level analysis
    zone_analysis: Dict[str, Dict] = {}
    for zone, ew_count in zone_ew.items():
        total = zone_all.get(zone, 1)
        zone_analysis[zone] = {
            "intra_zone_edges": ew_count,
            "total_edges": total,
            "ratio": round(ew_count / max(1, total), 2),
            "readiness": max(0, round(100 - (ew_count / max(1, total)) * 100, 1)),
        }

    # Generate deny rules for high-risk intra-zone connections
    generate_deny_rules: List[Dict] = []
    for conn in intra_zone_connections:
        if conn.risk >= 5:  # Only high-risk connections
            generate_deny_rules.append({
                "priority": conn.risk,
                "source": conn.source,
                "destination": conn.target,
                "service": ", ".join(conn.ports),
                "action": "deny",
                "zone": conn.zone,
                "reason": f"Micro-segmentation: restrict intra-zone traffic (risk={conn.risk})",
            })

    # Enrich nodes
    enriched_nodes: List[Dict] = []
    node_intra: Dict[str, int] = defaultdict(int)
    for e in enriched_edges:
        if e["is_intra_zone"] and e["is_host_to_host"]:
            node_intra[e["from"]] += 1
            node_intra[e["to"]] += 1

    for node in nodes:
        nid = node["id"]
        intra = node_intra.get(nid, 0)
        color = "#e94560" if intra >= 5 else \
                "#f59e0b" if intra >= 2 else \
                "#10b981" if intra == 0 else \
                node.get("color", "#87CEEB")
        size = 20 + intra * 4

        enriched = dict(node)
        enriched["color"] = color
        enriched["size"] = size
        enriched["intra_connections"] = intra
        enriched["title"] = f"{node.get('title', nid)}<br>Intra-zone links: {intra}"
        enriched_nodes.append(enriched)

    return MicrosegResult(
        nodes=enriched_nodes,
        edges=enriched_edges,
        readiness_score=round(readiness, 1),
        zone_analysis=zone_analysis,
        generated_deny_rules=generate_deny_rules,
        intra_zone_edges=total_ew,
        total_edges=len(enriched_edges),
    )
