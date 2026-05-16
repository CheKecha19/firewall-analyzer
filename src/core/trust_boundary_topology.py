"""
T2 — Trust Boundary Topology
Classifies edges: intra-zone, inter-zone, external.
Detects perimeter holes: outside→inside edges.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


BOUNDARY_COLORS = {
    "intra-zone": "#10b981",   # green — safe
    "inter-zone": "#f59e0b",   # amber — needs review
    "external": "#e94560",     # red — critical
    "unknown": "#6b7280",      # gray
}


@dataclass
class TrustBoundaryResult:
    nodes: List[Dict]
    edges: List[Dict]
    perimeter_holes: List[Dict]
    boundary_summary: Dict[str, int]
    total_edges: int


def _is_external(zone: str) -> bool:
    """Check if zone is external/untrusted."""
    if zone is None:
        return False
    zone_lower = zone.lower().strip()
    external_keywords = ["external", "outside", "internet", "untrust", "dmz", "guest", "public"]
    return any(kw in zone_lower for kw in external_keywords)


def _is_internal(zone: str) -> bool:
    """Check if zone is internal/trusted."""
    return not _is_external(zone)


def classify_boundary(src_zone: str, dst_zone: str) -> str:
    """Classify edge by trust boundary."""
    if src_zone == dst_zone:
        return "intra-zone"

    src_ext = _is_external(src_zone)
    dst_ext = _is_external(dst_zone)

    if src_ext or dst_ext:
        return "external"

    return "inter-zone"


def analyze_trust_boundary(
    nodes: List[Dict],
    edges: List[Dict],
) -> TrustBoundaryResult:
    """
    Analyze trust boundary topology.

    Classifies each edge by zone membership and identifies perimeter holes
    (external→internal connections that represent potential attack vectors).
    """
    # Build zone lookup
    node_zones: Dict[str, str] = {}
    for node in nodes:
        nid = node.get("id", "")
        zone = node.get("group", node.get("zone", "unknown"))
        node_zones[nid] = zone

    boundary_colors = BOUNDARY_COLORS
    enriched_edges: List[Dict] = []
    boundary_summary: Dict[str, int] = {}
    perimeter_holes: List[Dict] = []

    for idx, edge in enumerate(edges):
        src = edge.get("from", "")
        dst = edge.get("to", "")
        src_zone = node_zones.get(src, "unknown")
        dst_zone = node_zones.get(dst, "unknown")
        risk = edge.get("risk", 0)
        edge_id = edge.get("id", f"tb-{src}-{dst}-{idx}")

        boundary = classify_boundary(src_zone, dst_zone)

        color = boundary_colors.get(boundary, "#6b7280")
        width = 3 if boundary == "external" else 1.5

        enriched = {
            "id": edge_id,
            "from": src,
            "to": dst,
            "boundary": boundary,
            "src_zone": src_zone,
            "dst_zone": dst_zone,
            "color": color,
            "width": width,
            "risk": risk,
            "title": f"[{boundary.upper()}] {src} ({src_zone}) → {dst} ({dst_zone})<br>Risk: {risk}",
        }
        enriched_edges.append(enriched)
        boundary_summary[boundary] = boundary_summary.get(boundary, 0) + 1

        # Detect perimeter holes: outside → inside
        if _is_external(src_zone) and _is_internal(dst_zone):
            perimeter_holes.append({
                "source": src,
                "source_zone": src_zone,
                "target": dst,
                "target_zone": dst_zone,
                "risk": risk,
                "severity": "critical" if risk >= 7 else "high",
            })

    # Enrich nodes
    zone_colors = {
        "external": "#e94560",
        "internal": "#10b981",
        "default": "#3b82f6",
    }
    enriched_nodes: List[Dict] = []
    for node in nodes:
        zone = node_zones.get(node.get("id", ""), "unknown")
        nzone_type = "internal" if _is_internal(zone) else "external"
        enriched = dict(node)
        enriched["trust_type"] = nzone_type
        enriched["color"] = zone_colors.get(nzone_type, zone_colors["default"])
        enriched["title"] = f"[{nzone_type.upper()}] {node.get('title', node.get('id', ''))}"
        enriched_nodes.append(enriched)

    return TrustBoundaryResult(
        nodes=enriched_nodes,
        edges=enriched_edges,
        perimeter_holes=perimeter_holes,
        boundary_summary=boundary_summary,
        total_edges=len(enriched_edges),
    )
