"""
T5 — Lateral Movement Topology
East-West path detection: edges within the same zone (internal→internal).
Blast radius: from a host, all reachable nodes in N hops, grouped by type.
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class BlastRadiusInfo:
    host: str
    total_reachable: int
    hop_distribution: Dict[int, int]
    type_distribution: Dict[str, int]


@dataclass
class LateralMovementResult:
    nodes: List[Dict]
    edges: List[Dict]
    east_west_count: int
    blast_radii: List[Dict]
    lateral_risk_score: float
    total_edges: int


def _bfs_reachable(
    adj: Dict[str, Set[str]],
    start: str,
    max_hops: int = 5,
) -> Dict[int, List[str]]:
    """BFS from start, return nodes grouped by hop distance."""
    reachable: Dict[int, List[str]] = {}
    visited: Dict[str, int] = {start: 0}
    queue = [(start, 0)]

    while queue:
        current, hops = queue.pop(0)
        if hops > max_hops:
            continue
        if hops > 0:
            reachable.setdefault(hops, []).append(current)
        for neighbor in adj.get(current, set()):
            if neighbor not in visited:
                visited[neighbor] = hops + 1
                queue.append((neighbor, hops + 1))

    return reachable


def analyze_lateral_movement(
    nodes: List[Dict],
    edges: List[Dict],
    blast_hosts: Optional[List[str]] = None,
    max_hops: int = 4,
) -> LateralMovementResult:
    """
    Analyze lateral movement potential.

    Identifies East-West edges (same zone) and calculates blast radius
    from specified hosts (or hosts with high connectivity).
    """
    # Build zone lookup
    node_zones: Dict[str, str] = {}
    node_types: Dict[str, str] = {}
    for node in nodes:
        nid = node.get("id", "")
        node_zones[nid] = node.get("group", node.get("zone", "unknown"))
        node_types[nid] = node.get("type", "unknown")

    # Build adjacency (undirected for lateral movement)
    adj: Dict[str, Set[str]] = defaultdict(set)
    all_node_ids = {n["id"] for n in nodes}
    for edge in edges:
        src = edge.get("from", "")
        dst = edge.get("to", "")
        if src in all_node_ids and dst in all_node_ids:
            adj[src].add(dst)
            adj[dst].add(src)

    # Classify East-West edges
    east_west_count = 0
    enriched_edges: List[Dict] = []
    for idx, edge in enumerate(edges):
        src = edge.get("from", "")
        dst = edge.get("to", "")
        src_zone = node_zones.get(src, "unknown")
        dst_zone = node_zones.get(dst, "unknown")
        risk = edge.get("risk", 0)
        edge_id = edge.get("id", f"lm-{src}-{dst}-{idx}")

        is_ew = src_zone == dst_zone
        if is_ew:
            east_west_count += 1

        # Check if both are internal zones
        both_internal = all(
            "external" not in (node_zones.get(n) or "").lower()
            and "outside" not in (node_zones.get(n) or "").lower()
            and "dmz" not in (node_zones.get(n) or "").lower()
            for n in (src, dst)
        )

        color = "#e94560" if (is_ew and both_internal and risk >= 5) else \
                "#f59e0b" if is_ew else \
                edge.get("color", "#666")
        width = 3 if (is_ew and both_internal and risk >= 5) else 2 if is_ew else 1

        enriched = {
            "id": edge_id,
            "from": src,
            "to": dst,
            "is_east_west": is_ew,
            "internal": both_internal,
            "color": color,
            "width": width,
            "risk": risk,
            "title": f"{'↔️ E-W ' if is_ew else ''}{src} → {dst}<br>Risk: {risk}",
        }
        enriched_edges.append(enriched)

    # Blast radius calculation
    if not blast_hosts:
        # Pick hosts with highest degree as blast sources
        sorted_hosts = sorted(
            [n for n in nodes if n.get("type") in ("host", "server")],
            key=lambda n: len(adj.get(n["id"], set())),
            reverse=True,
        )
        blast_hosts = [h["id"] for h in sorted_hosts[:5]]

    blast_results: List[Dict] = []
    for host in blast_hosts:
        reachable = _bfs_reachable(adj, host, max_hops)
        hop_dist: Dict[int, int] = {}
        type_dist: Dict[str, int] = {}
        total = 0

        for hop, nodelist in reachable.items():
            hop_dist[hop] = len(nodelist)
            total += len(nodelist)
            for nid in nodelist:
                ntype = node_types.get(nid, "unknown")
                type_dist[ntype] = type_dist.get(ntype, 0) + 1

        blast_results.append({
            "host": host,
            "total_reachable": total,
            "hop_distribution": {str(k): v for k, v in sorted(hop_dist.items())},
            "type_distribution": type_dist,
            "severity": "critical" if total > 50 else "high" if total > 20 else "medium",
        })

    # Enrich nodes
    enriched_nodes: List[Dict] = []
    ew_node_count: Dict[str, int] = defaultdict(int)
    for e in enriched_edges:
        if e["is_east_west"]:
            ew_node_count[e["from"]] += 1
            ew_node_count[e["to"]] += 1

    for node in nodes:
        nid = node["id"]
        ew_conn = ew_node_count.get(nid, 0)
        color = "#e94560" if ew_conn >= 5 else \
                "#f59e0b" if ew_conn >= 2 else \
                node.get("color", "#90EE90")
        size = 25 + ew_conn * 3

        enriched = dict(node)
        enriched["color"] = color
        enriched["size"] = size
        enriched["ew_connections"] = ew_conn
        enriched["title"] = f"{node.get('title', nid)}<br>E-W connections: {ew_conn}"
        enriched_nodes.append(enriched)

    # Lateral risk score
    total_e = len(edges)
    lateral_risk = round(east_west_count / max(1, total_e) * 100, 1) if total_e else 0

    return LateralMovementResult(
        nodes=enriched_nodes,
        edges=enriched_edges,
        east_west_count=east_west_count,
        blast_radii=blast_results,
        lateral_risk_score=lateral_risk,
        total_edges=len(enriched_edges),
    )
