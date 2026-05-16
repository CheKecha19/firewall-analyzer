"""
T3 — Redundancy/Resilience Topology
SPOF detection: nodes with degree=1, critical paths without alternatives.
Redundancy scoring: independent paths → R_score 0-10.
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class SPOF:
    node_id: str
    node_label: str
    reason: str
    severity: str


@dataclass
class ResilienceResult:
    nodes: List[Dict]
    edges: List[Dict]
    spofs: List[Dict]
    redundancy_scores: Dict[str, int]
    total_nodes: int


def _count_disjoint_paths(adj: Dict[str, Set[str]], src: str, dst: str, max_paths: int = 10) -> int:
    """Count node-disjoint paths between src and dst (simplified BFS-based)."""
    if src == dst:
        return 0
    if src not in adj or dst not in adj:
        return 0

    # Simplified: count edge-disjoint by removing used edges
    paths_found = 0
    used_edges: Set[str] = set()

    for _ in range(max_paths):
        # BFS with edge tracking
        queue = [(src, [])]
        visited = {src}
        found = False
        while queue and not found:
            current, path = queue.pop(0)
            if current == dst:
                # Mark edges as used
                for u, v in path:
                    used_edges.add(f"{u}->{v}")
                    used_edges.add(f"{v}->{u}")
                paths_found += 1
                found = True
                break
            for neighbor in adj.get(current, set()):
                edge_key = f"{current}->{neighbor}"
                if neighbor not in visited and edge_key not in used_edges:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [(current, neighbor)]))
        if not found:
            break

    return paths_found


def analyze_resilience(
    nodes: List[Dict],
    edges: List[Dict],
) -> ResilienceResult:
    """
    Analyze resilience: find SPOFs, calculate redundancy scores.

    SPOF detection: nodes with only 1 connection (degree=1).
    Redundancy score: based on number of alternative paths to critical neighbors.
    """
    # Build adjacency
    adj: Dict[str, Set[str]] = defaultdict(set)
    all_node_ids = {n["id"] for n in nodes}
    for edge in edges:
        src = edge.get("from", "")
        dst = edge.get("to", "")
        if src in all_node_ids and dst in all_node_ids:
            adj[src].add(dst)
            adj[dst].add(src)

    # SPOF detection
    spofs: List[Dict] = []
    spof_ids: Set[str] = set()

    for node in nodes:
        nid = node["id"]
        degree = len(adj.get(nid, set()))
        if degree == 0:
            spofs.append({
                "node_id": nid,
                "node_label": node.get("label", nid),
                "reason": "Isolated node — no connections",
                "severity": "medium",
            })
            spof_ids.add(nid)
        elif degree == 1:
            spofs.append({
                "node_id": nid,
                "node_label": node.get("label", nid),
                "reason": "Single point of failure — only one connection",
                "severity": "high",
            })
            spof_ids.add(nid)

    # Redundancy scoring
    redundancy_scores: Dict[str, int] = {}
    critical_nodes = [
        n["id"] for n in nodes
        if n.get("type") in ("host", "server") or "critical" in str(n.get("title", "")).lower()
    ]
    if not critical_nodes:
        critical_nodes = [n["id"] for n in nodes[:min(10, len(nodes))]]

    for node in nodes:
        nid = node["id"]
        # Average disjoint paths to critical nodes
        path_counts = []
        for cn in critical_nodes:
            if cn == nid:
                continue
            paths = _count_disjoint_paths(adj, nid, cn, max_paths=10)
            path_counts.append(paths)

        if path_counts:
            avg_paths = sum(path_counts) / len(path_counts)
        else:
            avg_paths = 0

        # Scale: 0 paths → score 0, 3+ paths → score 10
        score = min(10, int(avg_paths * 3.3))
        redundancy_scores[nid] = score

    # Enrich nodes
    enriched_nodes: List[Dict] = []
    for node in nodes:
        nid = node["id"]
        score = redundancy_scores.get(nid, 5)
        is_spof = nid in spof_ids

        color = "#e94560" if is_spof else (
            "#10b981" if score >= 8 else "#f59e0b" if score >= 4 else "#e94560"
        )
        size = 35 if is_spof else (20 + score * 2)

        enriched = dict(node)
        enriched["color"] = color
        enriched["size"] = size
        enriched["redundancy_score"] = score
        enriched["is_spof"] = is_spof
        enriched["title"] = (
            f"{'⚠️ SPOF! ' if is_spof else ''}"
            f"R-Score: {score}/10 | Degree: {len(adj.get(nid, set()))}"
        )
        enriched_nodes.append(enriched)

    # Enrich edges
    enriched_edges: List[Dict] = []
    for edge in edges:
        src = edge.get("from", "")
        dst = edge.get("to", "")
        src_spof = src in spof_ids
        dst_spof = dst in spof_ids

        color = "#e94560" if (src_spof or dst_spof) else edge.get("color", "#666")
        width = 3 if (src_spof or dst_spof) else edge.get("width", 1)

        enriched = dict(edge)
        enriched["color"] = color
        enriched["width"] = width
        enriched_edges.append(enriched)

    return ResilienceResult(
        nodes=enriched_nodes,
        edges=enriched_edges,
        spofs=spofs,
        redundancy_scores=redundancy_scores,
        total_nodes=len(nodes),
    )
