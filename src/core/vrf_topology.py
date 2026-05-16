"""
T7 — Multi-tenancy / VRF Topology
VRF detection from configs (ip vrf, vrf definition).
VRF leak detection via route-target intersection analysis.
Isolation scoring per tenant.
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class VRF:
    name: str
    rd: str  # Route Distinguisher
    route_targets: List[str]
    interfaces: List[str]
    nodes: List[str]


@dataclass
class VRFLeak:
    vrf_a: str
    vrf_b: str
    shared_rt: str
    severity: str


@dataclass
class VRFResult:
    nodes: List[Dict]
    edges: List[Dict]
    vrfs: List[Dict]
    leaks: List[Dict]
    isolation_scores: Dict[str, float]
    total_vrfs: int


def parse_vrfs_from_rules(
    rules: List[Dict],
    nodes: List[Dict],
) -> List[VRF]:
    """
    Parse VRF information from rule names and descriptions.
    Since we may not have raw Cisco configs, we extract VRF-like
    patterns from rule metadata and node naming conventions.
    """
    vrfs: Dict[str, VRF] = {}

    # Common tenant/VRF naming patterns in firewall rules
    vrf_patterns = [
        "vrf:", "tenant:", "vrf-", "tenant-",
        "customer_", "cust_", "client_",
    ]

    for rule in rules:
        name = rule.get("name", "")
        srcs = rule.get("sources", "")
        dsts = rule.get("destinations", "")

        for pat in vrf_patterns:
            if pat in name.lower():
                parts = name.lower().split(pat, 1)
                if len(parts) > 1:
                    vrf_name = parts[1].split()[0] if parts[1].strip() else "unknown"
                    if vrf_name not in vrfs:
                        vrfs[vrf_name] = VRF(
                            name=vrf_name,
                            rd=f"auto:{vrf_name}",
                            route_targets=[],
                            interfaces=[],
                            nodes=[],
                        )
                    vrfs[vrf_name].nodes.extend(
                        s.strip() for s in (srcs + "," + dsts).split(",") if s.strip()
                    )

    return list(vrfs.values())


def detect_vrf_leaks(vrfs: List[VRF]) -> List[VRFLeak]:
    """Detect VRF leaks by shared route targets."""
    leaks: List[VRFLeak] = []
    rt_to_vrfs: Dict[str, Set[str]] = defaultdict(set)

    for vrf in vrfs:
        for rt in vrf.route_targets:
            rt_to_vrfs[rt].add(vrf.name)

    for rt, vrf_names in rt_to_vrfs.items():
        if len(vrf_names) > 1:
            vlist = list(vrf_names)
            for i in range(len(vlist)):
                for j in range(i + 1, len(vlist)):
                    leaks.append(VRFLeak(
                        vrf_a=vlist[i],
                        vrf_b=vlist[j],
                        shared_rt=rt,
                        severity="high",
                    ))

    # Also check for node-level overlaps (same node in multiple VRFs)
    node_vrfs: Dict[str, Set[str]] = defaultdict(set)
    for vrf in vrfs:
        for node in vrf.nodes:
            node_vrfs[node].add(vrf.name)

    for node, vrf_set in node_vrfs.items():
        if len(vrf_set) > 1:
            vlist = list(vrf_set)
            for i in range(len(vlist)):
                for j in range(i + 1, len(vlist)):
                    existing = False
                    for leak in leaks:
                        if (leak.vrf_a == vlist[i] and leak.vrf_b == vlist[j]) or \
                           (leak.vrf_a == vlist[j] and leak.vrf_b == vlist[i]):
                            existing = True
                            break
                    if not existing:
                        leaks.append(VRFLeak(
                            vrf_a=vlist[i], vrf_b=vlist[j],
                            shared_rt=f"node:{node}",
                            severity="critical",
                        ))

    return leaks


def analyze_vrf(
    nodes: List[Dict],
    edges: List[Dict],
    rules: Optional[List[Dict]] = None,
    config_vrfs: Optional[List[Dict]] = None,
) -> VRFResult:
    """
    Analyze VRF/multi-tenancy topology.

    Identifies VRFs from configs/rules, detects leaks between tenants,
    calculates isolation scores.
    """
    rules = rules or []

    # Parse VRFs
    vrfs: List[VRF] = []

    # From explicit config VRFs
    if config_vrfs:
        for cv in config_vrfs:
            vrfs.append(VRF(
                name=cv.get("name", "unknown"),
                rd=cv.get("rd", ""),
                route_targets=cv.get("route_targets", []),
                interfaces=cv.get("interfaces", []),
                nodes=cv.get("nodes", []),
            ))

    # From rule patterns
    rule_vrfs = parse_vrfs_from_rules(rules, nodes)
    existing_names = {v.name for v in vrfs}
    for rv in rule_vrfs:
        if rv.name not in existing_names:
            vrfs.append(rv)
            existing_names.add(rv.name)

    # Detect leaks
    leaks = detect_vrf_leaks(vrfs)

    # Isolation scoring per tenant
    isolation_scores: Dict[str, float] = {}
    for vrf in vrfs:
        # Score: number of unique nodes / number of cross-VRF connections
        unique_nodes = len(set(vrf.nodes))
        leak_count = sum(1 for l in leaks if l.vrf_a == vrf.name or l.vrf_b == vrf.name)
        if unique_nodes > 0:
            score = max(0, 100 - (leak_count * 20))
        else:
            score = 100.0
        isolation_scores[vrf.name] = round(score, 1)

    # Enrich nodes with VRF membership
    node_vrf: Dict[str, Set[str]] = defaultdict(set)
    for vrf in vrfs:
        for nid in vrf.nodes:
            node_vrf[nid].add(vrf.name)

    enriched_nodes: List[Dict] = []
    for node in nodes:
        nid = node["id"]
        member_vrfs = node_vrf.get(nid, set())
        is_multi_vrf = len(member_vrfs) > 1

        color = "#e94560" if is_multi_vrf else \
                "#3b82f6" if member_vrfs else \
                node.get("color", "#87CEEB")
        size = 30 if is_multi_vrf else 25

        vrf_label = ", ".join(sorted(member_vrfs)) if member_vrfs else "N/A"
        enriched = dict(node)
        enriched["color"] = color
        enriched["size"] = size
        enriched["vrfs"] = sorted(member_vrfs)
        enriched["title"] = f"{node.get('title', nid)}<br>VRF: {vrf_label}"
        enriched_nodes.append(enriched)

    # Enrich edges between different VRFs
    enriched_edges: List[Dict] = []
    leaking_edges = 0
    for edge in edges:
        src = edge.get("from", "")
        dst = edge.get("to", "")
        src_vrfs = node_vrf.get(src, set())
        dst_vrfs = node_vrf.get(dst, set())
        risk = edge.get("risk", 0)

        cross_vrf = bool(src_vrfs and dst_vrfs and src_vrfs != dst_vrfs)
        if cross_vrf:
            leaking_edges += 1

        color = "#e94560" if cross_vrf else edge.get("color", "#666")
        width = 4 if cross_vrf else edge.get("width", 1)

        enriched = {
            "from": src, "to": dst,
            "cross_vrf": cross_vrf,
            "color": color, "width": width, "risk": risk,
            "title": f"{'🏢 VRF Leak! ' if cross_vrf else ''}"
                     f"{src} → {dst} | Risk: {risk}",
        }
        enriched_edges.append(enriched)

    return VRFResult(
        nodes=enriched_nodes,
        edges=enriched_edges,
        vrfs=[{
            "name": v.name, "rd": v.rd,
            "route_targets": v.route_targets,
            "interfaces": v.interfaces,
            "nodes": v.nodes,
            "isolation_score": isolation_scores.get(v.name, 0),
        } for v in vrfs],
        leaks=[{"vrf_a": l.vrf_a, "vrf_b": l.vrf_b,
                "shared_rt": l.shared_rt, "severity": l.severity} for l in leaks],
        isolation_scores=isolation_scores,
        total_vrfs=len(vrfs),
    )
