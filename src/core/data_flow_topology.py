"""
T1 — Data Flow Topology
Classifies edges by port → flow type (DB, Web, File, Mail, Auth),
builds a 3-tier data layer graph (presentation / application / data).
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


# ── Port → Flow Classification ─────────────────────

FLOW_PORT_MAP: Dict[int, str] = {
    # DB
    1433: "DB", 1521: "DB", 3306: "DB", 5432: "DB", 27017: "DB",
    6379: "DB", 11211: "DB", 9042: "DB", 9200: "DB",
    # Web
    80: "Web", 443: "Web", 8080: "Web", 8443: "Web", 3000: "Web",
    4200: "Web", 5000: "Web", 8000: "Web", 9000: "Web",
    # File
    20: "File", 21: "File", 445: "File", 139: "File", 2049: "File",
    111: "File",
    # Mail
    25: "Mail", 110: "Mail", 143: "Mail", 465: "Mail", 587: "Mail",
    993: "Mail", 995: "Mail",
    # Auth
    88: "Auth", 389: "Auth", 636: "Auth", 3268: "Auth", 3269: "Auth",
    53: "Auth", 123: "Auth", 1812: "Auth", 1813: "Auth",
}

# Common service name → flow type patterns
SERVICE_NAME_MAP: Dict[str, str] = {
    "http": "Web", "https": "Web", "www": "Web",
    "mysql": "DB", "postgresql": "DB", "oracle": "DB", "mongodb": "DB",
    "redis": "DB", "mssql": "DB", "sql": "DB",
    "smtp": "Mail", "imap": "Mail", "pop3": "Mail",
    "ftp": "File", "samba": "File", "smb": "File", "nfs": "File",
    "ldap": "Auth", "kerberos": "Auth", "ldaps": "Auth", "radius": "Auth",
    "dns": "Auth", "ntp": "Auth",
    "ssh": "Admin", "telnet": "Admin", "rdp": "Admin",
}

# Layer mapping from flow type
FLOW_LAYER: Dict[str, str] = {
    "Web": "presentation",
    "Mail": "presentation",
    "File": "presentation",
    "DB": "data",
    "Admin": "application",
    "Auth": "application",
}


@dataclass
class FlowEdge:
    """Enriched edge with flow classification."""
    source: str
    target: str
    flow_type: str  # DB, Web, File, Mail, Auth, Admin, Other
    layer: str      # presentation, application, data
    port: Any = None
    risk: float = 0
    rules: List[str] = field(default_factory=list)


@dataclass
class DataFlowResult:
    nodes: List[Dict]
    edges: List[Dict]
    flow_summary: Dict[str, int]
    layer_stats: Dict[str, int]
    total_edges: int


def classify_flow(port: Any, service_name: str = "") -> str:
    """Classify a connection as a flow type based on port or service name."""
    if service_name and service_name.lower() in SERVICE_NAME_MAP:
        return SERVICE_NAME_MAP[service_name.lower()]

    if port is not None:
        try:
            p = int(port)
            if p in FLOW_PORT_MAP:
                return FLOW_PORT_MAP[p]
        except (ValueError, TypeError):
            pass

    return "Other"


def classify_layer(flow_type: str) -> str:
    """Map flow type to data layer."""
    return FLOW_LAYER.get(flow_type, "application")


def analyze_data_flow(
    nodes: List[Dict],
    edges: List[Dict],
) -> DataFlowResult:
    """
    Analyze data flow topology from graph nodes/edges.

    Returns enriched nodes with layer info and edges with flow classification.
    """
    node_ids = {n["id"] for n in nodes}
    flow_edges: List[Dict] = []
    flow_summary: Dict[str, int] = {}
    layer_stats: Dict[str, int] = {"presentation": 0, "application": 0, "data": 0}

    for edge in edges:
        src = edge.get("from", "")
        dst = edge.get("to", "")
        if src not in node_ids and dst not in node_ids:
            continue

        port = edge.get("port", None)
        svc = edge.get("service", "")
        risk = edge.get("risk", 0)

        flow_type = classify_flow(port, svc)
        layer = classify_layer(flow_type)

        enriched = {
            "from": src,
            "to": dst,
            "flow_type": flow_type,
            "layer": layer,
            "port": port,
            "risk": risk,
            "color": edge.get("color", "#666"),
            "width": edge.get("width", 1),
            "title": f"{flow_type} flow | Port: {port or 'any'} | Risk: {risk}",
        }
        flow_edges.append(enriched)

        flow_summary[flow_type] = flow_summary.get(flow_type, 0) + 1
        layer_stats[layer] = layer_stats.get(layer, 0) + 1

    # Enrich nodes with layer tag based on incident edges
    enriched_nodes: List[Dict] = []
    node_layer: Dict[str, str] = {}
    for edge in flow_edges:
        layer = edge["layer"]
        src = edge["from"]
        dst = edge["to"]
        if src not in node_layer:
            node_layer[src] = layer
        if dst not in node_layer:
            node_layer[dst] = layer

    layer_colors = {
        "presentation": "#3b82f6",  # blue
        "application": "#f59e0b",   # amber
        "data": "#10b981",          # green
    }
    layer_icons = {
        "presentation": "🌐",
        "application": "⚙️",
        "data": "🗄️",
    }

    for node in nodes:
        nid = node["id"]
        layer = node_layer.get(nid, "application")
        enriched = dict(node)
        enriched["layer"] = layer
        enriched["color"] = layer_colors.get(layer, "#D3D3D3")
        enriched["size"] = node.get("size", 25)
        enriched["title"] = f"{layer_icons.get(layer, '')} {layer.upper()}<br>{node.get('title', nid)}"
        enriched_nodes.append(enriched)

    return DataFlowResult(
        nodes=enriched_nodes,
        edges=flow_edges,
        flow_summary=flow_summary,
        layer_stats=layer_stats,
        total_edges=len(flow_edges),
    )
