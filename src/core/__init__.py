"""
Core analysis modules.
"""
from .analyzer import FirewallAnalyzer
from .resolver import ObjectResolver, ResolvedObject
from .security_auditor import SecurityAuditor, SecurityIssue, RiskScoredEdge
from .topology_builder import TopologyBuilder
from .physical_topology import (
    PhysicalTopologyBuilder,
    PhysicalInterfaceParser,
    PhysicalLink,
    PhysicalInterface as PhysicalInterfaceInfo,
    LLDPNeighbor as LLDPNeighborInfo,
    DevicePhysicalInfo,
    build_physical_topology,
)
from .l3_topology import (
    L3TopologyBuilder,
    L3RouteParser,
    L3Route,
    L3DeviceInfo,
    build_l3_topology,
)
from .reachability_checker import ReachabilityChecker, ReachabilityResult, PathStatus
from .service_topology import (
    ServiceTopologyBuilder,
    ServiceNode as ServiceTopologyNode,
    ServiceEdge as ServiceTopologyEdge,
    ServiceLayer,
    build_service_topology,
)
from .diff_temporal import (
    DiffTemporalEngine,
    DiffTimelineHTML,
    GraphDiffResult,
    NodeChange,
    EdgeChange,
    TimelineSnapshot,
    TimelineTrend,
    ChangeType,
    build_diff_temporal_html,
    export_unified_json,
)

__all__ = [
    'FirewallAnalyzer',
    'ObjectResolver',
    'ResolvedObject',
    'SecurityAuditor',
    'SecurityIssue',
    'RiskScoredEdge',
    'TopologyBuilder',
    'PhysicalTopologyBuilder',
    'PhysicalInterfaceParser',
    'PhysicalLink',
    'PhysicalInterfaceInfo',
    'LLDPNeighborInfo',
    'DevicePhysicalInfo',
    'build_physical_topology',
    'L3TopologyBuilder',
    'L3RouteParser',
    'L3Route',
    'L3DeviceInfo',
    'build_l3_topology',
    'ReachabilityChecker',
    'ReachabilityResult',
    'PathStatus',
    'ServiceTopologyBuilder',
    'ServiceTopologyNode',
    'ServiceTopologyEdge',
    'ServiceLayer',
    'build_service_topology',
    'DiffTemporalEngine',
    'DiffTimelineHTML',
    'GraphDiffResult',
    'NodeChange',
    'EdgeChange',
    'TimelineSnapshot',
    'TimelineTrend',
    'ChangeType',
    'build_diff_temporal_html',
    'export_unified_json',
]
