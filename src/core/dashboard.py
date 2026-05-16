"""
D1 — Dashboard / Landing Page
KPI aggregator: security score, rules health, open risks, compliance %, zone count,
trends (temporal comparison), top-10 risks, top changes.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class KPI:
    name: str
    value: float
    label: str
    trend: Optional[float] = None  # positive = improving, negative = degrading
    trend_display: str = ""
    icon: str = ""


@dataclass
class TopRisk:
    risk_type: str
    severity: str
    description: str
    count: int
    score_impact: float


@dataclass
class TopChange:
    change_type: str
    detail: str
    severity: str
    date: str
    affected_rules: int


@dataclass
class DashboardData:
    kpis: List[KPI] = field(default_factory=list)
    top_risks: List[TopRisk] = field(default_factory=list)
    top_changes: List[TopChange] = field(default_factory=list)
    security_score_breakdown: Dict[str, float] = field(default_factory=dict)
    rules_health_breakdown: Dict[str, float] = field(default_factory=dict)
    trend_data: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = ""


def _calc_security_score(issues: List[Dict], graph_stats: Dict) -> float:
    """Calculate 0-100 security score from issues and graph metrics."""
    if not issues and not graph_stats:
        return 100.0

    # Start at 100, deduct per issue
    deductions = 0.0
    severity_weight = {"critical": 10, "high": 5, "medium": 2, "low": 0.5}
    for issue in issues:
        deductions += severity_weight.get(issue.get("severity", "low"), 0.5)

    # Scale deductions relative to graph size
    total_nodes = graph_stats.get("nodes", 1) or 1
    score = max(0, 100 - (deductions / max(1, total_nodes) * 20))
    return round(score, 1)


def _calc_rules_health(rules: List[Dict], quality_data: Optional[Dict] = None) -> float:
    """Calculate rules health percentage."""
    if not rules:
        return 100.0

    if quality_data:
        qs = quality_data.get("quality_score", 100)
        return float(qs)

    # Simple heuristic: % of enabled rules with no issues
    total = len(rules)
    disabled = sum(1 for r in rules if r.get("action", "").lower() in ("deny", "drop"))
    # Heuristic: more deny rules = less healthy (too restrictive)
    healthy = total - disabled * 0.5
    return round(max(0, min(100, healthy / max(1, total) * 100)), 1)


def _calc_compliance(compliance_data: Optional[Dict] = None) -> float:
    """Calculate compliance percentage."""
    if not compliance_data:
        return 75.0  # Default
    passed = compliance_data.get("passed_checks", 0)
    total = compliance_data.get("total_checks", 1) or 1
    return round(passed / total * 100, 1)


def get_dashboard_data(
    issues: Optional[List[Dict]] = None,
    rules: Optional[List[Dict]] = None,
    graph_stats: Optional[Dict] = None,
    zones: Optional[List[str]] = None,
    quality_data: Optional[Dict] = None,
    compliance_data: Optional[Dict] = None,
    temporal_data: Optional[List[Dict]] = None,
    config_diffs: Optional[List[Dict]] = None,
) -> DashboardData:
    """
    Aggregate all available data into a dashboard structure.

    Args:
        issues: Audit issues list
        rules: Rules list
        graph_stats: Graph statistics dict
        zones: Zone names
        quality_data: Rule quality analysis results
        compliance_data: Compliance audit results
        temporal_data: Temporal trend data
        config_diffs: Config diff data for top changes
    """
    issues = issues or []
    rules = rules or []
    graph_stats = graph_stats or {}
    zones = zones or []
    temporal_data = temporal_data or []

    # ── KPI Calculations ────────────────────────
    security_score = _calc_security_score(issues, graph_stats)
    rules_health = _calc_rules_health(rules, quality_data)
    open_risks = len([i for i in issues if i.get("severity") in ("critical", "high")])
    compliance = _calc_compliance(compliance_data)
    zone_count = len(zones)

    # ── Trend calculation (compare with previous temporal snapshot) ──
    prev_score = None
    if len(temporal_data) >= 2:
        prev_score = temporal_data[-2].get("risk_score", security_score)

    score_trend = None
    if prev_score is not None:
        score_trend = round(security_score - prev_score, 1)

    kpis = [
        KPI(name="security_score", value=security_score, label="Security Score",
            trend=score_trend,
            trend_display=f"{'+' if score_trend and score_trend > 0 else ''}{score_trend}%" if score_trend else "—",
            icon="🛡️"),
        KPI(name="rules_health", value=rules_health, label="Rules Health",
            trend=None, trend_display="—", icon="📋"),
        KPI(name="open_risks", value=open_risks, label="Open Risks (Critical/High)",
            trend=None, trend_display="—", icon="⚠️"),
        KPI(name="compliance", value=compliance, label="Compliance %",
            trend=None, trend_display="—", icon="✅"),
        KPI(name="zone_count", value=zone_count, label="Security Zones",
            trend=None, trend_display="—", icon="🏢"),
    ]

    # ── Top-10 Risks ───────────────────────────
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_issues = sorted(issues, key=lambda i: severity_order.get(i.get("severity", "low"), 3))
    risk_groups: Dict[str, TopRisk] = {}
    for issue in sorted_issues:
        rtype = issue.get("type", "unknown")
        if rtype not in risk_groups:
            risk_groups[rtype] = TopRisk(
                risk_type=rtype,
                severity=issue.get("severity", "low"),
                description=issue.get("description", ""),
                count=0,
                score_impact=0,
            )
        risk_groups[rtype].count += 1
        sev_w = severity_order.get(issue.get("severity", "low"), 3)
        risk_groups[rtype].score_impact += (4 - sev_w) * 5

    top_risks = sorted(risk_groups.values(), key=lambda r: (-r.score_impact, -r.count))[:10]

    # ── Top-10 Changes ─────────────────────────
    top_changes: List[TopChange] = []
    if config_diffs:
        for diff in config_diffs[:10]:
            top_changes.append(TopChange(
                change_type=diff.get("change_type", "modified"),
                detail=diff.get("detail", ""),
                severity=diff.get("severity", "medium"),
                date=diff.get("date", "unknown"),
                affected_rules=diff.get("affected_rules", 0),
            ))
    elif temporal_data:
        for snapshot in temporal_data[:10]:
            added = len(snapshot.get("added_rules", []))
            removed = len(snapshot.get("removed_rules", []))
            if added or removed:
                top_changes.append(TopChange(
                    change_type="config_update",
                    detail=f"Snapshot {snapshot.get('timestamp', 'unknown')}",
                    severity="medium",
                    date=str(snapshot.get("timestamp", "")),
                    affected_rules=added + removed,
                ))

    # ── Breakdowns ─────────────────────────────
    score_breakdown = {
        "Access Control": 25,
        "Encryption": 20,
        "Redundancy": 15,
        "Segmentation": 20,
        "Compliance": 20,
    }

    critical_count = len([i for i in issues if i.get("severity") == "critical"])
    high_count = len([i for i in issues if i.get("severity") == "high"])
    medium_count = len([i for i in issues if i.get("severity") == "medium"])
    low_count = len([i for i in issues if i.get("severity") == "low"])

    health_breakdown = {
        "Shadowed": quality_data.get("summary", {}).get("shadowed_rules", 0) if quality_data else 0,
        "Conflicts": quality_data.get("summary", {}).get("conflicts", 0) if quality_data else 0,
        "Redundant": quality_data.get("summary", {}).get("redundant_rules", 0) if quality_data else 0,
        "Unused": quality_data.get("summary", {}).get("unused_rules", 0) if quality_data else 0,
        "Healthy": len(rules) - (critical_count + high_count),
    }

    # ── Trend Data for Chart ───────────────────
    trend_data = temporal_data

    from datetime import datetime
    return DashboardData(
        kpis=kpis,
        top_risks=top_risks,
        top_changes=top_changes,
        security_score_breakdown=score_breakdown,
        rules_health_breakdown=health_breakdown,
        trend_data=trend_data,
        timestamp=datetime.now().isoformat(),
    )


def get_dashboard_json(
    issues: Optional[List[Dict]] = None,
    rules: Optional[List[Dict]] = None,
    graph_stats: Optional[Dict] = None,
    zones: Optional[List[str]] = None,
    quality_data: Optional[Dict] = None,
    compliance_data: Optional[Dict] = None,
    temporal_data: Optional[List[Dict]] = None,
    config_diffs: Optional[List[Dict]] = None,
) -> Dict:
    """Return dashboard data as JSON-serializable dict."""
    data = get_dashboard_data(
        issues=issues, rules=rules, graph_stats=graph_stats,
        zones=zones, quality_data=quality_data, compliance_data=compliance_data,
        temporal_data=temporal_data, config_diffs=config_diffs,
    )
    return {
        "kpis": [{
            "name": k.name, "value": k.value, "label": k.label,
            "trend": k.trend, "trend_display": k.trend_display, "icon": k.icon,
        } for k in data.kpis],
        "top_risks": [{
            "risk_type": r.risk_type, "severity": r.severity,
            "description": r.description, "count": r.count,
            "score_impact": r.score_impact,
        } for r in data.top_risks],
        "top_changes": [{
            "change_type": c.change_type, "detail": c.detail,
            "severity": c.severity, "date": c.date,
            "affected_rules": c.affected_rules,
        } for c in data.top_changes],
        "security_score_breakdown": data.security_score_breakdown,
        "rules_health_breakdown": data.rules_health_breakdown,
        "trend_data": data.trend_data,
        "timestamp": data.timestamp,
    }
