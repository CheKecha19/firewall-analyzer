"""
WEB UI Server - Интерактивная визуализация для Firewall Analyzer
FastAPI сервер с Vis.js графом, фильтрами, поиском и тепловой картой.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
import networkx as nx

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.cli import CLI
from src.parsers import get_parser_for_file
from src.core import FirewallAnalyzer
from src.core.security_auditor import SecurityAuditor


app = FastAPI(title="Firewall Analyzer WEB UI", version="3.0.0")

analyzer_state: dict = {
    "analyzer": None,
    "nodes_data": [],
    "edges_data": [],
    "rules_data": [],
    "audit_issues": [],
    "zones": [],
    "stats": {},
}

TEMPLATE_DIR = Path(__file__).parent


def build_analyzer_from_configs(config_dir: str) -> FirewallAnalyzer:
    """Загружает и анализирует конфиги из директории."""
    analyzer = FirewallAnalyzer()
    config_path = Path(config_dir)
    if not config_path.exists():
        return analyzer

    extensions = {'.json', '.conf', '.cfg', '.txt', '.acl'}
    if config_path.is_file():
        files = [config_path]
    else:
        files = []
        for ext in extensions:
            files.extend(config_path.rglob(f"*{ext}"))

    for file_path in sorted(files):
        try:
            parser = get_parser_for_file(file_path)
            if parser is None:
                continue
            rules = parser.parse(file_path)
            if rules:
                analyzer.add_rules(rules, str(file_path))
        except Exception:
            pass

    analyzer.build_graph()
    return analyzer


def build_data(analyzer: FirewallAnalyzer):
    """Строит данные из анализатора для JSON-экспорта."""
    nodes_data = []
    for node, data in analyzer.graph.nodes(data=True):
        endpoint_type = data.get('endpoint_type', 'unknown')
        zone = data.get('zone', 'Unknown Zone')
        color_map = {
            'zone': '#90EE90', 'subnet': '#FFFACD', 'host': '#FFB6C1',
            'group': '#87CEEB', 'unknown': '#D3D3D3'
        }
        nodes_data.append({
            'id': str(node),
            'label': str(node),
            'group': zone,
            'type': endpoint_type,
            'color': color_map.get(endpoint_type, '#D3D3D3'),
            'size': 25,
            'title': f"Type: {endpoint_type}<br>Zone: {zone}"
        })

    edges_data = []
    for src, dst, data in analyzer.graph.edges(data=True):
        risk = data.get('risk_score', 0)
        rule_names = data.get('rules', [])
        if risk >= 8:
            color = 'red'
            width = 4
        elif risk >= 5:
            color = 'orange'
            width = 2
        else:
            color = '#666666'
            width = 1

        edge_title = f"Risk: {risk}/10"
        if rule_names:
            edge_title += f"<br>Rules: {', '.join(rule_names[:3])}"

        edges_data.append({
            'from': str(src),
            'to': str(dst),
            'color': color,
            'width': width,
            'risk': risk,
            'title': edge_title
        })

    rules_data = []
    for rule in analyzer.rules[:200]:
        rules_data.append({
            'name': rule.name,
            'sources': ', '.join(str(s) for s in rule.sources[:3]),
            'destinations': ', '.join(str(d) for d in rule.destinations[:3]),
            'services': ', '.join(str(s) for s in rule.services[:3]),
            'action': rule.action
        })

    auditor = SecurityAuditor(analyzer.rules, analyzer.graph)
    audit_issues = []
    try:
        audit_result = auditor.run_full_audit()
        for issue in audit_result.issues[:50]:
            audit_issues.append({
                'type': issue.check_type,
                'severity': issue.severity,
                'description': issue.description,
                'recommendation': getattr(issue, 'recommendation', '')
            })
    except Exception:
        pass

    zones = sorted(set(
        data.get('zone', 'Unknown Zone') for node, data in analyzer.graph.nodes(data=True)
    ))

    stats = {
        'nodes': analyzer.graph.number_of_nodes(),
        'edges': analyzer.graph.number_of_edges(),
        'rules': len(analyzer.rules),
        'zones': len(zones),
        'issues': len(audit_issues),
        'critical_issues': len([i for i in audit_issues if i['severity'] == 'critical']),
        'high_issues': len([i for i in audit_issues if i['severity'] == 'high']),
    }

    return nodes_data, edges_data, rules_data, audit_issues, zones, stats


# ─── API Endpoints ────────────────────────────────────────────

@app.get("/api/status")
async def get_status():
    return {'status': 'ok', 'version': '3.0.0', 'stats': analyzer_state.get("stats", {})}


@app.get("/api/graph")
async def get_graph():
    return {'nodes': analyzer_state.get("nodes_data", []), 'edges': analyzer_state.get("edges_data", [])}


@app.get("/api/rules")
async def get_rules(search: Optional[str] = Query(None), action: Optional[str] = Query(None)):
    rules = analyzer_state.get("rules_data", [])
    if search:
        q = search.lower()
        rules = [r for r in rules if q in r['name'].lower()
                 or q in r['sources'].lower() or q in r['destinations'].lower()]
    if action:
        rules = [r for r in rules if r['action'].lower() == action.lower()]
    return {'rules': rules, 'total': len(rules)}


@app.get("/api/audit")
async def get_audit(severity: Optional[str] = Query(None)):
    issues = analyzer_state.get("audit_issues", [])
    if severity:
        issues = [i for i in issues if i['severity'] == severity]
    return {'issues': issues, 'total': len(issues)}


@app.get("/api/search")
async def search_node(q: str = Query(...)):
    nodes = analyzer_state.get("nodes_data", [])
    results = [{'id': n['id'], 'label': n['label'], 'group': n['group'], 'type': n['type']}
               for n in nodes if q.lower() in str(n['id']).lower() or q.lower() in str(n['label']).lower()]
    return {'results': results, 'total': len(results)}


@app.get("/api/export/json")
async def export_json():
    return {
        'nodes': analyzer_state.get("nodes_data", []),
        'edges': analyzer_state.get("edges_data", []),
        'rules': analyzer_state.get("rules_data", []),
        'audit': analyzer_state.get("audit_issues", []),
        'stats': analyzer_state.get("stats", {}),
        'zones': analyzer_state.get("zones", []),
    }


@app.get("/api/zone-matrix")
async def get_zone_matrix():
    """Возвращает данные для матрицы зон безопасности."""
    analyzer = analyzer_state.get("analyzer")
    if not analyzer or not hasattr(analyzer, 'graph') or analyzer.graph.number_of_nodes() == 0:
        return {'zones': [], 'cells': {}}

    from src.graph.visualizer import GraphVisualizer
    visualizer = GraphVisualizer(analyzer.graph, analyzer.rules)
    matrix_data = visualizer._generate_zone_matrix_data()
    return matrix_data


# ─── Visualization Data ──────────────────────────────────────

@app.get("/api/sankey")
async def get_sankey():
    """Возвращает данные для Sankey-диаграммы потоков между зонами."""
    analyzer = analyzer_state.get("analyzer")
    if not analyzer or not hasattr(analyzer, 'graph') or analyzer.graph.number_of_nodes() == 0:
        return {'nodes': [], 'links': []}

    from src.graph.visualizer import GraphVisualizer
    visualizer = GraphVisualizer(analyzer.graph, analyzer.rules)
    data = visualizer._generate_sankey_data()
    return data


@app.get("/api/services")
async def get_services():
    """Возвращает топ-30 сервисов из рёбер графа."""
    analyzer = analyzer_state.get("analyzer")
    if not analyzer or not hasattr(analyzer, 'graph') or analyzer.graph.number_of_nodes() == 0:
        return []

    from src.graph.visualizer import GraphVisualizer
    visualizer = GraphVisualizer(analyzer.graph, analyzer.rules)
    data = visualizer._generate_service_data()
    return data


@app.get("/api/risk-severity")
async def get_risk_severity():
    """Возвращает распределение рисков по severity."""
    analyzer = analyzer_state.get("analyzer")
    if not analyzer or not hasattr(analyzer, 'graph') or analyzer.graph.number_of_nodes() == 0:
        return []

    from src.graph.visualizer import GraphVisualizer
    visualizer = GraphVisualizer(analyzer.graph, analyzer.rules)
    data = visualizer._generate_risk_severity_data()
    return data


@app.get("/api/hilbert")
async def get_hilbert():
    """Возвращает данные для Hilbert IP-space карты."""
    analyzer = analyzer_state.get("analyzer")
    if not analyzer or not hasattr(analyzer, 'graph') or analyzer.graph.number_of_nodes() == 0:
        return {'points': [], 'gridSize': 4096, 'totalPoints': 0}

    from src.graph.visualizer import GraphVisualizer
    visualizer = GraphVisualizer(analyzer.graph, analyzer.rules)
    data = visualizer._generate_hilbert_data()
    return data


@app.post("/api/siem/export")
async def siem_export(request: dict = None):
    from src.integrations.siem_export import export_all_formats
    audit_issues = analyzer_state.get("audit_issues", [])
    stats = analyzer_state.get("stats", {})
    output_dir = request.get("output_dir", "output") if request else "output"
    base_name = request.get("base_name", "siem_export") if request else "siem_export"

    issues_for_export = [{
        'check_type': i.get('type', 'unknown'), 'severity': i.get('severity', 'low'),
        'description': i.get('description', ''), 'rule_name': i.get('type', 'unknown'),
        'risk_score': 0, 'source_ip': '', 'destination_ip': '',
        'port': '', 'action': '', 'file': 'web-ui',
        'recommendation': i.get('recommendation', ''),
    } for i in audit_issues]

    export_data = {
        'issues': issues_for_export, 'total_rules': stats.get('rules', 0),
        'total_issues': len(issues_for_export), 'critical_count': stats.get('critical_issues', 0),
        'high_count': stats.get('high_issues', 0), 'medium_count': 0, 'low_count': 0,
        'average_risk': 5.0, 'compliance_score': 0, 'files_processed': 1, 'environment': 'production',
    }
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    export_all_formats(export_data, output_dir, base_name)
    return {'status': 'ok', 'formats': ['splunk', 'elastic', 'qradar', 'arcsight', 'csv', 'syslog'],
            'output_dir': output_dir, 'base_name': base_name}


@app.post("/api/siem/correlate")
async def siem_correlate(request: dict = None):
    from src.integrations.siem_correlator import run_correlation
    audit_issues = analyzer_state.get("audit_issues", [])
    syslog_path = request.get("syslog_path") if request else None
    time_window = request.get("time_window_hours", 24) if request else 24
    output_dir = request.get("output_dir", "output") if request else "output"
    base_name = request.get("base_name", "correlation") if request else "correlation"

    issues_for_corr = [{
        'check_type': i.get('type', 'unknown'), 'severity': i.get('severity', 'low'),
        'description': i.get('description', ''), 'rule_name': i.get('type', 'unknown'),
        'risk_score': 0, 'source_ip': '', 'destination_ip': '',
        'port': '', 'action': '', 'file': 'web-ui',
        'recommendation': i.get('recommendation', ''),
    } for i in audit_issues]

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    corr_output = str(Path(output_dir) / f"{base_name}_correlation.json")
    result = run_correlation(audit_issues=issues_for_corr, syslog_path=syslog_path,
                             time_window_hours=time_window, output_path=corr_output)
    return {'status': 'ok', 'summary': result, 'output_file': corr_output}


@app.get("/api/mitre")
async def get_mitre(technique: Optional[str] = Query(None)):
    """Возвращает MITRE ATT&CK маппинг."""
    from src.core.mitre_mapper import MitreMapper
    mapper = MitreMapper()
    audit_issues = analyzer_state.get("audit_issues", [])
    if not audit_issues:
        return {'matrix': {}, 'matches': [], 'total_matches': 0}
    report = mapper.map_all(audit_issues)
    matches = [{
        'finding_type': m.finding.get('type', ''),
        'severity': m.finding.get('severity', ''),
        'technique_id': m.technique_id,
        'technique_name': m.technique_name,
        'tactic': m.tactic,
        'confidence': m.confidence,
        'description': m.description,
    } for m in report.matches]
    if technique:
        matches = [m for m in matches if m['technique_id'] == technique]
    return {'matches': matches, 'total_matches': len(matches)}


@app.get("/api/mitre/matrix")
async def get_mitre_matrix():
    """Возвращает данные MITRE матрицы."""
    from src.core.mitre_mapper import MitreMapper
    mapper = MitreMapper()
    audit_issues = analyzer_state.get("audit_issues", [])
    return mapper.get_matrix_data(audit_issues)


@app.get("/api/branding")
async def get_branding():
    """Возвращает конфиг брендинга из branding.json в корне проекта."""
    branding_path = Path(__file__).parent.parent.parent / "branding.json"
    if not branding_path.exists():
        return JSONResponse({
            "primary_color": "#e94560",
            "accent": "#0f3460",
            "logo_url": "",
            "title": "Firewall Analyzer"
        })
    try:
        with open(branding_path, 'r', encoding='utf-8') as f:
            branding = json.load(f)
        return JSONResponse(branding)
    except Exception:
        return JSONResponse({
            "primary_color": "#e94560",
            "accent": "#0f3460",
            "logo_url": "",
            "title": "Firewall Analyzer"
        })


# ─── Attack Graph ─────────────────────────────────────────────

@app.get("/api/attack-graph")
async def get_attack_graph():
    """Возвращает граф атак: пути от external-узлов к critical assets."""
    from src.core.attack_graph import AttackGraphBuilder
    analyzer = analyzer_state.get("analyzer")
    if not analyzer:
        return {'attack_paths': [], 'sources_count': 0, 'targets_count': 0, 'reachable_targets': 0,
                'external_sources': [], 'critical_targets': []}
    builder = AttackGraphBuilder(analyzer.graph, analyzer.rules)
    return builder.to_dict()


# ─── Rule Quality ─────────────────────────────────────────────

@app.get("/api/rules/quality")
async def get_rules_quality():
    """Возвращает полный отчёт о качестве правил."""
    from src.core.rule_quality import RuleQualityAnalyzer
    analyzer = analyzer_state.get("analyzer")
    if not analyzer:
        return {'shadowed': [], 'conflicts': [], 'redundant': [], 'unused': [],
                'total_rules': 0, 'quality_score': 100, 'summary': {}}
    quality = RuleQualityAnalyzer(analyzer.rules)
    return quality.to_dict()


@app.get("/api/rules/shadowed")
async def get_rules_shadowed():
    """Возвращает только перекрытые (shadowed) правила."""
    from src.core.rule_quality import RuleQualityAnalyzer
    analyzer = analyzer_state.get("analyzer")
    if not analyzer:
        return {'shadowed': [], 'total': 0}
    quality = RuleQualityAnalyzer(analyzer.rules)
    report = quality.analyze()
    return {'shadowed': report.shadowed, 'total': len(report.shadowed)}


@app.get("/api/rules/conflicts")
async def get_rules_conflicts():
    """Возвращает только конфликтующие правила."""
    from src.core.rule_quality import RuleQualityAnalyzer
    analyzer = analyzer_state.get("analyzer")
    if not analyzer:
        return {'conflicts': [], 'total': 0}
    quality = RuleQualityAnalyzer(analyzer.rules)
    report = quality.analyze()
    return {'conflicts': report.conflicts, 'total': len(report.conflicts)}


@app.get("/api/rules/redundant")
async def get_rules_redundant():
    """Возвращает только избыточные (redundant) правила."""
    from src.core.rule_quality import RuleQualityAnalyzer
    analyzer = analyzer_state.get("analyzer")
    if not analyzer:
        return {'redundant': [], 'total': 0}
    quality = RuleQualityAnalyzer(analyzer.rules)
    report = quality.analyze()
    return {'redundant': report.redundant, 'total': len(report.redundant)}


# ─── D1 Dashboard ───────────────────────────────────────────

@app.get("/api/dashboard")
async def get_dashboard():
    """Возвращает дашборд с KPI, трендами и топ-10 рисков/изменений."""
    from src.core.dashboard import get_dashboard_json
    from src.core.temporal_view import TemporalAnalyzer

    issues = analyzer_state.get("audit_issues", [])
    rules = analyzer_state.get("rules_data", [])
    stats = analyzer_state.get("stats", {})
    zones = analyzer_state.get("zones", [])

    # Get quality data
    quality_data = None
    analyzer = analyzer_state.get("analyzer")
    if analyzer and analyzer.rules:
        try:
            from src.core.rule_quality import RuleQualityAnalyzer
            q = RuleQualityAnalyzer(analyzer.rules)
            quality_data = q.to_dict()
        except Exception:
            pass

    # Get temporal data for trends
    temporal_data = []
    try:
        ta = TemporalAnalyzer()
        temporal_data = [{
            "timestamp": str(s.timestamp),
            "risk_score": s.risk_score,
            "rules_count": s.rules_count,
            "changes_from_previous": s.changes_from_previous,
        } for s in ta.snapshots]
    except Exception:
        pass

    # Get attack graph data for dashboard
    attack_graph_data = None
    if analyzer and analyzer.graph and analyzer.graph.number_of_nodes() > 0:
        try:
            from src.core.attack_graph import AttackGraphBuilder
            builder = AttackGraphBuilder(analyzer.graph, analyzer.rules)
            attack_graph_data = builder.to_dict()
        except Exception:
            pass

    result = get_dashboard_json(
        issues=issues, rules=rules, graph_stats=stats,
        zones=zones, quality_data=quality_data,
        temporal_data=temporal_data,
        attack_graph_data=attack_graph_data,
    )
    return JSONResponse(result)


# ─── T1 Data Flow Topology ──────────────────────────────────

@app.get("/api/topology/data-flow")
async def get_data_flow_topology():
    """Data Flow Topology: классификация рёбер по портам (DB/Web/File/Mail/Auth)."""
    from src.core.data_flow_topology import analyze_data_flow
    nodes = analyzer_state.get("nodes_data", [])
    edges = analyzer_state.get("edges_data", [])
    result = analyze_data_flow(nodes, edges)
    return JSONResponse({
        "nodes": result.nodes, "edges": result.edges,
        "flow_summary": result.flow_summary,
        "layer_stats": result.layer_stats,
        "total_edges": result.total_edges,
    })


# ─── T2 Trust Boundary Topology ─────────────────────────────

@app.get("/api/topology/trust-boundary")
async def get_trust_boundary_topology():
    """Trust Boundary Topology: классификация рёбер intra/inter/external, perimeter holes."""
    from src.core.trust_boundary_topology import analyze_trust_boundary
    nodes = analyzer_state.get("nodes_data", [])
    edges = analyzer_state.get("edges_data", [])
    result = analyze_trust_boundary(nodes, edges)
    return JSONResponse({
        "nodes": result.nodes, "edges": result.edges,
        "perimeter_holes": result.perimeter_holes,
        "boundary_summary": result.boundary_summary,
        "total_edges": result.total_edges,
    })


# ─── T3 Redundancy/Resilience Topology ──────────────────────

@app.get("/api/topology/resilience")
async def get_resilience_topology():
    """Resilience Topology: SPOF detection, redundancy scoring."""
    from src.core.resilience_topology import analyze_resilience
    nodes = analyzer_state.get("nodes_data", [])
    edges = analyzer_state.get("edges_data", [])
    result = analyze_resilience(nodes, edges)
    return JSONResponse({
        "nodes": result.nodes, "edges": result.edges,
        "spofs": result.spofs,
        "redundancy_scores": result.redundancy_scores,
        "total_nodes": result.total_nodes,
    })


# ─── T4 Protocol/Encryption Topology ────────────────────────

@app.get("/api/topology/encryption")
async def get_encryption_topology():
    """Encryption Topology: классификация рёбер по уровню шифрования."""
    from src.core.encryption_topology import analyze_encryption
    nodes = analyzer_state.get("nodes_data", [])
    edges = analyzer_state.get("edges_data", [])
    result = analyze_encryption(nodes, edges)
    return JSONResponse({
        "nodes": result.nodes, "edges": result.edges,
        "encryption_summary": result.encryption_summary,
        "coverage_percent": result.coverage_percent,
        "total_edges": result.total_edges,
    })


# ─── T5 Lateral Movement Topology ───────────────────────────

@app.get("/api/topology/lateral-movement")
async def get_lateral_movement_topology():
    """Lateral Movement Topology: East-West paths, blast radius."""
    from src.core.lateral_movement_topology import analyze_lateral_movement
    nodes = analyzer_state.get("nodes_data", [])
    edges = analyzer_state.get("edges_data", [])
    result = analyze_lateral_movement(nodes, edges)
    return JSONResponse({
        "nodes": result.nodes, "edges": result.edges,
        "east_west_count": result.east_west_count,
        "blast_radii": result.blast_radii,
        "lateral_risk_score": result.lateral_risk_score,
        "total_edges": result.total_edges,
    })


# ─── T6 Micro-segmentation Topology ─────────────────────────

@app.get("/api/topology/microseg")
async def get_microseg_topology():
    """Micro-segmentation Topology: Intra-zone analysis, readiness score."""
    from src.core.microseg_topology import analyze_microseg
    nodes = analyzer_state.get("nodes_data", [])
    edges = analyzer_state.get("edges_data", [])
    result = analyze_microseg(nodes, edges)
    return JSONResponse({
        "nodes": result.nodes, "edges": result.edges,
        "readiness_score": result.readiness_score,
        "zone_analysis": result.zone_analysis,
        "generated_deny_rules": result.generated_deny_rules,
        "intra_zone_edges": result.intra_zone_edges,
        "total_edges": result.total_edges,
    })


# ─── T7 Multi-tenancy/VRF Topology ──────────────────────────

@app.get("/api/topology/vrf")
async def get_vrf_topology():
    """VRF Topology: VRF detection, leak detection, isolation scoring."""
    from src.core.vrf_topology import analyze_vrf
    nodes = analyzer_state.get("nodes_data", [])
    edges = analyzer_state.get("edges_data", [])
    rules = analyzer_state.get("rules_data", [])
    result = analyze_vrf(nodes, edges, rules=rules)
    return JSONResponse({
        "nodes": result.nodes, "edges": result.edges,
        "vrfs": result.vrfs,
        "leaks": result.leaks,
        "isolation_scores": result.isolation_scores,
        "total_vrfs": result.total_vrfs,
    })


# ─── A1 Rule Optimization ─────────────────────────────────

@app.post("/api/optimize/preview")
async def optimize_preview(request: dict = None):
    """Принимает config_dir, возвращает preview оптимизации."""
    from src.core.rule_optimizer import RuleOptimizer
    from pathlib import Path
    from src.parsers import get_parser_for_file
    
    config_dir = request.get("config_dir", "") if request else ""
    
    # Load rules from config directory
    rules = []
    if config_dir:
        config_path = Path(config_dir)
        if config_path.exists():
            extensions = {'.json', '.conf', '.cfg', '.txt', '.acl'}
            if config_path.is_file():
                files = [config_path]
            else:
                files = []
                for ext in extensions:
                    files.extend(config_path.rglob(f"*{ext}"))
            for file_path in sorted(files):
                try:
                    parser = get_parser_for_file(file_path)
                    if parser:
                        parsed = parser.parse(file_path)
                        if parsed:
                            rules.extend(parsed)
                except Exception:
                    pass

    # Use loaded rules if available, otherwise from analyzer_state
    if not rules:
        analyzer = analyzer_state.get("analyzer")
        if analyzer:
            rules = analyzer.rules

    if not rules:
        return JSONResponse({
            "error": "No rules loaded",
            "preview": {"original_rules": [], "consolidated_rules": [], "groupings": []},
            "score": {"original_count": 0, "consolidated_count": 0, "savings_count": 0, "savings_percent": 0},
        })

    optimizer = RuleOptimizer(rules)
    result = optimizer.to_dict()
    return JSONResponse(result)


# ─── A2 Impact Analysis ────────────────────────────────────

@app.post("/api/impact/analyze")
async def impact_analyze(request: dict = None):
    """Принимает {target_type, target_id}, возвращает impact analysis."""
    from src.core.impact_analysis import ImpactAnalyzer
    
    if not request:
        return JSONResponse({"error": "Missing request body"}, status_code=400)
    
    target_type = request.get("target_type", "node")
    target_id = request.get("target_id", "")
    
    if not target_id:
        return JSONResponse({"error": "Missing target_id"}, status_code=400)
    
    nodes = analyzer_state.get("nodes_data", [])
    edges = analyzer_state.get("edges_data", [])
    rules = analyzer_state.get("rules_data", [])
    
    analyzer = ImpactAnalyzer(nodes, edges, rules)
    result = analyzer.impact_json(target_type, target_id)
    return JSONResponse(result)


@app.get("/api/impact/report")
async def impact_report(type: str = "node", id: str = ""):
    """Возвращает текстовый отчёт анализа влияния."""
    from src.core.impact_analysis import ImpactAnalyzer
    
    if not id:
        return JSONResponse({"error": "Missing id parameter"}, status_code=400)
    
    nodes = analyzer_state.get("nodes_data", [])
    edges = analyzer_state.get("edges_data", [])
    rules = analyzer_state.get("rules_data", [])
    
    analyzer = ImpactAnalyzer(nodes, edges, rules)
    report = analyzer.impact_report(type, id)
    
    return JSONResponse({
        "target": {"type": type, "id": id},
        "summary": report.summary,
        "direct_impact": report.direct_section,
        "cascading_impact": report.cascading_section,
        "recommendations": report.recommendations,
    })


# ─── What-If Analysis ──────────────────────────────────

@app.post("/api/what-if")
async def what_if_analyze(request: dict = None):
    """Симуляция изменения правил."""
    from src.core.what_if import WhatIfAnalyzer, RuleChange, ChangeType

    if not request:
        return JSONResponse({"error": "Missing request body"}, status_code=400)

    change_type_str = request.get("change_type", "add")
    change_map = {
        "add": ChangeType.ADD_RULE,
        "remove": ChangeType.REMOVE_RULE,
        "change_action": ChangeType.CHANGE_ACTION,
        "change_source": ChangeType.CHANGE_SOURCE,
        "change_dest": ChangeType.CHANGE_DEST,
        "change_service": ChangeType.CHANGE_SERVICE,
    }

    change = RuleChange(
        change_type=change_map.get(change_type_str, ChangeType.ADD_RULE),
        rule_id=request.get("rule_id"),
        rule_name=request.get("rule_name"),
        old_value=request.get("old_value"),
        new_value=request.get("new_value"),
        description=request.get("description", ""),
        risk_delta=0.0,
    )

    analyzer = WhatIfAnalyzer([])
    result = analyzer.simulate([change])

    return JSONResponse({
        "original_risk": result.original_risk,
        "new_risk": result.new_risk,
        "risk_delta": result.risk_delta,
        "impact": result.impact_score,
        "new_issues": result.new_issues,
        "resolved_issues": result.resolved_issues,
        "recommendations": result.recommendations,
    })


# ─── Главная страница (читает HTML из отдельного файла) ──────

@app.get("/", response_class=HTMLResponse)
async def index():
    nodes_json = json.dumps(analyzer_state.get("nodes_data", []), ensure_ascii=False)
    edges_json = json.dumps(analyzer_state.get("edges_data", []), ensure_ascii=False)
    rules_json = json.dumps(analyzer_state.get("rules_data", []), ensure_ascii=False)
    audit_json = json.dumps(analyzer_state.get("audit_issues", []), ensure_ascii=False)
    stats_json = json.dumps(analyzer_state.get("stats", {}), ensure_ascii=False)
    zones_json = json.dumps(analyzer_state.get("zones", []), ensure_ascii=False)

    zones_options = ''.join(
        f'<option value="{z}">{z}</option>' for z in analyzer_state.get("zones", [])
    )

    html = _load_template().replace('__NODES_JSON__', nodes_json) \
                           .replace('__EDGES_JSON__', edges_json) \
                           .replace('__RULES_JSON__', rules_json) \
                           .replace('__AUDIT_JSON__', audit_json) \
                           .replace('__STATS_JSON__', stats_json) \
                           .replace('__ZONES_JSON__', zones_json) \
                           .replace('__ZONES_OPTIONS__', zones_options)
    return html


_template_cache = None


def _load_template():
    global _template_cache
    if _template_cache is not None:
        return _template_cache
    tmpl_path = TEMPLATE_DIR / "ui_template.html"
    if not tmpl_path.exists():
        raise FileNotFoundError(f"UI template not found: {tmpl_path}")
    _template_cache = tmpl_path.read_text(encoding="utf-8")
    return _template_cache


# ─── Запуск сервера ──────────────────────────────────────────

def start_web_server(config_dir: Optional[str] = None, host: str = "127.0.0.1",
                     port: int = 8000, open_browser: bool = False):
    import uvicorn

    if config_dir:
        print(f"Loading configs from: {config_dir}")
        analyzer = build_analyzer_from_configs(config_dir)
        nodes, edges, rules, audit, zones, stats = build_data(analyzer)
        analyzer_state.update(analyzer=analyzer, nodes_data=nodes, edges_data=edges,
                              rules_data=rules, audit_issues=audit, zones=zones, stats=stats)
        print(f"  [OK] Loaded: {stats['nodes']} nodes, {stats['edges']} edges, {stats['rules']} rules")
        if stats['issues']:
            print(f"  [WARN] Issues: {stats['issues']} (crit: {stats['critical_issues']}, high: {stats['high_issues']})")

    print(f"\n[OK] Firewall Analyzer WEB UI -> http://{host}:{port}\n   Press Ctrl+C to stop\n")

    if open_browser:
        import webbrowser
        webbrowser.open(f"http://{host}:{port}")

    uvicorn.run(app, host=host, port=port, log_level="warning")
