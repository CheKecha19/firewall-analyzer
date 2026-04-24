#!/usr/bin/env python3
"""
Firewall Analyzer v2.0 - Enterprise Security Analyzer

Анализатор конфигураций межсетевых экранов UserGate, Cisco, Juniper, Huawei.
Включает глубокое разрешение объектов, аудит безопасности и профессиональную визуализацию.
"""
import sys
import importlib.util
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional

# Импорт парсера топологии (Stage 2)
try:
    from src.parsers.topology_parser import TopologyParser
    TOPOLOGY_AVAILABLE = True
except ImportError:
    TOPOLOGY_AVAILABLE = False

# Импорт VLAN и Zone builders (Stage 3)
try:
    from src.core.vlan_topology import VLANTopologyBuilder
    from src.core.zone_topology import SecurityZoneBuilder
    VLAN_ZONE_AVAILABLE = True
except ImportError:
    VLAN_ZONE_AVAILABLE = False


def check_and_install_dependencies():
    """Проверяет и при необходимости устанавливает зависимости."""
    required_packages = [
        ('networkx', 'networkx'),
        ('pandas', 'pandas'),
        ('pyvis', 'pyvis'),
    ]
    
    optional_packages = [
        ('pygraphviz', 'pygraphviz'),
        ('matplotlib', 'matplotlib'),
    ]
    
    missing_required = []
    
    for import_name, package_name in required_packages:
        if importlib.util.find_spec(import_name) is None:
            missing_required.append(package_name)
    
    if missing_required:
        print("Missing required packages. Installing...")
        import subprocess
        for package in missing_required:
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"  [OK] Installed {package}")
            except subprocess.CalledProcessError as e:
                print(f"  [ERROR] Failed to install {package}: {e}")
                sys.exit(1)
        print("Dependencies installed. Please restart.")
        sys.exit(0)
    
    # Check optional packages
    missing_optional = []
    for import_name, package_name in optional_packages:
        if importlib.util.find_spec(import_name) is None:
            missing_optional.append(package_name)
    
    if missing_optional:
        print(f"Note: For better visualization, install: {', '.join(missing_optional)}")
        print(f"  pip install {' '.join(missing_optional)}")


check_and_install_dependencies()

import json
import warnings
warnings.filterwarnings('ignore')

from src.cli import CLI
from src.parsers import get_parser_for_file, UserGateParser, ACLParser
from src.core import FirewallAnalyzer
from src.core.security_auditor import SecurityAuditor
from src.core.config_diff import compare_configs
from src.core.compliance_auditor import ComplianceAuditor, ComplianceStandard
from src.graph import GraphVisualizer


def parse_file_worker(file_path: Path, args) -> Tuple[Path, List, Optional[str]]:
    """
    Worker function for parallel file parsing.
    
    Returns: (file_path, rules, error_message)
    """
    try:
        # Determine parser
        if args.source != 'auto':
            if args.source == 'usergate':
                parser = UserGateParser()
            else:
                parser = ACLParser()
        else:
            parser = get_parser_for_file(file_path)
        
        if parser is None:
            return file_path, [], "Unknown format"
        
        # Parse rules
        rules = parser.parse(file_path)
        return file_path, rules, None
        
    except Exception as e:
        return file_path, [], str(e)


def build_topology_for_files(
    analyzer: FirewallAnalyzer,
    files: List[Path],
    verbose: bool = False
) -> List[Tuple[Path, str]]:
    """
    Собирает топологию из файлов конфигураций.
    
    Returns: Список ошибок (file_path, error_message)
    """
    errors = []
    
    for file_path in files:
        try:
            # Определяем парсер
            parser = get_parser_for_file(file_path)
            if parser is None:
                continue
            
            # Парсим топологию
            interfaces, routes = parser.parse_topology(file_path)
            
            if interfaces or routes:
                # Извлекаем hostname из имени файла или содержимого
                device_id = file_path.stem
                hostname = None
                mgmt_ip = None
                
                # Определяем вендора
                if isinstance(parser, UserGateParser):
                    vendor = 'usergate'
                elif isinstance(parser, ACLParser):
                    # Определяем по содержимому
                    content = parser.read_file(file_path)
                    vendor = parser.detect_vendor(content)
                else:
                    vendor = 'unknown'
                
                # Добавляем устройство в топологию
                analyzer.add_device_topology(
                    device_id=device_id,
                    vendor=vendor,
                    hostname=hostname,
                    interfaces=interfaces,
                    routes=routes,
                    mgmt_ip=mgmt_ip
                )
                
                if verbose:
                    print(f"  [TOPO] {file_path.name}: {len(interfaces)} ifaces, {len(routes)} routes")
        
        except Exception as e:
            errors.append((file_path, str(e)))
    
    return errors


def run_config_diff(args) -> int:
    """Запускает сравнение двух конфигураций."""
    from pathlib import Path
    
    old_path = Path(args.diff_old)
    new_path = Path(args.diff_new)
    
    if not old_path.exists():
        print(f"[ERROR] Old config path not found: {old_path}")
        return 1
    
    if not new_path.exists():
        print(f"[ERROR] New config path not found: {new_path}")
        return 1
    
    print(f"\nComparing configurations:")
    print(f"  Old: {old_path}")
    print(f"  New: {new_path}")
    print()
    
    # Парсим старую конфигурацию
    print("Parsing old configuration...")
    old_parser = get_parser_for_file(old_path)
    if old_parser is None:
        print(f"[ERROR] Cannot detect format for: {old_path}")
        return 1
    old_rules = old_parser.parse(old_path)
    print(f"  [OK] {len(old_rules)} rules found")
    
    # Парсим новую конфигурацию
    print("Parsing new configuration...")
    new_parser = get_parser_for_file(new_path)
    if new_parser is None:
        print(f"[ERROR] Cannot detect format for: {new_path}")
        return 1
    new_rules = new_parser.parse(new_path)
    print(f"  [OK] {len(new_rules)} rules found")
    print()
    
    # Сравниваем
    print("Generating diff report...")
    diff, report = compare_configs(
        old_path, new_path, old_rules, new_rules,
        output_format=args.diff_format
    )
    
    # Выводим отчёт
    print(report)
    print()
    
    # Сохраняем в файл
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    ext = 'txt' if args.diff_format == 'text' else args.diff_format
    diff_path = output_dir / f"config_diff.{ext}"
    
    with open(diff_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"[OK] Diff report saved: {diff_path}")
    
    return 0


def run_compliance_audit(args) -> int:
    """Запускает аудит compliance."""
    from pathlib import Path
    
    input_path = Path(args.input_path)
    
    if not input_path.exists():
        print(f"[ERROR] Input path not found: {input_path}")
        return 1
    
    # Парсим конфигурацию
    print(f"Parsing configuration: {input_path}")
    parser = get_parser_for_file(input_path)
    if parser is None:
        print(f"[ERROR] Cannot detect format for: {input_path}")
        return 1
    
    rules = parser.parse(input_path)
    print(f"  [OK] {len(rules)} rules found\n")
    
    # Создаём аудитор
    auditor = ComplianceAuditor(rules)
    
    # Определяем стандарты для проверки
    standards = []
    if args.compliance == 'all':
        standards = list(ComplianceStandard)
    else:
        std_map = {
            'pci_dss': ComplianceStandard.PCI_DSS,
            'cis': ComplianceStandard.CIS,
            'nist': ComplianceStandard.NIST,
            'iso27001': ComplianceStandard.ISO27001,
            'sox': ComplianceStandard.SOX
        }
        standards = [std_map.get(args.compliance)]
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Проверяем каждый стандарт
    for std in standards:
        print(f"Running {std.value.upper()} compliance audit...")
        report = auditor.audit(std)
        
        # Генерируем отчёт
        report_text = auditor.generate_report(report, args.compliance_format)
        print(report_text)
        print()
        
        # Сохраняем
        ext = 'txt' if args.compliance_format == 'text' else args.compliance_format
        report_path = output_dir / f"compliance_{std.value}.{ext}"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print(f"[OK] {std.value.upper()} report saved: {report_path}\n")
    
    return 0


def main():
    """Main function."""
    cli = CLI()
    cli.print_welcome()
    
    args = cli.parse_args()
    
    # Handle config diff mode
    if hasattr(args, 'diff_old') and hasattr(args, 'diff_new'):
        if args.diff_old and args.diff_new:
            return run_config_diff(args)
    
    # Handle compliance audit mode
    if hasattr(args, 'compliance') and args.compliance:
        return run_compliance_audit(args)
    
    if args.verbose:
        print(f"Input path: {args.input_path}")
        print(f"Source type: {args.source}")
        print(f"Extensions: {args.extensions}")
        print(f"Recursive: {args.recursive}")
        print(f"Parallel: {args.parallel}")
        print(f"Aggregate subnets: {args.aggregate_subnets}")
        print(f"Output directory: {args.output_dir}")
        print()
    
    # Get list of files
    files = cli.get_files_to_process(args)
    
    if not files:
        print("[ERROR] No files found for processing.")
        print(f"   Check path: {args.input_path}")
        print(f"   Extensions: {args.extensions}")
        sys.exit(1)
    
    print(f"Files found: {len(files)}")
    if args.verbose:
        for f in files:
            print(f"  - {f}")
    print()
    
    # Create analyzer
    analyzer = FirewallAnalyzer()
    
    # Parse files (parallel or sequential)
    errors = []
    
    if args.parallel and len(files) > 1:
        print("Using parallel parsing...")
        with ThreadPoolExecutor(max_workers=min(8, len(files))) as executor:
            futures = {executor.submit(parse_file_worker, f, args): f for f in files}
            
            for future in as_completed(futures):
                file_path, rules, error = future.result()
                
                if error and error != "Unknown format":
                    errors.append((file_path, error))
                    if args.verbose:
                        print(f"[ERROR] {file_path.name}: {error}")
                elif rules:
                    analyzer.add_rules(rules, str(file_path))
                    if args.verbose:
                        print(f"[OK] {file_path.name}: {len(rules)} rules")
    else:
        # Sequential processing
        for file_path in files:
            file_path, rules, error = parse_file_worker(file_path, args)
            
            if error and error != "Unknown format":
                errors.append((file_path, error))
                if args.verbose:
                    print(f"[ERROR] {file_path.name}: {error}")
            elif rules:
                analyzer.add_rules(rules, str(file_path))
                if args.verbose:
                    print(f"[OK] {file_path.name}: {len(rules)} rules")
    
    if errors:
        print(f"\n[WARN] Errors during processing ({len(errors)} files):")
        for path, err in errors[:10]:  # Show first 10
            print(f"  - {path.name}: {err}")
    
    # Build graph
    print("\nBuilding network access graph...")
    analyzer.build_graph(
        aggregate_subnets=args.aggregate_subnets,
        aggregate_threshold=args.aggregate_threshold
    )
    
    # Build topology (if topology data available)
    print("\nBuilding network topology...")
    topology_errors = build_topology_for_files(analyzer, files, args.verbose)
    if topology_errors:
        if args.verbose:
            print(f"  [INFO] Topology data not available for {len(topology_errors)} files (normal for ACL-only configs)")
    
    # Print topology summary
    if analyzer.has_topology():
        topo_summary = analyzer.get_topology_summary()
        print(f"  Devices discovered: {topo_summary['devices_count']}")
        print(f"  Networks discovered: {topo_summary['networks_count']}")
    else:
        print("  No topology data available (only access graph)")
    
    # Print statistics
    analyzer.print_statistics()
    
    if analyzer.graph.number_of_nodes() == 0:
        print("[WARN] No data for visualization. Check input files.")
        sys.exit(1)
    
    # Security audit
    security_audit_results = None
    if args.audit:
        print("\nRunning security audit...")
        auditor = SecurityAuditor(analyzer.rules, analyzer.graph)
        security_audit_results = auditor.run_full_audit()
        auditor.print_summary()
        
        # Export risk report if requested
        if args.risk_report:
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            risk_path = output_dir / f"{args.output}_risk.json"
            auditor.export_json(risk_path)
            print(f"[OK] Risk report: {risk_path}")
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate visualizations
    visualizer = GraphVisualizer(analyzer.graph, analyzer.rules)
    
    base_name = args.output
    
    # Topology generation (Stage 2)
    if args.topology and TOPOLOGY_AVAILABLE:
        print("\nGenerating network topology...")
        try:
            topo_parser = TopologyParser()
            
            # Парсим все файлы на топологию
            for file_path in files:
                try:
                    topo_parser.parse_file(str(file_path))
                    if args.verbose:
                        print(f"  [TOPO] {file_path.name}: topology parsed")
                except Exception as e:
                    if args.verbose:
                        print(f"  [WARN] {file_path.name}: topology parse error: {e}")
            
            # Генерируем топологию
            topo_nodes, topo_edges = topo_parser.get_topology_graph()
            
            if topo_nodes:
                print(f"  Topology nodes: {len(topo_nodes)}")
                print(f"  Topology edges: {len(topo_edges)}")
                
                # Сохраняем в JSON
                if args.topology_format == 'json':
                    topo_path = output_dir / f"{base_name}_topology.json"
                    with open(topo_path, 'w', encoding='utf-8') as f:
                        json.dump({'nodes': topo_nodes, 'edges': topo_edges}, f, ensure_ascii=False, indent=2)
                    print(f"[OK] Topology JSON: {topo_path}")
                
                # Добавляем в HTML
                if args.html:
                    topology_data = (topo_nodes, topo_edges)
                else:
                    topology_data = None
            else:
                print("  No topology data found (interfaces not configured)")
                topology_data = None
                
        except Exception as e:
            print(f"[ERROR] Topology generation: {e}")
            topology_data = None
    else:
        topology_data = None
    
    if args.dot:
        dot_path = output_dir / f"{base_name}.dot"
        try:
            analyzer.export_to_dot(dot_path)
            print(f"[OK] DOT file: {dot_path}")
        except Exception as e:
            print(f"[ERROR] DOT generation: {e}")
    
    if args.png:
        png_path = output_dir / f"{base_name}.png"
        result = visualizer.generate_png(png_path)
        if result:
            print(f"[OK] PNG map: {png_path}")
    
    if args.html:
        html_path = output_dir / f"{base_name}.html"
        # Получаем данные топологии если есть
        topology_data = analyzer.get_topology_data()
        result = visualizer.generate_html(
            html_path, 
            title=f"Firewall Access Map - {base_name}",
            topology_data=topology_data
        )
        if result:
            print(f"[OK] HTML report: {html_path}")
    
    # Stage 3: VLAN and Zone Topology
    if (args.vlan_view or args.zone_view) and VLAN_ZONE_AVAILABLE:
        print("\nGenerating VLAN/Zone topology...")
        
        try:
            vlan_builder = VLANTopologyBuilder()
            zone_builder = SecurityZoneBuilder()
            
            # Парсим топологию для VLAN и Zone
            for file_path in files:
                try:
                    topo_parser = TopologyParser()
                    topo = topo_parser.parse_file(str(file_path))
                    
                    # Добавляем VLAN
                    if args.vlan_view:
                        vlan_builder.add_device_vlans(
                            topo.hostname, topo.vlans, topo.interfaces
                        )
                    
                    # Добавляем зоны
                    if args.zone_view:
                        zone_builder.auto_detect_zones(topo.interfaces, topo.hostname)
                        
                except Exception as e:
                    if args.verbose:
                        print(f"  [WARN] {file_path.name}: {e}")
            
            # Экспорт VLAN topology
            if args.vlan_view:
                vlan_nodes, vlan_edges = vlan_builder.get_vlan_graph()
                print(f"  VLAN nodes: {len(vlan_nodes)}, edges: {len(vlan_edges)}")
                
                # JSON export
                vlan_path = output_dir / f"{base_name}_vlan.json"
                with open(vlan_path, 'w', encoding='utf-8') as f:
                    json.dump({'nodes': vlan_nodes, 'edges': vlan_edges}, f, ensure_ascii=False, indent=2)
                print(f"[OK] VLAN topology: {vlan_path}")
                
                # Matrix export
                vlan_matrix = vlan_builder.get_vlan_matrix()
                matrix_path = output_dir / f"{base_name}_vlan_matrix.json"
                with open(matrix_path, 'w', encoding='utf-8') as f:
                    json.dump(vlan_matrix, f, ensure_ascii=False, indent=2)
                print(f"[OK] VLAN matrix: {matrix_path}")
            
            # Экспорт Zone topology
            if args.zone_view:
                zone_nodes, zone_edges = zone_builder.get_zone_graph()
                print(f"  Zone nodes: {len(zone_nodes)}, edges: {len(zone_edges)}")
                
                # JSON export
                zone_path = output_dir / f"{base_name}_zone.json"
                with open(zone_path, 'w', encoding='utf-8') as f:
                    json.dump({'nodes': zone_nodes, 'edges': zone_edges}, f, ensure_ascii=False, indent=2)
                print(f"[OK] Zone topology: {zone_path}")
                
                # Matrix export
                if args.zone_matrix:
                    zone_matrix = zone_builder.get_zone_matrix()
                    zm_path = output_dir / f"{base_name}_zone_matrix.json"
                    with open(zm_path, 'w', encoding='utf-8') as f:
                        json.dump(zone_matrix, f, ensure_ascii=False, indent=2)
                    print(f"[OK] Zone matrix: {zm_path}")
                
                # Violations report
                if zone_builder.violations:
                    viol_path = output_dir / f"{base_name}_zone_violations.json"
                    with open(viol_path, 'w', encoding='utf-8') as f:
                        json.dump([
                            {
                                'from': v.from_zone,
                                'to': v.to_zone,
                                'severity': v.severity,
                                'description': v.description,
                                'recommendation': v.recommendation
                            }
                            for v in zone_builder.violations
                        ], f, ensure_ascii=False, indent=2)
                    print(f"[WARN] Zone violations: {len(zone_builder.violations)} (see {viol_path})")
                    
        except Exception as e:
            print(f"[ERROR] VLAN/Zone generation: {e}")
    
    # Stage 4: Advanced Analytics
    if args.what_if or args.path_trace or args.temporal_view:
        print("\nRunning Advanced Analytics (Stage 4)...")
        
        try:
            from src.core.what_if import WhatIfAnalyzer, RuleChange, ChangeType
            from src.core.path_tracer import PathTracer, PathResult
            from src.core.temporal_view import TemporalAnalyzer
            
            # What-If Analysis
            if args.what_if:
                print("\n  What-If Analysis:")
                what_if = WhatIfAnalyzer(analyzer.rules)
                
                changes = []
                
                if args.what_if_add:
                    # Парсим "source,dest,port,action"
                    parts = args.what_if_add.split(',')
                    if len(parts) == 4:
                        changes.append(RuleChange(
                            change_type=ChangeType.ADD_RULE,
                            rule_id=None,
                            rule_name=f"WhatIf-{parts[0]}-{parts[1]}",
                            old_value=None,
                            new_value=f"{parts[0]}-{parts[1]}-{parts[2]}-{parts[3]}",
                            description=f"Add rule: {parts[0]} -> {parts[1]}:{parts[2]} ({parts[3]})",
                            risk_delta=0.0
                        ))
                
                if args.what_if_remove:
                    changes.append(RuleChange(
                        change_type=ChangeType.REMOVE_RULE,
                        rule_id=args.what_if_remove,
                        rule_name=args.what_if_remove,
                        old_value=None,
                        new_value=None,
                        description=f"Remove rule: {args.what_if_remove}",
                        risk_delta=0.0
                    ))
                
                if args.what_if_change_action:
                    # Парсим "rule_id,new_action"
                    parts = args.what_if_change_action.split(',')
                    if len(parts) == 2:
                        changes.append(RuleChange(
                            change_type=ChangeType.CHANGE_ACTION,
                            rule_id=parts[0],
                            rule_name=parts[0],
                            old_value=None,
                            new_value=parts[1],
                            description=f"Change action: {parts[0]} -> {parts[1]}",
                            risk_delta=0.0
                        ))
                
                if changes:
                    result = what_if.simulate(changes)
                    print(f"    Original risk: {result.original_risk:.1f}")
                    print(f"    New risk: {result.new_risk:.1f}")
                    print(f"    Risk delta: {result.risk_delta:+.1f}")
                    print(f"    Impact: {result.impact_score:.1f}/10")
                    
                    if result.new_issues:
                        print(f"    [!] New issues: {len(result.new_issues)}")
                        for issue in result.new_issues[:5]:
                            print(f"      - {issue}")
                    
                    if result.resolved_issues:
                        print(f"    [+] Resolved: {len(result.resolved_issues)}")
                        for issue in result.resolved_issues[:5]:
                            print(f"      - {issue}")
                    
                    # Сохраняем
                    wi_path = output_dir / f"{base_name}_whatif.json"
                    with open(wi_path, 'w', encoding='utf-8') as f:
                        json.dump({
                            'original_risk': result.original_risk,
                            'new_risk': result.new_risk,
                            'risk_delta': result.risk_delta,
                            'impact': result.impact_score,
                            'new_issues': result.new_issues,
                            'resolved': result.resolved_issues,
                            'recommendations': result.recommendations
                        }, f, ensure_ascii=False, indent=2)
                    print(f"[OK] What-If report: {wi_path}")
            
            # Path Tracer
            if args.path_trace and args.path_source and args.path_dest:
                print("\n  Path Tracer:")
                tracer = PathTracer(analyzer.rules)
                
                trace = tracer.trace(
                    args.path_source,
                    args.path_dest,
                    args.path_port
                )
                
                print(f"    Source: {trace.source}")
                print(f"    Destination: {trace.destination}")
                print(f"    Result: {trace.result.value}")
                print(f"    Hops: {len(trace.hops)}")
                print(f"    Total risk: {trace.total_risk:.1f}")
                
                if trace.hops:
                    for i, hop in enumerate(trace.hops, 1):
                        print(f"    Hop {i}: {hop.device} ({hop.action}) - {hop.details}")
                
                print(f"    Recommendation: {trace.recommendation}")
                
                # Сохраняем
                pt_path = output_dir / f"{base_name}_path.json"
                with open(pt_path, 'w', encoding='utf-8') as f:
                    json.dump({
                        'source': trace.source,
                        'destination': trace.destination,
                        'port': trace.port,
                        'protocol': trace.protocol,
                        'result': trace.result.value,
                        'hops': [
                            {
                                'device': h.device,
                                'action': h.action,
                                'rule': h.rule_name,
                                'details': h.details,
                                'risk': h.risk
                            }
                            for h in trace.hops
                        ],
                        'total_risk': trace.total_risk,
                        'recommendation': trace.recommendation
                    }, f, ensure_ascii=False, indent=2)
                print(f"[OK] Path trace: {pt_path}")
            
            # Temporal View
            if args.temporal_view:
                print("\n  Temporal Analysis:")
                temporal = TemporalAnalyzer()
                
                # Добавляем текущий снимок
                # Вычисляем средний риск если нужен
                current_risk = avg_risk if 'avg_risk' in locals() else 5.0
                
                snapshot = temporal.add_snapshot(
                    str(files[0]) if files else 'unknown',
                    analyzer.rules,
                    current_risk
                )
                
                print(f"    Snapshots: {len(temporal.snapshots)}")
                
                # Тренды
                trends = temporal.get_trends(days=args.temporal_days)
                if trends:
                    print(f"    Trends ({len(trends)} points):")
                    for t in trends[-5:]:
                        print(f"      {t.date}: risk={t.risk_score:.1f}, rules={t.rules_count}, changes={t.changes}")
                
                # Аномалии
                anomalies = temporal.detect_anomalies()
                if anomalies:
                    print(f"    [!] Anomalies: {len(anomalies)}")
                    for a in anomalies[:5]:
                        print(f"      [{a['severity']}] {a['date']}: {a['description']}")
                
                # Сводка
                summary = temporal.get_change_summary(days=args.temporal_days)
                print(f"    Summary: {summary.get('total_changes', 0)} changes, avg risk {summary.get('average_risk', 0):.1f}")
                
                # Сохраняем
                tv_path = output_dir / f"{base_name}_temporal.json"
                temporal.export_timeline(str(tv_path))
                print(f"[OK] Temporal view: {tv_path}")
                
        except Exception as e:
            print(f"[ERROR] Advanced analytics: {e}")
            import traceback
            traceback.print_exc()
    
    # Stage 5: Integrations (DISABLED)
    # if args.siem_export or args.ci_mode or args.api_server:
    #     print("\nRunning Integrations (Stage 5)...")
    #     try:
    #         from src.integrations.siem_export import SIEMExporter, export_all_formats
    #         from src.integrations.cicd import CICDIntegration
    #         ...
    
    print(f"\n[OK] Analysis completed. Results in: {output_dir.resolve()}/")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
