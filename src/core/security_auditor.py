"""
Модуль аудита безопасности.
Проверяет политики на ошибки конфигурации и риски.
"""
import json
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
from pathlib import Path
import networkx as nx
from ..models.rule import FirewallRule
from ..models.endpoint import Endpoint
from ..models.service import Service


@dataclass
class SecurityIssue:
    """Выявленная проблема безопасности."""
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    issue_type: str
    rule_name: str
    rule_id: Optional[str]
    description: str
    recommendation: str
    affected_rules: List[str] = field(default_factory=list)
    risk_score: int = 0  # 1-10


@dataclass
class RiskScoredEdge:
    """Ребро графа с оценкой риска."""
    source: str
    destination: str
    risk_score: int
    risk_factors: List[str]
    rules: List[str]


class SecurityAuditor:
    """
    Аудитор безопасности политик межсетевого экрана.
    Выявляет ошибки конфигурации и оценивает риски.
    """
    
    # Небезопасные протоколы
    INSECURE_PROTOCOLS = {
        'telnet', 'ftp', 'tftp', 'http', 'pop3', 'imap', 
        'ldap', 'snmp', 'rsh', 'rlogin', 'rexec'
    }
    
    # Критические порты
    CRITICAL_SERVICES = {
        'ssh': 22,
        'rdp': 3389,
        'vnc': 5900,
        'database': [1433, 3306, 5432, 1521, 27017],
        'admin': [80, 443, 8080, 8443]
    }
    
    # Критические порты, не должны быть открыты в Internet
    CRITICAL_PORTS_INTERNET = {
        22: 'SSH', 3389: 'RDP', 161: 'SNMP', 23: 'Telnet',
        445: 'SMB', 139: 'NetBIOS', 1433: 'MSSQL', 3306: 'MySQL',
        5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch'
    }
    
    # Недоверенные зоны (Internet-facing)
    UNTRUSTED_ZONES = {'internet', 'external', 'untrusted', 'wan', 'public'}
    
    # Зоны по критичности
    ZONE_CRITICALITY = {
        'internet': 1,      # Наименее доверенная
        'dmz': 2,
        'external': 2,
        'internal': 3,
        'trusted': 4,
        'management': 5,    # Наиболее критичная
        'critical': 5
    }
    
    def __init__(self, rules: List[FirewallRule], graph: nx.DiGraph):
        """
        Args:
            rules: Список правил для аудита
            graph: Построенный граф соединений
        """
        self.rules = rules
        self.graph = graph
        self.issues: List[SecurityIssue] = []
        self.risk_edges: List[RiskScoredEdge] = []
    
    def run_full_audit(self) -> Dict:
        """Выполняет полный аудит и возвращает результаты."""
        self.issues = []
        self.risk_edges = []
        
        # Запускаем все проверки
        self.detect_shadowed_rules()
        self.detect_any_any_rules()
        self.detect_insecure_protocols()
        self.find_redundant_rules()
        self.calculate_risk_scores()
        self.detect_zone_violations()
        self.detect_overly_permissive_rules()
        # Новые проверки
        self.detect_critical_ports_to_internet()
        self.detect_wide_port_ranges()
        self.detect_bidirectional_rules()
        self.detect_logging_disabled()
        
        return self.get_audit_report()
    
    def detect_shadowed_rules(self) -> List[SecurityIssue]:
        """
        Находит правила, перекрытые более широкими правилами выше.
        Только для правил с одинаковым направлением (src->dst).
        """
        issues = []
        
        # Группируем правила по паре зон/сетей
        zone_pairs: Dict[Tuple[str, str], List[FirewallRule]] = {}
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            for src in rule.sources:
                for dst in rule.destinations:
                    pair = (src.zone or 'any', dst.zone or 'any')
                    if pair not in zone_pairs:
                        zone_pairs[pair] = []
                    zone_pairs[pair].append(rule)
        
        # Проверяем перекрытие внутри каждой группы
        seen_rules: Set[str] = set()
        for pair, rules_in_pair in zone_pairs.items():
            seen_rules.clear()
            for rule in rules_in_pair:
                # Проверяем, перекрывается ли правило более широкими правилами выше
                for prev_rule_id in seen_rules:
                    prev_rule = next((r for r in rules_in_pair if r.rule_id == prev_rule_id), None)
                    if prev_rule and self._is_rule_shadowed(rule, prev_rule):
                        if rule.rule_id != prev_rule.rule_id:  # Не сравниваем с самим собой
                            issue = SecurityIssue(
                                severity='medium',
                                issue_type='shadowed_rule',
                                rule_name=rule.name,
                                rule_id=rule.rule_id,
                                description=f"Rule '{rule.name}' may be shadowed by rule '{prev_rule.name}'",
                                recommendation="Review rule order or specificity",
                                risk_score=4
                            )
                            issues.append(issue)
                            break
                seen_rules.add(rule.rule_id)
        
        self.issues.extend(issues)
        return issues
    
    def _is_rule_shadowed(self, rule: FirewallRule, potential_shadower: FirewallRule) -> bool:
        """Проверяет, перекрывает ли второе правило первое."""
        # Проверяем источники
        if not self._endpoints_covered(rule.sources, potential_shadower.sources):
            return False
        
        # Проверяем назначения
        if not self._endpoints_covered(rule.destinations, potential_shadower.destinations):
            return False
        
        # Проверяем сервисы
        if not self._services_covered(rule.services, potential_shadower.services):
            return False
        
        return True
    
    def _endpoints_covered(self, endpoints: List[Endpoint], potential_covers: List[Endpoint]) -> bool:
        """Проверяет, покрываются ли endpoints более широким набором."""
        # Если потенциальный покрывающий содержит 'any', всё покрывается
        for cover in potential_covers:
            if cover.name == 'any' or '0.0.0.0/0' in cover.cidrs:
                return True
        
        # Проверяем, что все endpoints покрываются
        for ep in endpoints:
            ep_covered = False
            for cover in potential_covers:
                if self._cidr_covers(cover.cidrs, ep.cidrs):
                    ep_covered = True
                    break
            if not ep_covered:
                return False
        
        return True
    
    def _cidr_covers(self, cover_cidrs: Set[str], target_cidrs: Set[str]) -> bool:
        """Проверяет, покрывает ли одна CIDR другую."""
        if not cover_cidrs or not target_cidrs:
            return False
        
        for target in target_cidrs:
            for cover in cover_cidrs:
                try:
                    import ipaddress
                    target_net = ipaddress.ip_network(target, strict=False)
                    cover_net = ipaddress.ip_network(cover, strict=False)
                    # Проверяем перекрытие
                    if target_net.subnet_of(cover_net) or target_net.supernet_of(cover_net):
                        return True
                except (ValueError, TypeError):
                    continue
        
        return False
    
    def _services_covered(self, services: List[Service], potential_covers: List[Service]) -> bool:
        """Проверяет, покрываются ли сервисы."""
        # Если есть 'any' в покрывающих
        for cover in potential_covers:
            if cover.name == 'any' or cover.protocol == 'ip':
                return True
        
        # Проверяем порты
        for svc in services:
            svc_covered = False
            for cover in potential_covers:
                if svc.protocol == cover.protocol or cover.protocol == 'ip':
                    # Проверяем порты
                    if not svc.ports or not cover.ports:
                        svc_covered = True
                    elif svc.ports.issubset(cover.ports):
                        svc_covered = True
                    break
            if not svc_covered:
                return False
        
        return True
    
    def detect_any_any_rules(self) -> List[SecurityIssue]:
        """Находит правила с any-any (0.0.0.0/0) в источниках или назначениях."""
        issues = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            has_any_src = any(
                src.name == 'any' or '0.0.0.0/0' in src.cidrs
                for src in rule.sources
            )
            has_any_dst = any(
                dst.name == 'any' or '0.0.0.0/0' in dst.cidrs
                for dst in rule.destinations
            )
            
            if has_any_src and has_any_dst:
                issue = SecurityIssue(
                    severity='critical',
                    issue_type='any_any_rule',
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    description=f"Rule allows traffic from any to any",
                    recommendation="Restrict sources and destinations to specific networks",
                    risk_score=10
                )
                issues.append(issue)
            elif has_any_src:
                issue = SecurityIssue(
                    severity='high',
                    issue_type='any_source_rule',
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    description=f"Rule allows traffic from any source",
                    recommendation="Define specific source networks or groups",
                    risk_score=7
                )
                issues.append(issue)
            elif has_any_dst:
                issue = SecurityIssue(
                    severity='high',
                    issue_type='any_destination_rule',
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    description=f"Rule allows traffic to any destination",
                    recommendation="Define specific destination networks or groups",
                    risk_score=7
                )
                issues.append(issue)
        
        self.issues.extend(issues)
        return issues
    
    def detect_insecure_protocols(self) -> List[SecurityIssue]:
        """Находит правила с небезопасными протоколами."""
        issues = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            insecure_services = []
            for svc in rule.services:
                if svc.protocol.lower() in self.INSECURE_PROTOCOLS:
                    insecure_services.append(svc.name or svc.protocol)
            
            if insecure_services:
                issue = SecurityIssue(
                    severity='medium',
                    issue_type='insecure_protocol',
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    description=f"Rule allows insecure protocols: {', '.join(insecure_services)}",
                    recommendation="Replace with secure alternatives (SSH instead of Telnet, SFTP instead of FTP)",
                    risk_score=5
                )
                issues.append(issue)
        
        self.issues.extend(issues)
        return issues
    
    def find_redundant_rules(self) -> List[SecurityIssue]:
        """Находит полностью дублирующиеся правила."""
        issues = []
        seen_rules: Dict[str, FirewallRule] = {}
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Создаём ключ из характеристик правила
            key_parts = [
                frozenset(ep.name for ep in rule.sources),
                frozenset(ep.name for ep in rule.destinations),
                frozenset(svc.name for svc in rule.services),
                rule.action
            ]
            key = tuple(key_parts)
            
            if key in seen_rules:
                existing = seen_rules[key]
                issue = SecurityIssue(
                    severity='low',
                    issue_type='redundant_rule',
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    description=f"Rule duplicates '{existing.name}'",
                    recommendation="Remove redundant rule",
                    affected_rules=[existing.name, rule.name],
                    risk_score=2
                )
                issues.append(issue)
            else:
                seen_rules[key] = rule
        
        self.issues.extend(issues)
        return issues
    
    def calculate_risk_scores(self) -> List[RiskScoredEdge]:
        """Оценивает риск для каждого соединения в графе."""
        risk_edges = []
        
        for src, dst, data in self.graph.edges(data=True):
            risk_score = 0
            risk_factors = []
            
            # Получаем данные узлов
            src_data = self.graph.nodes.get(src, {})
            dst_data = self.graph.nodes.get(dst, {})
            
            src_type = src_data.get('endpoint_type', 'unknown')
            dst_type = dst_data.get('endpoint_type', 'unknown')
            src_zone = (src_data.get('zone') or 'unknown').lower()
            dst_zone = (dst_data.get('zone') or 'unknown').lower()
            
            # Риск на основе зон
            src_criticality = self.ZONE_CRITICALITY.get(src_zone, 3)
            dst_criticality = self.ZONE_CRITICALITY.get(dst_zone, 3)
            
            # Доступ из менее доверенной в более критичную зону = высокий риск
            if src_criticality < dst_criticality:
                risk_score += (dst_criticality - src_criticality) * 2
                risk_factors.append(f"Access from {src_zone} to more critical zone {dst_zone}")
            
            # Проверяем сервисы
            services = data.get('services', [])
            for svc in services:
                svc_lower = svc.lower()
                
                # Небезопасные протоколы
                if any(proto in svc_lower for proto in self.INSECURE_PROTOCOLS):
                    risk_score += 3
                    risk_factors.append(f"Insecure protocol: {svc}")
                
                # Критические сервисы
                for critical, ports in self.CRITICAL_SERVICES.items():
                    if isinstance(ports, int):
                        if str(ports) in svc or svc.endswith(str(ports)):
                            risk_score += 2
                            risk_factors.append(f"Critical service: {critical}")
                    elif isinstance(ports, list):
                        if any(str(p) in svc for p in ports):
                            risk_score += 2
                            risk_factors.append(f"Critical service: {critical}")
            
            # Добавляем риск в граф
            self.graph[src][dst]['risk_score'] = risk_score
            self.graph[src][dst]['risk_factors'] = risk_factors
            
            if risk_score > 0:
                risk_edges.append(RiskScoredEdge(
                    source=src,
                    destination=dst,
                    risk_score=risk_score,
                    risk_factors=risk_factors,
                    rules=data.get('rules', [])
                ))
        
        self.risk_edges = sorted(risk_edges, key=lambda x: x.risk_score, reverse=True)
        return self.risk_edges
    
    def detect_zone_violations(self) -> List[SecurityIssue]:
        """Находит нарушения зональной политики."""
        issues = []
        
        # Примеры зональных нарушений
        restricted_flows = [
            ('internet', 'trusted', 'Direct access from Internet to Trusted zone'),
            ('dmz', 'management', 'DMZ should not access Management directly'),
        ]
        
        for src_zone, dst_zone, reason in restricted_flows:
            for rule in self.rules:
                if not rule.enabled:
                    continue
                
                src_zones = {ep.zone.lower() for ep in rule.sources if ep.zone}
                dst_zones = {ep.zone.lower() for ep in rule.destinations if ep.zone}
                
                if src_zone in src_zones and dst_zone in dst_zones:
                    issue = SecurityIssue(
                        severity='high',
                        issue_type='zone_violation',
                        rule_name=rule.name,
                        rule_id=rule.rule_id,
                        description=f"{reason}: {rule.name}",
                        recommendation="Review zone-based access policies",
                        risk_score=8
                    )
                    issues.append(issue)
        
        self.issues.extend(issues)
        return issues
    
    def detect_overly_permissive_rules(self) -> List[SecurityIssue]:
        """Находит чрезмерно разрешительные правила."""
        issues = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Правило с >10 источниками и >10 назначениями
            if len(rule.sources) > 10 and len(rule.destinations) > 10:
                issue = SecurityIssue(
                    severity='medium',
                    issue_type='overly_permissive',
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    description=f"Rule has {len(rule.sources)} sources and {len(rule.destinations)} destinations",
                    recommendation="Consider splitting into more specific rules",
                    risk_score=5
                )
                issues.append(issue)
        
        self.issues.extend(issues)
        return issues
    
    def detect_critical_ports_to_internet(self) -> List[SecurityIssue]:
        """Находит критические порты, открытые в Internet."""
        issues = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Проверяем, есть ли источник из недоверенной зоны
            src_zones = {ep.zone.lower() for ep in rule.sources if ep.zone}
            is_from_internet = bool(src_zones & self.UNTRUSTED_ZONES)
            is_any_source = any(src.name == 'any' or '0.0.0.0/0' in src.cidrs for src in rule.sources)
            
            if not (is_from_internet or is_any_source):
                continue
            
            # Проверяем порты
            for svc in rule.services:
                for port in svc.ports:
                    if port in self.CRITICAL_PORTS_INTERNET:
                        service_name = self.CRITICAL_PORTS_INTERNET[port]
                        issue = SecurityIssue(
                            severity='critical',
                            issue_type='critical_port_exposed',
                            rule_name=rule.name,
                            rule_id=rule.rule_id,
                            description=f"Critical service {service_name} (port {port}) accessible from Internet/untrusted zone",
                            recommendation=f"Restrict {service_name} access using VPN or jump hosts; never expose to Internet",
                            risk_score=9
                        )
                        issues.append(issue)
        
        self.issues.extend(issues)
        return issues
    
    def detect_wide_port_ranges(self) -> List[SecurityIssue]:
        """Находит правила с широкими диапазонами портов."""
        issues = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            for svc in rule.services:
                if svc.ports:
                    port_list = list(svc.ports)
                    if len(port_list) > 1000:
                        issue = SecurityIssue(
                            severity='high',
                            issue_type='wide_port_range',
                            rule_name=rule.name,
                            rule_id=rule.rule_id,
                            description=f"Rule allows {len(port_list)} ports - overly permissive",
                            recommendation="Specify exact ports needed; avoid large ranges",
                            risk_score=7
                        )
                        issues.append(issue)
        
        self.issues.extend(issues)
        return issues
    
    def detect_bidirectional_rules(self) -> List[SecurityIssue]:
        """Находит правила с пересекающимися source/destination (би-директорные)."""
        issues = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Получаем CIDR source и destination
            src_cidrs = set()
            dst_cidrs = set()
            
            for ep in rule.sources:
                src_cidrs.update(ep.cidrs)
            for ep in rule.destinations:
                dst_cidrs.update(ep.cidrs)
            
            # Проверяем пересечение
            if src_cidrs & dst_cidrs:
                overlap = src_cidrs & dst_cidrs
                issue = SecurityIssue(
                    severity='medium',
                    issue_type='bidirectional_rule',
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    description=f"Rule allows traffic between overlapping networks: {', '.join(list(overlap)[:3])}",
                    recommendation="Split into separate rules for each direction with explicit controls",
                    risk_score=5
                )
                issues.append(issue)
        
        self.issues.extend(issues)
        return issues
    
    def detect_logging_disabled(self) -> List[SecurityIssue]:
        """Находит правила без логирования."""
        issues = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Проверяем поле logging
            logging_enabled = getattr(rule, 'logging', False) or getattr(rule, 'log', False)
            
            if not logging_enabled:
                issue = SecurityIssue(
                    severity='low',
                    issue_type='logging_disabled',
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    description=f"Rule has no logging enabled",
                    recommendation="Enable logging for security monitoring and incident response",
                    risk_score=3
                )
                issues.append(issue)
        
        self.issues.extend(issues)
        return issues
    
    def get_audit_report(self) -> Dict:
        """Возвращает полный отчёт аудита."""
        # Сортируем issues по серьёзности
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_issues = sorted(
            self.issues,
            key=lambda x: severity_order.get(x.severity, 5)
        )
        
        return {
            'summary': {
                'total_rules_analyzed': len([r for r in self.rules if r.enabled]),
                'total_issues': len(self.issues),
                'critical': len([i for i in self.issues if i.severity == 'critical']),
                'high': len([i for i in self.issues if i.severity == 'high']),
                'medium': len([i for i in self.issues if i.severity == 'medium']),
                'low': len([i for i in self.issues if i.severity == 'low']),
                'avg_risk_score': sum(e.risk_score for e in self.risk_edges) / len(self.risk_edges) if self.risk_edges else 0
            },
            'issues': [
                {
                    'severity': issue.severity,
                    'type': issue.issue_type,
                    'rule': issue.rule_name,
                    'rule_id': issue.rule_id,
                    'description': issue.description,
                    'recommendation': issue.recommendation,
                    'risk_score': issue.risk_score
                }
                for issue in sorted_issues
            ],
            'high_risk_connections': [
                {
                    'source': edge.source,
                    'destination': edge.destination,
                    'risk_score': edge.risk_score,
                    'factors': edge.risk_factors
                }
                for edge in self.risk_edges[:20]  # Топ-20
            ]
        }
    
    def export_json(self, output_path: Path) -> Path:
        """Экспортирует отчёт в JSON."""
        report = self.get_audit_report()
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return output_path
    
    def print_summary(self):
        """Выводит сводку аудита в консоль."""
        report = self.get_audit_report()
        summary = report['summary']
        
        print("\n" + "="*60)
        print("SECURITY AUDIT REPORT")
        print("="*60)
        print(f"Rules analyzed:     {summary['total_rules_analyzed']}")
        print(f"Issues found:       {summary['total_issues']}")
        print(f"  Critical:         {summary['critical']}")
        print(f"  High:             {summary['high']}")
        print(f"  Medium:           {summary['medium']}")
        print(f"  Low:              {summary['low']}")
        print(f"Avg risk score:     {summary['avg_risk_score']:.1f}/10")
        print("="*60)
        
        if report['issues']:
            print("\nTOP ISSUES:")
            for issue in report['issues'][:10]:
                severity_marker = {
                    'critical': '[!!]',
                    'high': '[!]',
                    'medium': '[*]',
                    'low': '[.]',
                    'info': '[i]'
                }.get(issue['severity'], '[?]')
                print(f"{severity_marker} {issue['type']}: {issue['rule']}")
                print(f"    {issue['description']}")
                print(f"    Risk: {issue['risk_score']}/10")
        
        print()
