"""
Модуль аудита соответствия стандартам (Compliance Audit).
Поддерживает PCI DSS, CIS Benchmarks, NIST.
"""
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import re

from ..models.rule import FirewallRule
from ..models.endpoint import Endpoint


class ComplianceStandard(Enum):
    """Поддерживаемые стандарты compliance."""
    PCI_DSS = "pci_dss"           # Payment Card Industry
    CIS = "cis"                   # Center for Internet Security
    NIST = "nist"                 # NIST Cybersecurity Framework
    ISO27001 = "iso27001"         # ISO/IEC 27001
    SOX = "sox"                   # Sarbanes-Oxley


class Severity(Enum):
    """Уровень критичности нарушения."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceRequirement:
    """Требование стандарта compliance."""
    standard: ComplianceStandard
    control_id: str              # ID контроля (например "PCI-DSS-1.1")
    title: str                   # Название требования
    description: str             # Описание
    severity: Severity           # Критичность
    check_function: str          # Имя функции проверки
    remediation: str             # Рекомендации по исправлению


@dataclass
class ComplianceViolation:
    """Нарушение требования compliance."""
    requirement: ComplianceRequirement
    severity: Severity
    message: str
    affected_rules: List[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class ComplianceReport:
    """Отчёт по compliance."""
    standard: ComplianceStandard
    violations: List[ComplianceViolation] = field(default_factory=list)
    passed_checks: List[str] = field(default_factory=list)
    
    @property
    def total_checks(self) -> int:
        return len(self.violations) + len(self.passed_checks)
    
    @property
    def compliance_score(self) -> float:
        """Возвращает процент соответствия (0-100)."""
        if self.total_checks == 0:
            return 100.0
        passed = len(self.passed_checks)
        return (passed / self.total_checks) * 100
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.MEDIUM)


class ComplianceAuditor:
    """Выполняет аудит compliance по различным стандартам."""
    
    # Критичные порты по PCI DSS
    PCI_CRITICAL_PORTS = {22, 23, 3389, 5900}  # SSH, Telnet, RDP, VNC
    PCI_SENSITIVE_DATA_PORTS = {1433, 3306, 5432, 1521, 27017}  # Базы данных
    
    # Порты для CIS
    CIS_MANAGEMENT_PORTS = {22, 23, 3389, 5900, 5985, 5986}
    
    def __init__(self, rules: List[FirewallRule]):
        """
        Args:
            rules: Список правил firewall для проверки
        """
        self.rules = rules
        self.requirements: Dict[ComplianceStandard, List[ComplianceRequirement]] = {}
        self._load_requirements()
    
    def _load_requirements(self):
        """Загружает требования для всех стандартов."""
        # PCI DSS требования
        self.requirements[ComplianceStandard.PCI_DSS] = [
            ComplianceRequirement(
                standard=ComplianceStandard.PCI_DSS,
                control_id="PCI-DSS-1.1",
                title="Default Deny",
                description="Firewall must implement default deny-all rule",
                severity=Severity.CRITICAL,
                check_function="_check_pci_default_deny",
                remediation="Add explicit deny-all rule at the end of ACL"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.PCI_DSS,
                control_id="PCI-DSS-1.2",
                title="Restrict Inbound Traffic",
                description="Inbound traffic must be restricted to necessary ports",
                severity=Severity.HIGH,
                check_function="_check_pci_inbound_restriction",
                remediation="Review and limit inbound service ports"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.PCI_DSS,
                control_id="PCI-DSS-1.3",
                title="Deny Management from Internet",
                description="Management protocols must not be accessible from Internet",
                severity=Severity.CRITICAL,
                check_function="_check_pci_mgmt_access",
                remediation="Restrict SSH/Telnet/RDP access to internal networks only"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.PCI_DSS,
                control_id="PCI-DSS-1.4",
                title="Database Protection",
                description="Database ports must not be exposed to Internet",
                severity=Severity.CRITICAL,
                check_function="_check_pci_database_exposure",
                remediation="Remove direct Internet access to database ports"
            ),
        ]
        
        # CIS требования
        self.requirements[ComplianceStandard.CIS] = [
            ComplianceRequirement(
                standard=ComplianceStandard.CIS,
                control_id="CIS-3.1",
                title="Disable Unused Rules",
                description="Disabled or unused firewall rules should be removed",
                severity=Severity.MEDIUM,
                check_function="_check_cis_unused_rules",
                remediation="Remove disabled rules from configuration"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.CIS,
                control_id="CIS-3.2",
                title="Log All Dropped Traffic",
                description="All denied traffic should be logged",
                severity=Severity.MEDIUM,
                check_function="_check_cis_logging",
                remediation="Enable logging for deny rules"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.CIS,
                control_id="CIS-3.3",
                title="Restrict Management Access",
                description="Administrative access should be from dedicated management network",
                severity=Severity.HIGH,
                check_function="_check_cis_mgmt_network",
                remediation="Restrict management access to specific admin networks"
            ),
        ]
        
        # NIST требования
        self.requirements[ComplianceStandard.NIST] = [
            ComplianceRequirement(
                standard=ComplianceStandard.NIST,
                control_id="NIST-PR.AC-3",
                title="Remote Access Control",
                description="Remote access must be monitored and controlled",
                severity=Severity.HIGH,
                check_function="_check_nist_remote_access",
                remediation="Implement strict controls for remote access rules"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.NIST,
                control_id="NIST-PR.AC-5",
                title="Network Integrity",
                description="Network integrity should be protected",
                severity=Severity.MEDIUM,
                check_function="_check_nist_network_integrity",
                remediation="Segment network and implement least privilege"
            ),
        ]
    
    def audit(self, standard: ComplianceStandard) -> ComplianceReport:
        """
        Выполняет аудит по указанному стандарту.
        
        Args:
            standard: Стандарт для проверки
            
        Returns:
            ComplianceReport с результатами
        """
        report = ComplianceReport(standard=standard)
        
        requirements = self.requirements.get(standard, [])
        
        for req in requirements:
            check_func = getattr(self, req.check_function, None)
            if check_func:
                violation = check_func(req)
                if violation:
                    report.violations.append(violation)
                else:
                    report.passed_checks.append(req.control_id)
        
        # Сортируем по severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        report.violations.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        return report
    
    def audit_all(self) -> Dict[ComplianceStandard, ComplianceReport]:
        """Выполняет аудит по всем стандартам."""
        return {std: self.audit(std) for std in ComplianceStandard}
    
    # ===== PCI DSS Checks =====
    
    def _check_pci_default_deny(self, req: ComplianceRequirement) -> Optional[ComplianceViolation]:
        """Проверяет наличие default deny rule."""
        has_deny_all = False
        
        for rule in self.rules:
            if (rule.action.lower() in ("deny", "drop") and 
                any(s.name == "any" for s in rule.services) and
                any(e.name == "any" for e in rule.sources) and
                any(e.name == "any" for e in rule.destinations)):
                has_deny_all = True
                break
        
        if not has_deny_all:
            return ComplianceViolation(
                requirement=req,
                severity=req.severity,
                message="No explicit deny-all rule found at end of ACL",
                remediation=req.remediation
            )
        return None
    
    def _check_pci_inbound_restriction(self, req: ComplianceRequirement) -> Optional[ComplianceViolation]:
        """Проверяет ограничение входящего трафика."""
        open_rules = []
        
        for rule in self.rules:
            if rule.action.lower() in ("accept", "allow", "permit"):
                # Проверяем широкие разрешения
                if any(e.name == "any" for e in rule.sources):
                    services = [s.name for s in rule.services]
                    if "any" in services or len(services) > 10:
                        open_rules.append(rule.name)
        
        if open_rules:
            return ComplianceViolation(
                requirement=req,
                severity=req.severity,
                message=f"{len(open_rules)} rules allow wide inbound access",
                affected_rules=open_rules[:10],
                remediation=req.remediation
            )
        return None
    
    def _check_pci_mgmt_access(self, req: ComplianceRequirement) -> Optional[ComplianceViolation]:
        """Проверяет доступ к management портам из Internet."""
        violations = []
        
        for rule in self.rules:
            if rule.action.lower() not in ("accept", "allow", "permit"):
                continue
            
            # Проверяем management порты
            for svc in rule.services:
                ports = self._parse_ports(svc.ports)
                if any(p in self.PCI_CRITICAL_PORTS for p in ports):
                    # Проверяем источник
                    for src in rule.sources:
                        if self._is_internet_accessible(src.name):
                            violations.append(rule.name)
                            break
        
        if violations:
            return ComplianceViolation(
                requirement=req,
                severity=req.severity,
                message=f"Management protocols accessible from Internet: {len(violations)} rules",
                affected_rules=violations[:10],
                remediation=req.remediation
            )
        return None
    
    def _check_pci_database_exposure(self, req: ComplianceRequirement) -> Optional[ComplianceViolation]:
        """Проверяет доступность баз данных из Internet."""
        violations = []
        
        for rule in self.rules:
            if rule.action.lower() not in ("accept", "allow", "permit"):
                continue
            
            for svc in rule.services:
                ports = self._parse_ports(svc.ports)
                if any(p in self.PCI_SENSITIVE_DATA_PORTS for p in ports):
                    for src in rule.sources:
                        if self._is_internet_accessible(src.name):
                            violations.append(rule.name)
                            break
        
        if violations:
            return ComplianceViolation(
                requirement=req,
                severity=req.severity,
                message=f"Database ports exposed to Internet: {len(violations)} rules",
                affected_rules=violations[:10],
                remediation=req.remediation
            )
        return None
    
    # ===== CIS Checks =====
    
    def _check_cis_unused_rules(self, req: ComplianceRequirement) -> Optional[ComplianceViolation]:
        """Проверяет наличие неиспользуемых (disabled) правил."""
        disabled = [r.name for r in self.rules if not r.enabled]
        
        if disabled:
            return ComplianceViolation(
                requirement=req,
                severity=req.severity,
                message=f"{len(disabled)} disabled rules should be removed",
                affected_rules=disabled[:10],
                remediation=req.remediation
            )
        return None
    
    def _check_cis_logging(self, req: ComplianceRequirement) -> Optional[ComplianceViolation]:
        """Проверяет logging для deny правил."""
        # Заглушка - требует метаданных о logging
        return None
    
    def _check_cis_mgmt_network(self, req: ComplianceRequirement) -> Optional[ComplianceViolation]:
        """Проверяет доступ к management из dedicated сети."""
        violations = []
        
        for rule in self.rules:
            if rule.action.lower() not in ("accept", "allow", "permit"):
                continue
            
            for svc in rule.services:
                ports = self._parse_ports(svc.ports)
                if any(p in self.CIS_MANAGEMENT_PORTS for p in ports):
                    for src in rule.sources:
                        if src.name not in ("management", "mgmt", "admin") and \
                           not src.name.startswith("10.") and \
                           not src.name.startswith("192.168."):
                            violations.append(rule.name)
                            break
        
        if violations:
            return ComplianceViolation(
                requirement=req,
                severity=req.severity,
                message=f"Management access not restricted to admin network: {len(violations)} rules",
                affected_rules=violations[:10],
                remediation=req.remediation
            )
        return None
    
    # ===== NIST Checks =====
    
    def _check_nist_remote_access(self, req: ComplianceRequirement) -> Optional[ComplianceViolation]:
        """Проверяет контроль удалённого доступа."""
        vpn_rules = []
        
        for rule in self.rules:
            if "vpn" in rule.name.lower() or "remote" in rule.name.lower():
                vpn_rules.append(rule.name)
        
        if not vpn_rules and len(self.rules) > 0:
            return ComplianceViolation(
                requirement=req,
                severity=Severity.INFO,
                message="No explicit remote access rules found - review required",
                remediation="Document and verify remote access controls"
            )
        return None
    
    def _check_nist_network_integrity(self, req: ComplianceRequirement) -> Optional[ComplianceViolation]:
        """Проверяет целостность сети."""
        # Проверяем наличие сегментации
        has_any_rules = sum(1 for r in self.rules 
                          if any(e.name == "any" for e in r.sources))
        
        if has_any_rules > len(self.rules) * 0.5:
            return ComplianceViolation(
                requirement=req,
                severity=req.severity,
                message=f"High number of 'any' source rules ({has_any_rules}) - poor segmentation",
                remediation="Implement network segmentation with specific source networks"
            )
        return None
    
    # ===== Helper Methods =====
    
    def _parse_ports(self, port_str: str) -> Set[int]:
        """Парсит строку портов в множество чисел."""
        ports = set()
        
        if not port_str or port_str.lower() == "any":
            return ports
        
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                # Диапазон
                try:
                    start, end = part.split('-', 1)
                    ports.update(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    continue
        
        return ports
    
    def _is_internet_accessible(self, endpoint: str) -> bool:
        """Проверяет, является ли endpoint доступным из Internet."""
        endpoint_lower = endpoint.lower()
        
        # Явно Internet
        if endpoint_lower in ("any", "0.0.0.0/0", "internet", "public"):
            return True
        
        # Проверяем публичные IP
        if endpoint_lower.startswith("0.") or endpoint_lower.startswith("::/0"):
            return True
        
        # RFC 1918 приватные сети - не Internet
        private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                           "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                           "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                           "172.29.", "172.30.", "172.31.")
        
        if any(endpoint_lower.startswith(p) for p in private_prefixes):
            return False
        
        # Если не приватный и содержит / - проверяем маску
        if '/' in endpoint:
            try:
                import ipaddress
                network = ipaddress.ip_network(endpoint, strict=False)
                # Проверяем, является ли сеть публичной
                if network.is_private or network.is_loopback or network.is_link_local:
                    return False
                return True
            except ValueError:
                pass
        
        return True  # По умолчанию считаем потенциально публичным
    
    def generate_report(self, report: ComplianceReport, format: str = "text") -> str:
        """Генерирует отчёт о compliance."""
        if format == "json":
            return self._generate_json_report(report)
        elif format == "html":
            return self._generate_html_report(report)
        else:
            return self._generate_text_report(report)
    
    def _generate_text_report(self, report: ComplianceReport) -> str:
        """Генерирует текстовый отчёт."""
        lines = [
            "=" * 70,
            f"COMPLIANCE AUDIT REPORT: {report.standard.value.upper()}",
            "=" * 70,
            "",
            f"Compliance Score: {report.compliance_score:.1f}%",
            f"Total Checks: {report.total_checks}",
            f"Passed: {len(report.passed_checks)}",
            f"Failed: {len(report.violations)}",
            "",
            "SEVERITY BREAKDOWN:",
            f"  Critical: {report.critical_count}",
            f"  High: {report.high_count}",
            f"  Medium: {report.medium_count}",
            "",
        ]
        
        if report.violations:
            lines.extend([
                "-" * 70,
                "VIOLATIONS:",
                "-" * 70,
                ""
            ])
            
            for v in report.violations:
                lines.append(f"[{v.severity.value.upper()}] {v.requirement.control_id}: {v.requirement.title}")
                lines.append(f"  {v.message}")
                if v.affected_rules:
                    lines.append(f"  Rules: {', '.join(v.affected_rules[:5])}")
                lines.append(f"  Remediation: {v.remediation or v.requirement.remediation}")
                lines.append("")
        else:
            lines.extend([
                "-" * 70,
                "✓ ALL CHECKS PASSED",
                "-" * 70,
                ""
            ])
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def _generate_json_report(self, report: ComplianceReport) -> str:
        """Генерирует JSON отчёт."""
        import json
        
        data = {
            'standard': report.standard.value,
            'score': report.compliance_score,
            'summary': {
                'total': report.total_checks,
                'passed': len(report.passed_checks),
                'failed': len(report.violations),
                'critical': report.critical_count,
                'high': report.high_count,
                'medium': report.medium_count
            },
            'violations': [
                {
                    'control_id': v.requirement.control_id,
                    'title': v.requirement.title,
                    'severity': v.severity.value,
                    'message': v.message,
                    'affected_rules': v.affected_rules,
                    'remediation': v.remediation or v.requirement.remediation
                }
                for v in report.violations
            ],
            'passed': report.passed_checks
        }
        
        return json.dumps(data, indent=2)
    
    def _generate_html_report(self, report: ComplianceReport) -> str:
        """Генерирует HTML отчёт."""
        # Определяем цвет в зависимости от score
        if report.compliance_score >= 90:
            score_color = "green"
        elif report.compliance_score >= 70:
            score_color = "orange"
        else:
            score_color = "red"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report - {report.standard.value.upper()}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        .score {{ font-size: 48px; color: {score_color}; text-align: center; margin: 20px 0; }}
        .summary {{ display: flex; justify-content: space-around; background: #f9f9f9; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .summary-item {{ text-align: center; }}
        .summary-item .number {{ font-size: 32px; font-weight: bold; color: #667eea; }}
        .severity-critical {{ background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }}
        .severity-high {{ background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }}
        .severity-medium {{ background: #fff8e1; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }}
        .violation-title {{ font-weight: bold; color: #333; }}
        .violation-message {{ margin: 5px 0; color: #666; }}
        .violation-rules {{ font-size: 12px; color: #999; }}
        .remediation {{ background: #e3f2fd; padding: 10px; margin-top: 10px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Report: {report.standard.value.upper()}</h1>
        
        <div class="score">{report.compliance_score:.1f}%</div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="number">{report.total_checks}</div>
                <div>Total Checks</div>
            </div>
            <div class="summary-item">
                <div class="number">{len(report.passed_checks)}</div>
                <div>Passed</div>
            </div>
            <div class="summary-item">
                <div class="number">{len(report.violations)}</div>
                <div>Failed</div>
            </div>
        </div>
        
        <h2>Violations</h2>
"""
        
        for v in report.violations:
            html += f"""
        <div class="severity-{v.severity.value}">
            <div class="violation-title">[{v.severity.value.upper()}] {v.requirement.control_id}: {v.requirement.title}</div>
            <div class="violation-message">{v.message}</div>
            {f'<div class="violation-rules">Rules: {", ".join(v.affected_rules[:5])}</div>' if v.affected_rules else ''}
            <div class="remediation"><strong>Remediation:</strong> {v.remediation or v.requirement.remediation}</div>
        </div>
"""
        
        html += """
    </div>
</body>
</html>"""
        
        return html
