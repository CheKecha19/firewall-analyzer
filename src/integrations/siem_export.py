"""
SIEM Export
Экспорт результатов в SIEM системы (Splunk, ELK, QRadar, ArcSight).
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class SIEMExporter:
    """Экспортер для SIEM систем."""
    
    def __init__(self, analyzer_results: Dict):
        self.results = analyzer_results
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def export_splunk(self, output_path: str):
        """Экспортирует в Splunk HEC формат."""
        
        events = []
        
        # Аудит issues
        for issue in self.results.get('issues', []):
            event = {
                'time': self.timestamp,
                'sourcetype': 'firewall:audit',
                'event': {
                    'type': 'security_audit',
                    'check_type': issue.get('check_type'),
                    'severity': issue.get('severity'),
                    'description': issue.get('description'),
                    'rule_name': issue.get('rule_name'),
                    'risk_score': issue.get('risk_score', 0),
                    'source_ip': issue.get('source_ip'),
                    'destination_ip': issue.get('destination_ip'),
                    'port': issue.get('port'),
                    'action': issue.get('action'),
                    'file': issue.get('file', 'unknown'),
                    'environment': self.results.get('environment', 'production')
                }
            }
            events.append(json.dumps(event))
        
        # Сводная статистика
        summary = {
            'time': self.timestamp,
            'sourcetype': 'firewall:summary',
            'event': {
                'type': 'analysis_summary',
                'total_rules': self.results.get('total_rules', 0),
                'issues_found': self.results.get('total_issues', 0),
                'critical_count': self.results.get('critical_count', 0),
                'high_count': self.results.get('high_count', 0),
                'medium_count': self.results.get('medium_count', 0),
                'low_count': self.results.get('low_count', 0),
                'average_risk': self.results.get('average_risk', 0),
                'compliance_score': self.results.get('compliance_score', 0),
                'files_processed': self.results.get('files_processed', 0)
            }
        }
        events.append(json.dumps(summary))
        
        # Сохраняем
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(events))
        
        print(f"[OK] Splunk export: {output_path}")
    
    def export_elasticsearch(self, output_path: str):
        """Экспортирует в Elasticsearch bulk формат."""
        
        lines = []
        index = 'firewall-analysis'
        
        # Аудит issues
        for i, issue in enumerate(self.results.get('issues', [])):
            # Action metadata
            action = {
                'index': {
                    '_index': index,
                    '_type': '_doc',
                    '_id': f"audit-{i}"
                }
            }
            lines.append(json.dumps(action))
            
            # Document
            doc = {
                '@timestamp': self.timestamp,
                'type': 'security_audit',
                'check_type': issue.get('check_type'),
                'severity': issue.get('severity'),
                'description': issue.get('description'),
                'rule_name': issue.get('rule_name'),
                'risk_score': issue.get('risk_score', 0),
                'source_ip': issue.get('source_ip'),
                'destination_ip': issue.get('destination_ip'),
                'port': issue.get('port'),
                'action': issue.get('action'),
                'file': issue.get('file', 'unknown')
            }
            lines.append(json.dumps(doc))
        
        # Сводка
        action = {
            'index': {
                '_index': index,
                '_type': '_doc',
                '_id': 'summary'
            }
        }
        lines.append(json.dumps(action))
        
        summary_doc = {
            '@timestamp': self.timestamp,
            'type': 'analysis_summary',
            'total_rules': self.results.get('total_rules', 0),
            'issues_found': self.results.get('total_issues', 0),
            'average_risk': self.results.get('average_risk', 0)
        }
        lines.append(json.dumps(summary_doc))
        
        # Сохраняем
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        
        print(f"[OK] Elasticsearch export: {output_path}")
    
    def export_qradar(self, output_path: str):
        """Экспортирует в QRadar LEEF формат."""
        
        lines = []
        
        for issue in self.results.get('issues', []):
            # LEEF формат
            leef = (
                f"LEEF:2.0|FirewallAnalyzer|2.0|{issue.get('check_type', 'unknown')}"
                f"|cat={issue.get('check_type')}"
                f"\tdevTime={self.timestamp}"
                f"\tsev={self._severity_to_qradar(issue.get('severity', 'low'))}"
                f"\tmsg={issue.get('description', '')}"
                f"\tsrc={issue.get('source_ip', 'unknown')}"
                f"\tdst={issue.get('destination_ip', 'unknown')}"
                f"\tdport={issue.get('port', 'unknown')}"
                f"\taction={issue.get('action', 'unknown')}"
                f"\trule={issue.get('rule_name', 'unknown')}"
                f"\trisk={issue.get('risk_score', 0)}"
            )
            lines.append(leef)
        
        # Сохраняем
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"[OK] QRadar export: {output_path}")
    
    def export_cef(self, output_path: str):
        """Экспортирует в ArcSight CEF формат."""
        
        lines = []
        
        for issue in self.results.get('issues', []):
            # CEF формат
            cef = (
                f"CEF:0|FirewallAnalyzer|2.0|{issue.get('check_type', 'unknown')}"
                f"|{issue.get('check_type', 'unknown')}"
                f"|{self._severity_to_cef(issue.get('severity', 'low'))}"
                f"|rt={self.timestamp}"
                f" src={issue.get('source_ip', 'unknown')}"
                f" dst={issue.get('destination_ip', 'unknown')}"
                f" spt={issue.get('source_port', 'unknown')}"
                f" dpt={issue.get('port', 'unknown')}"
                f" act={issue.get('action', 'unknown')}"
                f" msg={issue.get('description', '')}"
                f" cs1={issue.get('rule_name', 'unknown')}"
                f" cs1Label=RuleName"
                f" cs2={issue.get('risk_score', 0)}"
                f" cs2Label=RiskScore"
            )
            lines.append(cef)
        
        # Сохраняем
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"[OK] ArcSight CEF export: {output_path}")
    
    def export_csv(self, output_path: str):
        """Экспортирует в CSV."""
        
        issues = self.results.get('issues', [])
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Заголовки
            writer.writerow([
                'Timestamp', 'Type', 'Severity', 'Description',
                'Rule', 'Source', 'Destination', 'Port', 'Action',
                'Risk Score', 'File'
            ])
            
            # Данные
            for issue in issues:
                writer.writerow([
                    self.timestamp,
                    issue.get('check_type', ''),
                    issue.get('severity', ''),
                    issue.get('description', ''),
                    issue.get('rule_name', ''),
                    issue.get('source_ip', ''),
                    issue.get('destination_ip', ''),
                    issue.get('port', ''),
                    issue.get('action', ''),
                    issue.get('risk_score', 0),
                    issue.get('file', '')
                ])
        
        print(f"[OK] CSV export: {output_path}")
    
    def export_syslog(self, output_path: str):
        """Экспортирует в Syslog формат."""
        
        lines = []
        
        for issue in self.results.get('issues', []):
            severity = self._severity_to_syslog(issue.get('severity', 'low'))
            msg = (
                f"{self.timestamp} {severity} firewall-analyzer: "
                f"[{issue.get('check_type', 'unknown')}] "
                f"{issue.get('severity', 'low').upper()}: "
                f"{issue.get('description', '')} "
                f"(rule={issue.get('rule_name', 'unknown')}, "
                f"risk={issue.get('risk_score', 0)})"
            )
            lines.append(msg)
        
        # Сохраняем
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"[OK] Syslog export: {output_path}")
    
    def _severity_to_qradar(self, severity: str) -> int:
        """Конвертирует severity в QRadar severity."""
        mapping = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3
        }
        return mapping.get(severity.lower(), 1)
    
    def _severity_to_cef(self, severity: str) -> str:
        """Конвертирует severity в CEF severity."""
        mapping = {
            'critical': '10',
            'high': '8',
            'medium': '5',
            'low': '3'
        }
        return mapping.get(severity.lower(), '1')
    
    def _severity_to_syslog(self, severity: str) -> str:
        """Конвертирует severity в Syslog severity."""
        mapping = {
            'critical': '<2>',  # Critical
            'high': '<3>',     # Error
            'medium': '<4>',    # Warning
            'low': '<6>'       # Informational
        }
        return mapping.get(severity.lower(), '<6>')


def export_all_formats(results: Dict, output_dir: str, base_name: str):
    """Экспортирует во все форматы."""
    
    exporter = SIEMExporter(results)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    
    print("\nExporting to SIEM formats...")
    
    exporter.export_splunk(output / f"{base_name}_splunk.json")
    exporter.export_elasticsearch(output / f"{base_name}_elastic.json")
    exporter.export_qradar(output / f"{base_name}_qradar.leef")
    exporter.export_cef(output / f"{base_name}_arcsight.cef")
    exporter.export_csv(output / f"{base_name}_siem.csv")
    exporter.export_syslog(output / f"{base_name}_syslog.log")
    
    print("[OK] All SIEM exports completed")


# Экспорт
__all__ = ['SIEMExporter', 'export_all_formats']
