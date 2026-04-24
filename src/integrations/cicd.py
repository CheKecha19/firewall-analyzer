"""
CI/CD Integration
Интеграция с GitLab CI, GitHub Actions, Jenkins.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class CIResult:
    """Результат CI проверки."""
    success: bool
    issues_found: int
    critical_issues: int
    risk_score: float
    details: str
    output_files: List[str]
    exit_code: int


class CICDIntegration:
    """Интеграция с CI/CD системами."""
    
    # CI environment detection
    CI_ENVIRONMENTS = {
        'GITLAB_CI': 'gitlab',
        'GITHUB_ACTIONS': 'github',
        'JENKINS_HOME': 'jenkins',
        'CIRCLECI': 'circle',
        'TRAVIS': 'travis'
    }
    
    def __init__(self):
        self.ci_type = self._detect_ci()
        self.is_ci = self.ci_type is not None
    
    def _detect_ci(self) -> Optional[str]:
        """Определяет тип CI окружения."""
        for env_var, ci_name in self.CI_ENVIRONMENTS.items():
            if os.environ.get(env_var):
                return ci_name
        return None
    
    def run_pipeline_check(self, configs_path: str, 
                          max_critical: int = 0,
                          max_risk: float = 7.0) -> CIResult:
        """Запускает проверку в CI pipeline."""
        
        print(f"Running in {self.ci_type or 'local'} environment")
        
        # Импортируем основной анализатор
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        
        # Запускаем анализ
        from main import main
        import argparse
        
        # Создаём args
        args = argparse.Namespace(
            input_path=configs_path,
            source='auto',
            ext='.txt',
            recursive=True,
            output='ci_analysis',
            output_dir='output',
            parallel=True,
            aggregate_subnets=True,
            aggregate_threshold=24,
            audit=True,
            risk_report=True,
            compliance=True,
            compliance_format='json',
            diff_old=None,
            diff_new=None,
            diff_format='text',
            reachability_check=False,
            reachability_source=None,
            reachability_destination=None,
            reachability_port=80,
            reachability_proto='tcp',
            topology=False,
            topology_format='json',
            vlan_view=False,
            zone_view=False,
            zone_matrix=False,
            what_if=False,
            what_if_add=None,
            what_if_remove=None,
            what_if_change_action=None,
            path_trace=False,
            path_source=None,
            path_dest=None,
            path_port=80,
            temporal_view=False,
            temporal_days=30,
            dot=False,
            png=False,
            html=False,
            verbose=False,
            version=False
        )
        
        # Запускаем
        try:
            result = main(args)
            
            # Читаем результаты
            output_dir = Path('output')
            risk_file = output_dir / 'ci_analysis_risk.json'
            
            issues_found = 0
            critical = 0
            risk = 0.0
            
            if risk_file.exists():
                with open(risk_file, 'r', encoding='utf-8') as f:
                    risk_data = json.load(f)
                issues_found = risk_data.get('total_issues', 0)
                critical = risk_data.get('by_severity', {}).get('critical', 0)
                risk = risk_data.get('average_risk', 0)
            
            # Определяем успешность
            success = critical <= max_critical and risk <= max_risk
            exit_code = 0 if success else 1
            
            # Генерируем CI-friendly отчёт
            details = self._format_ci_report(
                issues_found, critical, risk,
                max_critical, max_risk
            )
            
            # Сохраняем отчёт
            report_file = output_dir / 'ci_report.json'
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'success': success,
                    'issues': issues_found,
                    'critical': critical,
                    'risk': risk,
                    'threshold_critical': max_critical,
                    'threshold_risk': max_risk
                }, f, ensure_ascii=False, indent=2)
            
            output_files = [str(report_file)]
            if risk_file.exists():
                output_files.append(str(risk_file))
            
            return CIResult(
                success=success,
                issues_found=issues_found,
                critical_issues=critical,
                risk_score=risk,
                details=details,
                output_files=output_files,
                exit_code=exit_code
            )
            
        except Exception as e:
            return CIResult(
                success=False,
                issues_found=0,
                critical_issues=0,
                risk_score=10.0,
                details=f"Analysis failed: {str(e)}",
                output_files=[],
                exit_code=2
            )
    
    def _format_ci_report(self, issues: int, critical: int, 
                          risk: float, max_crit: int, max_risk: float) -> str:
        """Форматирует отчёт для CI."""
        lines = [
            "=" * 60,
            "FIREWALL ANALYSIS CI REPORT",
            "=" * 60,
            "",
            f"Issues found:     {issues}",
            f"Critical issues:  {critical} (max: {max_crit})",
            f"Average risk:     {risk:.1f} (max: {max_risk})",
            "",
        ]
        
        if critical > max_crit:
            lines.append("❌ FAILED: Too many critical issues")
        if risk > max_risk:
            lines.append("❌ FAILED: Risk too high")
        
        if critical <= max_crit and risk <= max_risk:
            lines.append("✅ PASSED: All checks passed")
        
        lines.extend([
            "",
            "=" * 60,
        ])
        
        return "\n".join(lines)
    
    def generate_badge(self, result: CIResult, output_path: str):
        """Генерирует SVG badge для README."""
        
        color = 'brightgreen' if result.success else 'red'
        status = 'passed' if result.success else 'failed'
        
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="180" height="20">
  <linearGradient id="a" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="180" height="20" fill="#555"/>
  <rect rx="3" x="100" width="80" height="20" fill="{color}"/>
  <path fill="{color}" d="M100 0h4v20h-4z"/>
  <rect rx="3" width="180" height="20" fill="url(#a)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="50" y="15" fill="#010101" fill-opacity=".3">firewall</text>
    <text x="50" y="14">firewall</text>
    <text x="140" y="15" fill="#010101" fill-opacity=".3">{status}</text>
    <text x="140" y="14">{status}</text>
  </g>
</svg>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(svg)


class GitLabFormatter:
    """Форматер для GitLab CI."""
    
    @staticmethod
    def format_code_quality_issues(issues: List[Dict]) -> List[Dict]:
        """Форматирует issues в GitLab Code Quality формат."""
        return [
            {
                'description': i.get('description', ''),
                'check_name': i.get('check_type', 'unknown'),
                'fingerprint': i.get('rule_id', 'unknown'),
                'severity': i.get('severity', 'minor'),
                'location': {
                    'path': i.get('file', 'config.txt'),
                    'lines': {
                        'begin': i.get('line', 0)
                    }
                }
            }
            for i in issues
        ]


class GitHubFormatter:
    """Форматер для GitHub Actions."""
    
    @staticmethod
    def format_annotations(issues: List[Dict]) -> List[Dict]:
        """Форматирует issues в GitHub Annotations формат."""
        severity_map = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'notice'
        }
        
        return [
            {
                'path': i.get('file', 'config.txt'),
                'start_line': i.get('line', 0),
                'end_line': i.get('line', 0),
                'annotation_level': severity_map.get(i.get('severity', 'low'), 'notice'),
                'message': i.get('description', ''),
                'title': i.get('check_type', 'Issue')
            }
            for i in issues
        ]


# Экспорт
__all__ = [
    'CICDIntegration', 'CIResult',
    'GitLabFormatter', 'GitHubFormatter'
]
