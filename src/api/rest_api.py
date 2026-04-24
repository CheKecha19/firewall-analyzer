"""
REST API Server
Предоставляет HTTP API для анализа конфигураций.
"""

import json
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


class FirewallAPI:
    """REST API для firewall analyzer."""
    
    def __init__(self, analyzer=None):
        self.analyzer = analyzer
        self.version = "2.0.0"
    
    def get_status(self) -> Dict:
        """Возвращает статус API."""
        return {
            'status': 'ok',
            'version': self.version,
            'features': [
                'analyze',
                'audit',
                'topology',
                'vlan',
                'zone',
                'path-trace',
                'what-if',
                'temporal'
            ]
        }
    
    def analyze_config(self, config_content: str, source_type: str = 'auto') -> Dict:
        """Анализирует конфигурацию из строки."""
        # Сохраняем во временный файл
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(config_content)
            temp_path = f.name
        
        try:
            # Импортируем main
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from main import main
            
            # Запускаем анализ
            import argparse
            args = argparse.Namespace(
                input_path=temp_path,
                source=source_type,
                ext='.txt',
                recursive=False,
                output='api_analysis',
                output_dir='output',
                parallel=False,
                aggregate_subnets=False,
                aggregate_threshold=24,
                audit=True,
                risk_report=True,
                compliance=False,
                compliance_format='text',
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
            
            # Запускаем анализ
            result = main(args)
            
            # Читаем результаты
            output_dir = Path('output')
            
            result_data = {
                'status': 'success',
                'files_analyzed': 1,
                'output_files': {}
            }
            
            # Читаем JSON отчёты
            for json_file in output_dir.glob('api_analysis*.json'):
                with open(json_file, 'r', encoding='utf-8') as f:
                    result_data['output_files'][json_file.name] = json.load(f)
            
            return result_data
            
        finally:
            # Удаляем временный файл
            Path(temp_path).unlink(missing_ok=True)
    
    def get_audit_summary(self, rules: List) -> Dict:
        """Возвращает сводку аудита."""
        from src.core.security_auditor import SecurityAuditor
        
        auditor = SecurityAuditor()
        issues = auditor.audit(rules)
        
        return {
            'total_rules': len(rules),
            'issues_found': len(issues),
            'by_severity': {
                'critical': len([i for i in issues if i.severity == 'critical']),
                'high': len([i for i in issues if i.severity == 'high']),
                'medium': len([i for i in issues if i.severity == 'medium']),
                'low': len([i for i in issues if i.severity == 'low'])
            },
            'top_issues': [
                {
                    'type': i.check_type,
                    'severity': i.severity,
                    'description': i.description
                }
                for i in issues[:10]
            ]
        }
    
    def trace_path(self, source: str, destination: str, 
                   port: int = 80, protocol: str = 'tcp',
                   rules: List = None) -> Dict:
        """Трассирует путь между узлами."""
        from src.core.path_tracer import PathTracer
        
        tracer = PathTracer(rules or [])
        trace = tracer.trace(source, destination, port, protocol)
        
        return {
            'source': trace.source,
            'destination': trace.destination,
            'result': trace.result.value,
            'hops': [
                {
                    'device': h.device,
                    'action': h.action,
                    'details': h.details,
                    'risk': h.risk
                }
                for h in trace.hops
            ],
            'total_risk': trace.total_risk,
            'recommendation': trace.recommendation
        }
    
    def simulate_change(self, rules: List, 
                        change_type: str, **kwargs) -> Dict:
        """Симулирует изменение."""
        from src.core.what_if import WhatIfAnalyzer, RuleChange, ChangeType
        
        analyzer = WhatIfAnalyzer(rules)
        
        # Создаём изменение
        change_map = {
            'add': ChangeType.ADD_RULE,
            'remove': ChangeType.REMOVE_RULE,
            'change_action': ChangeType.CHANGE_ACTION
        }
        
        change = RuleChange(
            change_type=change_map.get(change_type, ChangeType.ADD_RULE),
            rule_id=kwargs.get('rule_id'),
            rule_name=kwargs.get('rule_name'),
            old_value=kwargs.get('old_value'),
            new_value=kwargs.get('new_value'),
            description=kwargs.get('description', ''),
            risk_delta=0.0
        )
        
        result = analyzer.simulate([change])
        
        return {
            'original_risk': result.original_risk,
            'new_risk': result.new_risk,
            'risk_delta': result.risk_delta,
            'impact': result.impact_score,
            'new_issues': result.new_issues,
            'resolved_issues': result.resolved_issues,
            'recommendations': result.recommendations
        }


# Простой HTTP сервер
from http.server import HTTPServer, BaseHTTPRequestHandler


class APIHandler(BaseHTTPRequestHandler):
    """HTTP обработчик для API."""
    
    api = FirewallAPI()
    
    def log_message(self, format, *args):
        """Отключаем логирование запросов."""
        pass
    
    def _send_json(self, data: Dict, status: int = 200):
        """Отправляет JSON ответ."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))
    
    def do_GET(self):
        """Обрабатывает GET запросы."""
        if self.path == '/api/status':
            self._send_json(self.api.get_status())
        
        elif self.path == '/api/health':
            self._send_json({'status': 'healthy'})
        
        else:
            self._send_json({'error': 'Not found'}, 404)
    
    def do_POST(self):
        """Обрабатывает POST запросы."""
        import urllib.parse
        
        # Читаем тело запроса
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json({'error': 'Invalid JSON'}, 400)
            return
        
        if self.path == '/api/analyze':
            # Анализ конфигурации
            config = data.get('config', '')
            source = data.get('source', 'auto')
            
            if not config:
                self._send_json({'error': 'Config required'}, 400)
                return
            
            result = self.api.analyze_config(config, source)
            self._send_json(result)
        
        elif self.path == '/api/audit':
            # Аудит правил
            rules = data.get('rules', [])
            result = self.api.get_audit_summary(rules)
            self._send_json(result)
        
        elif self.path == '/api/path-trace':
            # Трассировка пути
            source = data.get('source')
            dest = data.get('destination')
            port = data.get('port', 80)
            protocol = data.get('protocol', 'tcp')
            rules = data.get('rules', [])
            
            if not source or not dest:
                self._send_json({'error': 'Source and destination required'}, 400)
                return
            
            result = self.api.trace_path(source, dest, port, protocol, rules)
            self._send_json(result)
        
        elif self.path == '/api/what-if':
            # What-If анализ
            rules = data.get('rules', [])
            change_type = data.get('change_type', 'add')
            
            result = self.api.simulate_change(rules, change_type, **data)
            self._send_json(result)
        
        else:
            self._send_json({'error': 'Not found'}, 404)


def start_api_server(host: str = 'localhost', port: int = 8080):
    """Запускает API сервер."""
    server = HTTPServer((host, port), APIHandler)
    print(f"Firewall API server started at http://{host}:{port}")
    print("Endpoints:")
    print("  GET  /api/status      - API status")
    print("  GET  /api/health      - Health check")
    print("  POST /api/analyze     - Analyze config")
    print("  POST /api/audit       - Audit rules")
    print("  POST /api/path-trace  - Trace path")
    print("  POST /api/what-if     - What-If analysis")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


# Экспорт
__all__ = ['FirewallAPI', 'APIHandler', 'start_api_server']
