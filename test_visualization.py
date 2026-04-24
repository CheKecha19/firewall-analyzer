#!/usr/bin/env python3
"""Тест визуализации с демо-данными."""
import sys
from pathlib import Path

# Добавляем src в путь
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.core import FirewallAnalyzer
from src.models.endpoint import Endpoint
from src.models.service import Service
from src.models.rule import FirewallRule
from src.graph.visualizer import GraphVisualizer

def create_demo_rules():
    """Создаёт демо-правила для теста."""
    rules = []
    
    # Создаём endpoints
    endpoints = {
        '192.168.1.1': Endpoint('192.168.1.1', 'host'),
        '192.168.1.10': Endpoint('192.168.1.10', 'host'),
        '192.168.1.20': Endpoint('192.168.1.20', 'host'),
        '192.168.2.0/24': Endpoint('192.168.2.0/24', 'subnet'),
        'any': Endpoint('any', 'host'),
    }
    
    # Создаём services
    services = {
        'ssh': Service('ssh', ['tcp/22']),
        'http': Service('http', ['tcp/80']),
        'https': Service('https', ['tcp/443']),
        'ip': Service('ip', []),
    }
    
    # Создаём правила
    rule1 = FirewallRule(
        name='rule_ssh_admin',
        sources=[endpoints['192.168.1.1']],
        destinations=[endpoints['192.168.1.10']],
        services=[services['ssh']],
        action='accept',
        enabled=True
    )
    
    rule2 = FirewallRule(
        name='rule_web_dmz',
        sources=[endpoints['192.168.2.0/24']],
        destinations=[endpoints['192.168.1.20']],
        services=[services['http'], services['https']],
        action='accept',
        enabled=True
    )
    
    rule3 = FirewallRule(
        name='rule_any_danger',
        sources=[endpoints['any']],
        destinations=[endpoints['any']],
        services=[services['ip']],
        action='accept',
        enabled=True
    )
    
    return [rule1, rule2, rule3]

def main():
    print("Creating demo data...")
    
    # Создаём анализатор
    analyzer = FirewallAnalyzer()
    
    # Добавляем правила
    rules = create_demo_rules()
    analyzer.add_rules(rules, "demo_config")
    
    print(f"Added {len(rules)} rules")
    
    # Строим граф
    print("Building graph...")
    analyzer.build_graph()
    
    print(f"Graph nodes: {analyzer.graph.number_of_nodes()}")
    print(f"Graph edges: {analyzer.graph.number_of_edges()}")
    
    if analyzer.graph.number_of_nodes() == 0:
        print("[ERROR] No nodes in graph!")
        return 1
    
    # Создаём визуализатор
    print("Creating visualizer...")
    visualizer = GraphVisualizer(analyzer.graph, analyzer.rules)
    
    # Генерируем HTML
    output_path = Path('output/test_visualization.html')
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating HTML: {output_path}")
    result = visualizer.generate_html(output_path, title="Demo Visualization Test")
    
    if result:
        print(f"[OK] HTML saved: {result}")
        
        # Проверяем содержимое
        with open(result, 'r', encoding='utf-8') as f:
            content = f.read()
            
        if 'nodesData = []' in content:
            print("[WARN] Empty nodesData in HTML!")
        elif 'nodesData = [{"id"' in content:
            print("[OK] nodesData contains data!")
            
        if 'edgesData = []' in content:
            print("[WARN] Empty edgesData in HTML!")
        elif 'edgesData = [{"' in content:
            print("[OK] edgesData contains data!")
            
        print(f"\nHTML file size: {len(content)} bytes")
        
    else:
        print("[ERROR] Failed to generate HTML")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
