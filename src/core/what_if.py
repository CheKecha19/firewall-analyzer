"""
What-If Analyzer
Симулирует изменения конфигурации без применения.
"""

import copy
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class ChangeType(Enum):
    ADD_RULE = "add_rule"
    REMOVE_RULE = "remove_rule"
    MODIFY_RULE = "modify_rule"
    CHANGE_ACTION = "change_action"
    CHANGE_SOURCE = "change_source"
    CHANGE_DEST = "change_dest"
    CHANGE_SERVICE = "change_service"


@dataclass
class RuleChange:
    """Одно изменение правила."""
    change_type: ChangeType
    rule_id: Optional[str]
    rule_name: Optional[str]
    old_value: Optional[str]
    new_value: Optional[str]
    description: str
    risk_delta: float = 0.0


@dataclass
class WhatIfResult:
    """Результат What-If анализа."""
    original_risk: float
    new_risk: float
    risk_delta: float
    changes: List[RuleChange] = field(default_factory=list)
    affected_flows: List[Dict] = field(default_factory=list)
    new_issues: List[str] = field(default_factory=list)
    resolved_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    impact_score: float = 0.0


class WhatIfAnalyzer:
    """Анализатор What-If сценариев."""
    
    def __init__(self, rules: List, topology=None, topology_builder=None):
        self.original_rules = rules
        self.topology = topology
        self.topology_builder = topology_builder
        self.original_risk = self._calculate_overall_risk(rules)
    
    def simulate(self, changes: List[RuleChange]) -> WhatIfResult:
        """Симулирует изменения и возвращает результат."""
        
        # Копируем правила
        new_rules = copy.deepcopy(self.original_rules)
        
        # Применяем изменения
        applied_changes = []
        affected_flows = []
        
        for change in changes:
            result = self._apply_change(new_rules, change)
            if result:
                applied_changes.append(change)
                if result.get('affected'):
                    affected_flows.extend(result['affected'])
        
        # Рассчитываем новый риск
        new_risk = self._calculate_overall_risk(new_rules)
        risk_delta = new_risk - self.original_risk
        
        # Анализируем влияние
        new_issues = self._find_new_issues(new_rules, self.original_rules)
        resolved = self._find_resolved_issues(new_rules, self.original_rules)
        recommendations = self._generate_recommendations(changes, risk_delta)
        
        # Impact score
        impact = self._calculate_impact(applied_changes, affected_flows)
        
        return WhatIfResult(
            original_risk=self.original_risk,
            new_risk=new_risk,
            risk_delta=risk_delta,
            changes=applied_changes,
            affected_flows=affected_flows,
            new_issues=new_issues,
            resolved_issues=resolved,
            recommendations=recommendations,
            impact_score=impact
        )
    
    def compare_scenarios(self, scenario1: List[RuleChange], 
                          scenario2: List[RuleChange]) -> Dict:
        """Сравнивает два сценария изменений."""
        result1 = self.simulate(scenario1)
        result2 = self.simulate(scenario2)
        
        return {
            'scenario1': {
                'risk_delta': result1.risk_delta,
                'impact': result1.impact_score,
                'issues_created': len(result1.new_issues),
                'issues_resolved': len(result1.resolved_issues),
                'recommendations': result1.recommendations
            },
            'scenario2': {
                'risk_delta': result2.risk_delta,
                'impact': result2.impact_score,
                'issues_created': len(result2.new_issues),
                'issues_resolved': len(result2.resolved_issues),
                'recommendations': result2.recommendations
            },
            'comparison': {
                'better_scenario': 1 if result1.risk_delta < result2.risk_delta else 2,
                'risk_difference': abs(result1.risk_delta - result2.risk_delta),
                'recommendation': f"Scenario {1 if result1.risk_delta < result2.risk_delta else 2} is safer"
            }
        }
    
    def _apply_change(self, rules: List, change: RuleChange) -> Optional[Dict]:
        """Применяет одно изменение к списку правил."""
        
        if change.change_type == ChangeType.ADD_RULE:
            # Создаём новое правило
            new_rule = type('Rule', (), {
                'id': change.rule_id or f"new_{len(rules)}",
                'name': change.rule_name or 'New Rule',
                'source': 'any',
                'destination': 'any',
                'service': 'any',
                'action': 'permit',
                'risk_score': 5.0
            })()
            rules.append(new_rule)
            return {'success': True, 'affected': [{
                'type': 'new_rule',
                'rule': change.rule_name
            }]}
        
        elif change.change_type == ChangeType.REMOVE_RULE:
            # Удаляем правило
            for i, rule in enumerate(rules):
                if getattr(rule, 'id', None) == change.rule_id or \
                   getattr(rule, 'name', None) == change.rule_name:
                    removed = rules.pop(i)
                    return {'success': True, 'affected': [{
                        'type': 'removed',
                        'rule': getattr(removed, 'name', 'unknown')
                    }]}
            return None
        
        elif change.change_type == ChangeType.CHANGE_ACTION:
            # Меняем действие
            for rule in rules:
                if getattr(rule, 'id', None) == change.rule_id:
                    old_action = getattr(rule, 'action', 'unknown')
                    rule.action = change.new_value
                    return {'success': True, 'affected': [{
                        'type': 'action_changed',
                        'rule': getattr(rule, 'name', 'unknown'),
                        'from': old_action,
                        'to': change.new_value
                    }]}
            return None
        
        elif change.change_type == ChangeType.CHANGE_SOURCE:
            # Меняем источник
            for rule in rules:
                if getattr(rule, 'id', None) == change.rule_id:
                    old_src = getattr(rule, 'source', 'any')
                    rule.source = change.new_value
                    return {'success': True, 'affected': [{
                        'type': 'source_changed',
                        'rule': getattr(rule, 'name', 'unknown'),
                        'from': old_src,
                        'to': change.new_value
                    }]}
            return None
        
        return None
    
    def _calculate_overall_risk(self, rules: List) -> float:
        """Рассчитывает общий риск конфигурации."""
        if not rules:
            return 0.0
        
        total = sum(getattr(r, 'risk_score', 5.0) for r in rules)
        return round(total / len(rules), 2)
    
    def _find_new_issues(self, new_rules: List, old_rules: List) -> List[str]:
        """Находит новые проблемы."""
        issues = []
        
        # Проверяем any-any правила
        any_any = [r for r in new_rules 
                   if getattr(r, 'source', '') == 'any' 
                   and getattr(r, 'destination', '') == 'any'
                   and getattr(r, 'action', '') == 'permit']
        
        for r in any_any:
            # Проверяем, было ли оно в старых правилах
            old = [o for o in old_rules 
                   if getattr(o, 'id', None) == getattr(r, 'id', None)]
            if not old:
                issues.append(f"New any-any rule: {getattr(r, 'name', 'unknown')}")
        
        # Проверяем wide port ranges
        for r in new_rules:
            service = str(getattr(r, 'service', 'any'))
            if service != 'any':
                try:
                    # Парсим диапазон
                    if '-' in service:
                        start, end = service.split('-')
                        if int(end) - int(start) > 1000:
                            issues.append(f"Wide port range: {getattr(r, 'name', 'unknown')}")
                except:
                    pass
        
        return issues
    
    def _find_resolved_issues(self, new_rules: List, old_rules: List) -> List[str]:
        """Находит исправленные проблемы."""
        resolved = []
        
        # Проверяем, были ли any-any правила удалены
        old_any_any = [o for o in old_rules 
                       if getattr(o, 'source', '') == 'any' 
                       and getattr(o, 'destination', '') == 'any'
                       and getattr(o, 'action', '') == 'permit']
        
        for old in old_any_any:
            new = [n for n in new_rules 
                   if getattr(n, 'id', None) == getattr(old, 'id', None)]
            if not new:
                resolved.append(f"Removed any-any rule: {getattr(old, 'name', 'unknown')}")
            elif getattr(new[0], 'action', '') == 'deny':
                resolved.append(f"Blocked any-any rule: {getattr(old, 'name', 'unknown')}")
        
        return resolved
    
    def _generate_recommendations(self, changes: List[RuleChange], 
                                  risk_delta: float) -> List[str]:
        """Генерирует рекомендации."""
        recs = []
        
        if risk_delta > 2.0:
            recs.append("High risk increase — review changes carefully")
        elif risk_delta < -2.0:
            recs.append("Risk decreased significantly — good changes")
        
        for change in changes:
            if change.change_type == ChangeType.ADD_RULE:
                recs.append(f"Verify new rule doesn't shadow existing rules")
            elif change.change_type == ChangeType.REMOVE_RULE:
                recs.append(f"Ensure no critical flows depend on removed rule")
            elif change.change_type == ChangeType.CHANGE_ACTION:
                if change.new_value == 'permit':
                    recs.append(f"Changed to permit — verify destination restrictions")
                elif change.new_value == 'deny':
                    recs.append(f"Changed to deny — check for false positives")
        
        return recs
    
    def _calculate_impact(self, changes: List[RuleChange], 
                          affected: List[Dict]) -> float:
        """Рассчитывает impact score."""
        base = len(changes) * 2.0
        flow_impact = len(affected) * 0.5
        return min(base + flow_impact, 10.0)


# Экспорт
__all__ = ['WhatIfAnalyzer', 'WhatIfResult', 'RuleChange', 'ChangeType']
