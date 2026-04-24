"""
Модуль сравнения (diff) конфигураций межсетевых экранов.
"""
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import hashlib

from ..models.rule import FirewallRule
from ..models.endpoint import Endpoint
from ..models.service import Service


class ChangeType(Enum):
    """Тип изменения в конфигурации."""
    ADDED = "added"       # Правило добавлено
    REMOVED = "removed"   # Правило удалено
    MODIFIED = "modified" # Правило изменено
    UNCHANGED = "unchanged" # Без изменений


@dataclass
class RuleDiff:
    """Разница для одного правила."""
    rule_name: str
    change_type: ChangeType
    old_rule: Optional[FirewallRule] = None
    new_rule: Optional[FirewallRule] = None
    changes: List[str] = field(default_factory=list)  # Список изменённых полей


@dataclass
class ConfigDiff:
    """Результат сравнения двух конфигураций."""
    old_config_path: str
    new_config_path: str
    rules_diff: List[RuleDiff] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    
    @property
    def added_count(self) -> int:
        return sum(1 for d in self.rules_diff if d.change_type == ChangeType.ADDED)
    
    @property
    def removed_count(self) -> int:
        return sum(1 for d in self.rules_diff if d.change_type == ChangeType.REMOVED)
    
    @property
    def modified_count(self) -> int:
        return sum(1 for d in self.rules_diff if d.change_type == ChangeType.MODIFIED)
    
    @property
    def total_changes(self) -> int:
        return len([d for d in self.rules_diff if d.change_type != ChangeType.UNCHANGED])


class ConfigComparator:
    """Сравнивает две конфигурации и находит различия."""
    
    def __init__(self, old_rules: List[FirewallRule], new_rules: List[FirewallRule]):
        """
        Args:
            old_rules: Список правил из старой конфигурации
            new_rules: Список правил из новой конфигурации
        """
        self.old_rules = old_rules
        self.new_rules = new_rules
        
        # Индексы для быстрого поиска
        self._old_by_name: Dict[str, FirewallRule] = {}
        self._new_by_name: Dict[str, FirewallRule] = {}
        self._build_indices()
    
    def _build_indices(self):
        """Строит индексы правил по имени."""
        for rule in self.old_rules:
            self._old_by_name[rule.name] = rule
        
        for rule in self.new_rules:
            self._new_by_name[rule.name] = rule
    
    def compare(self) -> ConfigDiff:
        """Выполняет сравнение и возвращает результат."""
        diff = ConfigDiff(
            old_config_path="",
            new_config_path="",
            rules_diff=[]
        )
        
        old_names = set(self._old_by_name.keys())
        new_names = set(self._new_by_name.keys())
        
        # Найдены в обоих - проверяем изменения
        common_names = old_names & new_names
        for name in common_names:
            old_rule = self._old_by_name[name]
            new_rule = self._new_by_name[name]
            rule_diff = self._compare_rules(old_rule, new_rule)
            diff.rules_diff.append(rule_diff)
        
        # Добавлены в новой конфигурации
        added_names = new_names - old_names
        for name in added_names:
            diff.rules_diff.append(RuleDiff(
                rule_name=name,
                change_type=ChangeType.ADDED,
                new_rule=self._new_by_name[name],
                changes=["rule_added"]
            ))
        
        # Удалены из старой конфигурации
        removed_names = old_names - new_names
        for name in removed_names:
            diff.rules_diff.append(RuleDiff(
                rule_name=name,
                change_type=ChangeType.REMOVED,
                old_rule=self._old_by_name[name],
                changes=["rule_removed"]
            ))
        
        # Сортируем по типу изменения
        diff.rules_diff.sort(key=lambda x: (
            0 if x.change_type == ChangeType.REMOVED else
            1 if x.change_type == ChangeType.MODIFIED else
            2 if x.change_type == ChangeType.ADDED else 3
        ))
        
        # Формируем summary
        diff.summary = {
            'total_old': len(self.old_rules),
            'total_new': len(self.new_rules),
            'added': diff.added_count,
            'removed': diff.removed_count,
            'modified': diff.modified_count,
            'unchanged': len(common_names) - diff.modified_count
        }
        
        return diff
    
    def _compare_rules(self, old: FirewallRule, new: FirewallRule) -> RuleDiff:
        """Сравнивает два правила и находит различия."""
        changes = []
        
        # Сравниваем sources
        old_src = {e.name for e in old.sources}
        new_src = {e.name for e in new.sources}
        if old_src != new_src:
            changes.append("sources")
        
        # Сравниваем destinations
        old_dst = {e.name for e in old.destinations}
        new_dst = {e.name for e in new.destinations}
        if old_dst != new_dst:
            changes.append("destinations")
        
        # Сравниваем services
        old_svc = {s.name for s in old.services}
        new_svc = {s.name for s in new.services}
        if old_svc != new_svc:
            changes.append("services")
        
        # Сравниваем action
        if old.action != new.action:
            changes.append("action")
        
        # Сравниваем enabled
        if old.enabled != new.enabled:
            changes.append("enabled")
        
        # Определяем тип изменения
        if changes:
            change_type = ChangeType.MODIFIED
        else:
            change_type = ChangeType.UNCHANGED
        
        return RuleDiff(
            rule_name=old.name,
            change_type=change_type,
            old_rule=old,
            new_rule=new,
            changes=changes
        )
    
    def generate_report(self, diff: ConfigDiff, format: str = "text") -> str:
        """Генерирует отчёт о различиях."""
        if format == "json":
            return self._generate_json_report(diff)
        elif format == "html":
            return self._generate_html_report(diff)
        else:
            return self._generate_text_report(diff)
    
    def _generate_text_report(self, diff: ConfigDiff) -> str:
        """Генерирует текстовый отчёт."""
        lines = [
            "=" * 60,
            "CONFIGURATION DIFF REPORT",
            "=" * 60,
            "",
            f"Old rules: {diff.summary['total_old']}",
            f"New rules: {diff.summary['total_new']}",
            "",
            "SUMMARY:",
            f"  Added:   {diff.added_count}",
            f"  Removed: {diff.removed_count}",
            f"  Modified: {diff.modified_count}",
            f"  Unchanged: {diff.summary['unchanged']}",
            "",
            "-" * 60,
            "DETAILED CHANGES:",
            "-" * 60,
            ""
        ]
        
        # Removed
        if diff.removed_count > 0:
            lines.append("REMOVED RULES:")
            for rule_diff in diff.rules_diff:
                if rule_diff.change_type == ChangeType.REMOVED:
                    lines.append(f"  [-] {rule_diff.rule_name}")
            lines.append("")
        
        # Added
        if diff.added_count > 0:
            lines.append("ADDED RULES:")
            for rule_diff in diff.rules_diff:
                if rule_diff.change_type == ChangeType.ADDED:
                    lines.append(f"  [+] {rule_diff.rule_name}")
                    if rule_diff.new_rule:
                        lines.append(f"      Src: {', '.join(e.name for e in rule_diff.new_rule.sources)}")
                        lines.append(f"      Dst: {', '.join(e.name for e in rule_diff.new_rule.destinations)}")
            lines.append("")
        
        # Modified
        if diff.modified_count > 0:
            lines.append("MODIFIED RULES:")
            for rule_diff in diff.rules_diff:
                if rule_diff.change_type == ChangeType.MODIFIED:
                    lines.append(f"  [*] {rule_diff.rule_name}")
                    lines.append(f"      Changes: {', '.join(rule_diff.changes)}")
            lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def _generate_json_report(self, diff: ConfigDiff) -> str:
        """Генерирует JSON отчёт."""
        import json
        
        data = {
            'summary': diff.summary,
            'changes': [
                {
                    'rule': d.rule_name,
                    'type': d.change_type.value,
                    'changes': d.changes,
                    'old': self._rule_to_dict(d.old_rule) if d.old_rule else None,
                    'new': self._rule_to_dict(d.new_rule) if d.new_rule else None
                }
                for d in diff.rules_diff
                if d.change_type != ChangeType.UNCHANGED
            ]
        }
        
        return json.dumps(data, indent=2)
    
    def _generate_html_report(self, diff: ConfigDiff) -> str:
        """Генерирует HTML отчёт."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Configuration Diff Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 1px solid #ccc; padding-bottom: 5px; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .added {{ color: green; }}
        .removed {{ color: red; }}
        .modified {{ color: orange; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #667eea; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>Configuration Diff Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Old rules: {diff.summary['total_old']} | New rules: {diff.summary['total_new']}</p>
        <p>
            <span class="added">Added: {diff.added_count}</span> | 
            <span class="removed">Removed: {diff.removed_count}</span> | 
            <span class="modified">Modified: {diff.modified_count}</span> | 
            Unchanged: {diff.summary['unchanged']}
        </p>
    </div>
"""
        
        # Added rules
        if diff.added_count > 0:
            html += "    <h2 class='added'>Added Rules</h2>\n    <table>\n"
            html += "        <tr><th>Rule Name</th><th>Sources</th><th>Destinations</th><th>Action</th></tr>\n"
            for rule_diff in diff.rules_diff:
                if rule_diff.change_type == ChangeType.ADDED and rule_diff.new_rule:
                    r = rule_diff.new_rule
                    html += f"        <tr><td>{r.name}</td><td>{', '.join(e.name for e in r.sources)}</td><td>{', '.join(e.name for e in r.destinations)}</td><td>{r.action}</td></tr>\n"
            html += "    </table>\n"
        
        # Removed rules
        if diff.removed_count > 0:
            html += "    <h2 class='removed'>Removed Rules</h2>\n    <table>\n"
            html += "        <tr><th>Rule Name</th><th>Sources</th><th>Destinations</th><th>Action</th></tr>\n"
            for rule_diff in diff.rules_diff:
                if rule_diff.change_type == ChangeType.REMOVED and rule_diff.old_rule:
                    r = rule_diff.old_rule
                    html += f"        <tr><td>{r.name}</td><td>{', '.join(e.name for e in r.sources)}</td><td>{', '.join(e.name for e in r.destinations)}</td><td>{r.action}</td></tr>\n"
            html += "    </table>\n"
        
        # Modified rules
        if diff.modified_count > 0:
            html += "    <h2 class='modified'>Modified Rules</h2>\n    <table>\n"
            html += "        <tr><th>Rule Name</th><th>Changes</th></tr>\n"
            for rule_diff in diff.rules_diff:
                if rule_diff.change_type == ChangeType.MODIFIED:
                    html += f"        <tr><td>{rule_diff.rule_name}</td><td>{', '.join(rule_diff.changes)}</td></tr>\n"
            html += "    </table>\n"
        
        html += """</body>
</html>"""
        
        return html
    
    def _rule_to_dict(self, rule: FirewallRule) -> Dict:
        """Конвертирует правило в словарь."""
        return {
            'name': rule.name,
            'sources': [e.name for e in rule.sources],
            'destinations': [e.name for e in rule.destinations],
            'services': [s.name for s in rule.services],
            'action': rule.action,
            'enabled': rule.enabled
        }


def compare_configs(
    old_path: Path,
    new_path: Path,
    old_rules: List[FirewallRule],
    new_rules: List[FirewallRule],
    output_format: str = "text"
) -> Tuple[ConfigDiff, str]:
    """
    Сравнивает две конфигурации и возвращает результат.
    
    Args:
        old_path: Путь к старой конфигурации
        new_path: Путь к новой конфигурации
        old_rules: Список правил старой конфигурации
        new_rules: Список правил новой конфигурации
        output_format: Формат отчёта (text, json, html)
        
    Returns:
        Tuple (ConfigDiff, report_string)
    """
    comparator = ConfigComparator(old_rules, new_rules)
    diff = comparator.compare()
    diff.old_config_path = str(old_path)
    diff.new_config_path = str(new_path)
    
    report = comparator.generate_report(diff, output_format)
    return diff, report
