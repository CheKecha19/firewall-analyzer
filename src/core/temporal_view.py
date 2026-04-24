"""
Temporal View - Timeline Analysis
Отслеживает изменения конфигурации во времени.
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ConfigSnapshot:
    """Снимок конфигурации."""
    timestamp: datetime
    file_hash: str
    rules_count: int
    risk_score: float
    changes_from_previous: int
    added_rules: List[str] = field(default_factory=list)
    removed_rules: List[str] = field(default_factory=list)
    modified_rules: List[str] = field(default_factory=list)
    file_path: Optional[str] = None


@dataclass
class TrendPoint:
    """Точка тренда."""
    date: str
    risk_score: float
    rules_count: int
    changes: int


class TemporalAnalyzer:
    """Анализатор временных изменений."""
    
    def __init__(self, storage_path: str = ".temporal_storage"):
        self.storage = Path(storage_path)
        self.storage.mkdir(exist_ok=True)
        self.snapshots: List[ConfigSnapshot] = []
        self.load_history()
    
    def add_snapshot(self, file_path: str, rules: List, 
                     risk_score: float) -> ConfigSnapshot:
        """Добавляет новый снимок конфигурации."""
        
        # Вычисляем hash файла
        file_hash = self._hash_file(file_path)
        
        # Сравниваем с предыдущим
        previous = self.snapshots[-1] if self.snapshots else None
        
        added = []
        removed = []
        modified = []
        changes = 0
        
        if previous:
            current_rule_ids = {self._rule_id(r) for r in rules}
            prev_rule_ids = set(previous.added_rules + previous.modified_rules)
            
            added = list(current_rule_ids - prev_rule_ids)
            removed = list(prev_rule_ids - current_rule_ids)
            changes = len(added) + len(removed)
        
        snapshot = ConfigSnapshot(
            timestamp=datetime.now(),
            file_hash=file_hash,
            rules_count=len(rules),
            risk_score=risk_score,
            changes_from_previous=changes,
            added_rules=added,
            removed_rules=removed,
            modified_rules=modified,
            file_path=file_path
        )
        
        self.snapshots.append(snapshot)
        self.save_history()
        
        return snapshot
    
    def get_trends(self, days: int = 30) -> List[TrendPoint]:
        """Возвращает тренды за последние N дней."""
        
        cutoff = datetime.now() - timedelta(days=days)
        relevant = [s for s in self.snapshots if s.timestamp >= cutoff]
        
        # Группируем по дням
        daily = {}
        for s in relevant:
            date_str = s.timestamp.strftime('%Y-%m-%d')
            if date_str not in daily:
                daily[date_str] = []
            daily[date_str].append(s)
        
        # Берём последний снимок за день
        trends = []
        for date in sorted(daily.keys()):
            last = daily[date][-1]
            trends.append(TrendPoint(
                date=date,
                risk_score=last.risk_score,
                rules_count=last.rules_count,
                changes=sum(s.changes_from_previous for s in daily[date])
            ))
        
        return trends
    
    def detect_anomalies(self) -> List[Dict]:
        """Обнаруживает аномалии в изменениях."""
        
        if len(self.snapshots) < 3:
            return []
        
        anomalies = []
        
        # Считаем среднее и стандартное отклонение
        risks = [s.risk_score for s in self.snapshots]
        avg_risk = sum(risks) / len(risks)
        
        for i, snapshot in enumerate(self.snapshots[1:], 1):
            # Резкое изменение риска
            risk_change = abs(snapshot.risk_score - self.snapshots[i-1].risk_score)
            if risk_change > avg_risk * 0.5:  # >50% от среднего
                anomalies.append({
                    'type': 'risk_spike',
                    'date': snapshot.timestamp.strftime('%Y-%m-%d %H:%M'),
                    'description': f"Risk changed by {risk_change:.1f} "
                                 f"({self.snapshots[i-1].risk_score:.1f} → {snapshot.risk_score:.1f})",
                    'severity': 'high' if risk_change > 3 else 'medium'
                })
            
            # Много изменений за раз
            if snapshot.changes_from_previous > 10:
                anomalies.append({
                    'type': 'mass_change',
                    'date': snapshot.timestamp.strftime('%Y-%m-%d %H:%M'),
                    'description': f"{snapshot.changes_from_previous} rules changed at once",
                    'severity': 'high'
                })
            
            # Удаление всех правил
            if snapshot.rules_count == 0 and self.snapshots[i-1].rules_count > 0:
                anomalies.append({
                    'type': 'config_cleared',
                    'date': snapshot.timestamp.strftime('%Y-%m-%d %H:%M'),
                    'description': "All rules were removed",
                    'severity': 'critical'
                })
        
        return anomalies
    
    def get_change_summary(self, days: int = 7) -> Dict:
        """Возвращает сводку изменений."""
        
        cutoff = datetime.now() - timedelta(days=days)
        relevant = [s for s in self.snapshots if s.timestamp >= cutoff]
        
        if not relevant:
            return {'message': 'No data for the period'}
        
        total_changes = sum(s.changes_from_previous for s in relevant)
        avg_risk = sum(s.risk_score for s in relevant) / len(relevant)
        
        # Находим наиболее изменяемые правила
        all_modified = []
        for s in relevant:
            all_modified.extend(s.modified_rules)
        
        frequent_changes = {}
        for rule_id in all_modified:
            frequent_changes[rule_id] = frequent_changes.get(rule_id, 0) + 1
        
        return {
            'period_days': days,
            'snapshots_count': len(relevant),
            'total_changes': total_changes,
            'average_risk': round(avg_risk, 2),
            'current_risk': relevant[-1].risk_score,
            'risk_trend': 'up' if relevant[-1].risk_score > relevant[0].risk_score else 'down',
            'most_changed_rules': sorted(frequent_changes.items(), 
                                         key=lambda x: x[1], reverse=True)[:5],
            'last_change': relevant[-1].timestamp.strftime('%Y-%m-%d %H:%M')
        }
    
    def export_timeline(self, output_path: str):
        """Экспортирует timeline в JSON."""
        
        data = {
            'snapshots': [
                {
                    'timestamp': s.timestamp.isoformat(),
                    'file_hash': s.file_hash,
                    'rules_count': s.rules_count,
                    'risk_score': s.risk_score,
                    'changes': s.changes_from_previous,
                    'added': s.added_rules,
                    'removed': s.removed_rules,
                    'modified': s.modified_rules
                }
                for s in self.snapshots
            ],
            'trends': [
                {
                    'date': t.date,
                    'risk': t.risk_score,
                    'rules': t.rules_count,
                    'changes': t.changes
                }
                for t in self.get_trends(days=365)
            ],
            'anomalies': self.detect_anomalies()
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def _hash_file(self, file_path: str) -> str:
        """Вычисляет hash файла."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()[:16]
        except:
            return "unknown"
    
    def _rule_id(self, rule) -> str:
        """Генерирует ID правила."""
        return getattr(rule, 'id', None) or getattr(rule, 'name', 'unknown')
    
    def save_history(self):
        """Сохраняет историю в файл."""
        data = [
            {
                'timestamp': s.timestamp.isoformat(),
                'file_hash': s.file_hash,
                'rules_count': s.rules_count,
                'risk_score': s.risk_score,
                'changes': s.changes_from_previous,
                'added': s.added_rules,
                'removed': s.removed_rules,
                'modified': s.modified_rules,
                'file_path': s.file_path
            }
            for s in self.snapshots
        ]
        
        history_file = self.storage / 'history.json'
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def load_history(self):
        """Загружает историю из файла."""
        history_file = self.storage / 'history.json'
        
        if not history_file.exists():
            return
        
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for item in data:
                self.snapshots.append(ConfigSnapshot(
                    timestamp=datetime.fromisoformat(item['timestamp']),
                    file_hash=item['file_hash'],
                    rules_count=item['rules_count'],
                    risk_score=item['risk_score'],
                    changes_from_previous=item.get('changes', 0),
                    added_rules=item.get('added', []),
                    removed_rules=item.get('removed', []),
                    modified_rules=item.get('modified', []),
                    file_path=item.get('file_path')
                ))
        except Exception as e:
            print(f"[WARN] Failed to load temporal history: {e}")


# Экспорт
__all__ = ['TemporalAnalyzer', 'ConfigSnapshot', 'TrendPoint']
