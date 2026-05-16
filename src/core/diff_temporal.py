"""
Diff Mode + Temporal View — Unified Module
Интеграция сравнения конфигураций (diff) и временной шкалы (temporal).

Возможности:
- Сравнение двух снимков графа (graph-level diff: nodes/edges added/removed/modified)
- Временная шкала снимков с возможностью выбора точек для diff
- Генерация единого HTML со side-by-side diff и timeline slider
- Построение trend-графиков изменений (rules count, risk score, changes)
- Экспорт unified JSON timeline с diff-информацией
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

from ..models.rule import FirewallRule
from ..models.endpoint import Endpoint
from ..models.service import Service


# ─────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────

class ChangeType(Enum):
    """Тип изменения между снимками."""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


@dataclass
class NodeChange:
    """Изменение узла графа."""
    node_id: str
    node_label: str
    change_type: ChangeType
    group: Optional[str] = None          # zone/vlan
    risk_old: Optional[float] = None
    risk_new: Optional[float] = None


@dataclass
class EdgeChange:
    """Изменение ребра графа."""
    source_id: str
    target_id: str
    source_label: str
    target_label: str
    change_type: ChangeType
    action_old: Optional[str] = None     # accept/deny
    action_new: Optional[str] = None
    risk_old: Optional[float] = None
    risk_new: Optional[float] = None
    services: List[str] = field(default_factory=list)


@dataclass
class GraphDiffResult:
    """Разница между двумя снимками графа."""
    snapshot_old: str   # timestamp
    snapshot_new: str
    nodes_added: List[NodeChange] = field(default_factory=list)
    nodes_removed: List[NodeChange] = field(default_factory=list)
    nodes_modified: List[NodeChange] = field(default_factory=list)
    edges_added: List[EdgeChange] = field(default_factory=list)
    edges_removed: List[EdgeChange] = field(default_factory=list)
    edges_modified: List[EdgeChange] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return (len(self.nodes_added) + len(self.nodes_removed) +
                len(self.nodes_modified) + len(self.edges_added) +
                len(self.edges_removed) + len(self.edges_modified))

    def summary(self) -> Dict:
        return {
            'nodes': {
                'added': len(self.nodes_added),
                'removed': len(self.nodes_removed),
                'modified': len(self.nodes_modified),
            },
            'edges': {
                'added': len(self.edges_added),
                'removed': len(self.edges_removed),
                'modified': len(self.edges_modified),
            },
            'total_changes': self.total_changes,
        }


@dataclass
class TimelineSnapshot:
    """Снимок графа в конкретный момент времени."""
    id: str                     # unique snapshot id (hash)
    timestamp: datetime
    label: str                  # human-readable label
    file_hash: str
    file_path: Optional[str] = None
    rules_count: int = 0
    nodes_count: int = 0
    edges_count: int = 0
    risk_score: float = 0.0
    risk_max: float = 0.0
    changes_from_previous: int = 0
    graph_data: Optional[Dict] = None   # Vis.js nodes/edges (cached)


@dataclass
class TimelineTrend:
    """Точка тренда."""
    date: str
    risk_avg: float
    risk_max: float
    rules_count: int
    nodes_count: int
    edges_count: int
    changes: int


# ─────────────────────────────────────────────────────────
# Core Engine
# ─────────────────────────────────────────────────────────

class DiffTemporalEngine:
    """
    Унифицированный движок Diff Mode + Temporal View.
    Объединяет логику сравнения конфигураций и временных снимков.
    """

    def __init__(self, storage_dir: str = ".temporal_storage"):
        self.storage = Path(storage_dir)
        self.storage.mkdir(exist_ok=True)
        self.snapshots: List[TimelineSnapshot] = []
        self._load_history()

    # ── Snapshot Management ──────────────────────────

    def add_snapshot(
        self,
        file_path: str,
        rules: List[FirewallRule],
        nodes_data: Optional[List[Dict]] = None,
        edges_data: Optional[List[Dict]] = None,
        label: Optional[str] = None,
    ) -> TimelineSnapshot:
        """Добавляет новый снимок графа."""
        file_hash = self._hash_file(file_path)

        # Вычисляем риски
        risks = []
        for r in rules:
            risk = getattr(r, 'risk_score', None)
            if risk is not None:
                risks.append(risk)
            else:
                # Вычисляем базовый риск из правила
                risk = self._compute_rule_risk(r)
                risks.append(risk)

        risk_avg = sum(risks) / len(risks) if risks else 0.0
        risk_max = max(risks) if risks else 0.0

        nodes_count = len(nodes_data) if nodes_data else 0
        edges_count = len(edges_data) if edges_data else 0

        # Сравниваем с предыдущим
        prev = self.snapshots[-1] if self.snapshots else None
        changes = 0
        if prev and nodes_data and prev.graph_data:
            prev_ids = {n['id'] for n in prev.graph_data.get('nodes', [])}
            curr_ids = {n['id'] for n in nodes_data}
            changes = len(curr_ids ^ prev_ids)  # symmetric difference

        snapshot_id = f"snap_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file_hash}"

        s = TimelineSnapshot(
            id=snapshot_id,
            timestamp=datetime.now(),
            label=label or Path(file_path).stem,
            file_hash=file_hash,
            file_path=file_path,
            rules_count=len(rules),
            nodes_count=nodes_count,
            edges_count=edges_count,
            risk_score=round(risk_avg, 2),
            risk_max=round(risk_max, 2),
            changes_from_previous=changes,
            graph_data={'nodes': nodes_data or [], 'edges': edges_data or []},
        )

        self.snapshots.append(s)
        self._save_history()
        return s

    def get_snapshot_by_id(self, snapshot_id: str) -> Optional[TimelineSnapshot]:
        """Возвращает снимок по ID."""
        for s in self.snapshots:
            if s.id == snapshot_id:
                return s
        return None

    def get_snapshots_range(self, days: int = 30) -> List[TimelineSnapshot]:
        """Возвращает снимки за последние N дней."""
        cutoff = datetime.now() - timedelta(days=days)
        return [s for s in self.snapshots if s.timestamp >= cutoff]

    # ── Graph-Level Diff ─────────────────────────────

    def diff_snapshots(
        self,
        old_id: str,
        new_id: str,
    ) -> Optional[GraphDiffResult]:
        """Сравнивает два снимка на уровне графа (nodes + edges)."""
        old = self.get_snapshot_by_id(old_id)
        new = self.get_snapshot_by_id(new_id)
        if not old or not new:
            return None

        result = GraphDiffResult(
            snapshot_old=old.timestamp.isoformat(),
            snapshot_new=new.timestamp.isoformat(),
        )

        if not old.graph_data or not new.graph_data:
            return result

        old_nodes = {n['id']: n for n in old.graph_data.get('nodes', [])}
        new_nodes = {n['id']: n for n in new.graph_data.get('nodes', [])}

        old_ids = set(old_nodes.keys())
        new_ids = set(new_nodes.keys())

        # Nodes: removed
        for nid in old_ids - new_ids:
            node = old_nodes[nid]
            result.nodes_removed.append(NodeChange(
                node_id=nid,
                node_label=node.get('label', nid),
                change_type=ChangeType.REMOVED,
                group=node.get('group'),
                risk_old=node.get('risk_score'),
            ))

        # Nodes: added
        for nid in new_ids - old_ids:
            node = new_nodes[nid]
            result.nodes_added.append(NodeChange(
                node_id=nid,
                node_label=node.get('label', nid),
                change_type=ChangeType.ADDED,
                group=node.get('group'),
                risk_new=node.get('risk_score'),
            ))

        # Nodes: modified
        for nid in old_ids & new_ids:
            on = old_nodes[nid]
            nn = new_nodes[nid]
            changed_fields = []
            for field in ('label', 'group', 'color', 'risk_score', 'size', 'level'):
                if on.get(field) != nn.get(field):
                    changed_fields.append(field)
            if changed_fields:
                result.nodes_modified.append(NodeChange(
                    node_id=nid,
                    node_label=nn.get('label', nid),
                    change_type=ChangeType.MODIFIED,
                    group=nn.get('group'),
                    risk_old=on.get('risk_score'),
                    risk_new=nn.get('risk_score'),
                ))

        # Edges: removed
        old_edges_keyed = self._key_edges(old.graph_data.get('edges', []))
        new_edges_keyed = self._key_edges(new.graph_data.get('edges', []))

        for ek in set(old_edges_keyed.keys()) - set(new_edges_keyed.keys()):
            e = old_edges_keyed[ek]
            result.edges_removed.append(EdgeChange(
                source_id=e.get('from', ''),
                target_id=e.get('to', ''),
                source_label=e.get('fromLabel', e.get('from', '')),
                target_label=e.get('toLabel', e.get('to', '')),
                change_type=ChangeType.REMOVED,
                action_old=e.get('action'),
                risk_old=e.get('risk_score'),
                services=e.get('services', []),
            ))

        # Edges: added
        for ek in set(new_edges_keyed.keys()) - set(old_edges_keyed.keys()):
            e = new_edges_keyed[ek]
            result.edges_added.append(EdgeChange(
                source_id=e.get('from', ''),
                target_id=e.get('to', ''),
                source_label=e.get('fromLabel', e.get('from', '')),
                target_label=e.get('toLabel', e.get('to', '')),
                change_type=ChangeType.ADDED,
                action_new=e.get('action'),
                risk_new=e.get('risk_score'),
                services=e.get('services', []),
            ))

        # Edges: modified
        for ek in set(old_edges_keyed.keys()) & set(new_edges_keyed.keys()):
            oe = old_edges_keyed[ek]
            ne = new_edges_keyed[ek]
            changed_fields = []
            for field in ('color', 'width', 'risk_score', 'action', 'label', 'services'):
                if oe.get(field) != ne.get(field):
                    changed_fields.append(field)
            if changed_fields:
                result.edges_modified.append(EdgeChange(
                    source_id=ne.get('from', ''),
                    target_id=ne.get('to', ''),
                    source_label=ne.get('fromLabel', ne.get('from', '')),
                    target_label=ne.get('toLabel', ne.get('to', '')),
                    change_type=ChangeType.MODIFIED,
                    action_old=oe.get('action'),
                    action_new=ne.get('action'),
                    risk_old=oe.get('risk_score'),
                    risk_new=ne.get('risk_score'),
                    services=ne.get('services', []),
                ))

        return result

    def diff_last_two(self) -> Optional[GraphDiffResult]:
        """Сравнивает два последних снимка."""
        if len(self.snapshots) < 2:
            return None
        return self.diff_snapshots(
            self.snapshots[-2].id,
            self.snapshots[-1].id,
        )

    # ── Trends ───────────────────────────────────────

    def get_trends(self, days: int = 30) -> List[TimelineTrend]:
        """Возвращает агрегированные тренды по дням."""
        cutoff = datetime.now() - timedelta(days=days)
        relevant = [s for s in self.snapshots if s.timestamp >= cutoff]

        daily: Dict[str, List[TimelineSnapshot]] = {}
        for s in relevant:
            date_str = s.timestamp.strftime('%Y-%m-%d')
            daily.setdefault(date_str, []).append(s)

        trends = []
        for date in sorted(daily):
            snaps = daily[date]
            last = snaps[-1]
            trends.append(TimelineTrend(
                date=date,
                risk_avg=round(sum(s.risk_score for s in snaps) / len(snaps), 2),
                risk_max=max(s.risk_max for s in snaps),
                rules_count=last.rules_count,
                nodes_count=last.nodes_count,
                edges_count=last.edges_count,
                changes=sum(s.changes_from_previous for s in snaps),
            ))
        return trends

    def get_change_summary(self, days: int = 7) -> Dict:
        """Сводка изменений за период."""
        cutoff = datetime.now() - timedelta(days=days)
        relevant = [s for s in self.snapshots if s.timestamp >= cutoff]

        if not relevant:
            return {'message': 'No data for this period', 'period_days': days}

        total_changes = sum(s.changes_from_previous for s in relevant)
        avg_risk = sum(s.risk_score for s in relevant) / len(relevant)
        first, last = relevant[0], relevant[-1]

        return {
            'period_days': days,
            'snapshots_count': len(relevant),
            'total_changes': total_changes,
            'avg_risk': round(avg_risk, 2),
            'current_risk': last.risk_score,
            'risk_trend': 'up' if last.risk_score > first.risk_score else 'down' if last.risk_score < first.risk_score else 'stable',
            'current_rules': last.rules_count,
            'current_nodes': last.nodes_count,
            'current_edges': last.edges_count,
            'first_snapshot': first.timestamp.strftime('%Y-%m-%d %H:%M'),
            'last_snapshot': last.timestamp.strftime('%Y-%m-%d %H:%M'),
        }

    # ── Anomaly Detection ────────────────────────────

    def detect_anomalies(self) -> List[Dict]:
        """Обнаруживает аномальные изменения."""
        if len(self.snapshots) < 3:
            return []

        anomalies = []
        for i in range(1, len(self.snapshots)):
            prev = self.snapshots[i - 1]
            curr = self.snapshots[i]

            # Резкий скачок риска (>50% от среднего)
            avg_risk = sum(s.risk_score for s in self.snapshots) / len(self.snapshots)
            risk_delta = abs(curr.risk_score - prev.risk_score)
            if risk_delta > avg_risk * 0.5:
                anomalies.append({
                    'type': 'risk_spike',
                    'timestamp': curr.timestamp.strftime('%Y-%m-%d %H:%M'),
                    'risk_old': prev.risk_score,
                    'risk_new': curr.risk_score,
                    'description': f'Risk spike: {prev.risk_score:.1f}→{curr.risk_score:.1f} (Δ={risk_delta:.1f})',
                    'severity': 'critical' if risk_delta > 5 else 'high' if risk_delta > 3 else 'medium',
                })

            # Массовое изменение (>15 узлов за раз)
            if curr.changes_from_previous > 15:
                anomalies.append({
                    'type': 'mass_change',
                    'timestamp': curr.timestamp.strftime('%Y-%m-%d %H:%M'),
                    'changes': curr.changes_from_previous,
                    'description': f'Mass change: {curr.changes_from_previous} elements',
                    'severity': 'high',
                })

            # Обнуление графа
            if curr.nodes_count == 0 and prev.nodes_count > 0:
                anomalies.append({
                    'type': 'graph_cleared',
                    'timestamp': curr.timestamp.strftime('%Y-%m-%d %H:%M'),
                    'description': 'Graph was cleared (0 nodes)',
                    'severity': 'critical',
                })

            # Удвоение размера графа
            if prev.nodes_count > 0 and curr.nodes_count > prev.nodes_count * 2:
                anomalies.append({
                    'type': 'graph_explosion',
                    'timestamp': curr.timestamp.strftime('%Y-%m-%d %H:%M'),
                    'nodes_old': prev.nodes_count,
                    'nodes_new': curr.nodes_count,
                    'description': f'Graph size doubled: {prev.nodes_count}→{curr.nodes_count} nodes',
                    'severity': 'high',
                })

        return anomalies

    # ── Rule-Level Diff (via config_diff) ────────────

    @staticmethod
    def diff_rules(
        old_rules: List[FirewallRule],
        new_rules: List[FirewallRule],
    ) -> Dict:
        """Сравнивает два набора правил (delegates to config_diff module)."""
        from .config_diff import ConfigComparator

        comparator = ConfigComparator(old_rules, new_rules)
        diff = comparator.compare()

        return {
            'summary': diff.summary,
            'changes': [
                {
                    'rule': d.rule_name,
                    'type': d.change_type.value,
                    'changes': d.changes,
                }
                for d in diff.rules_diff
                if d.change_type.value != 'unchanged'
            ],
        }

    # ── Helpers ──────────────────────────────────────

    def _hash_file(self, file_path: str) -> str:
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()[:16]
        except Exception:
            return 'unknown'

    def _compute_rule_risk(self, rule: FirewallRule) -> float:
        """Вычисляет базовый риск правила."""
        risk = 1.0  # base

        # Deny правила менее рискованны
        if getattr(rule, 'action', '').lower() == 'deny':
            risk -= 1.0

        # Any источники/назначения повышают риск
        for src in getattr(rule, 'sources', []):
            name = getattr(src, 'name', '')
            if name == 'any' or name == '0.0.0.0/0':
                risk += 2.0

        for dst in getattr(rule, 'destinations', []):
            name = getattr(dst, 'name', '')
            if name == 'any' or name == '0.0.0.0/0':
                risk += 1.5

        # Критичные порты
        critical_ports = {22, 23, 3389, 1433, 3306, 5432, 6379, 27017}
        for svc in getattr(rule, 'services', []):
            port = getattr(svc, 'port', None)
            if port in critical_ports:
                risk += 1.0

        return max(0, min(10, risk))

    @staticmethod
    def _key_edges(edges: List[Dict]) -> Dict[str, Dict]:
        """Ключует рёбра по from|to для diff."""
        result = {}
        for e in edges:
            key = f"{e.get('from', '')}|{e.get('to', '')}"
            result[key] = e
        return result

    # ── Persistence ──────────────────────────────────

    def _save_history(self):
        """Сохраняет все снимки в storage."""
        data = []
        for s in self.snapshots:
            data.append({
                'id': s.id,
                'timestamp': s.timestamp.isoformat(),
                'label': s.label,
                'file_hash': s.file_hash,
                'file_path': s.file_path,
                'rules_count': s.rules_count,
                'nodes_count': s.nodes_count,
                'edges_count': s.edges_count,
                'risk_score': s.risk_score,
                'risk_max': s.risk_max,
                'changes': s.changes_from_previous,
                'graph_data': s.graph_data,
            })

        history_file = self.storage / 'history.json'
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _load_history(self):
        """Загружает снимки из хранилища."""
        history_file = self.storage / 'history.json'
        if not history_file.exists():
            return

        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for item in data:
                self.snapshots.append(TimelineSnapshot(
                    id=item.get('id', f"snap_{item.get('timestamp', 'unknown')}"),
                    timestamp=datetime.fromisoformat(item['timestamp']),
                    label=item.get('label', 'Snapshot'),
                    file_hash=item.get('file_hash', ''),
                    file_path=item.get('file_path'),
                    rules_count=item.get('rules_count', 0),
                    nodes_count=item.get('nodes_count', 0),
                    edges_count=item.get('edges_count', 0),
                    risk_score=item.get('risk_score', 0.0),
                    risk_max=item.get('risk_max', 0.0),
                    changes_from_previous=item.get('changes', 0),
                    graph_data=item.get('graph_data'),
                ))
        except Exception as e:
            print(f"[WARN] Failed to load temporal history: {e}")


# ─────────────────────────────────────────────────────────
# HTML Generation
# ─────────────────────────────────────────────────────────

class DiffTimelineHTML:
    """Генерирует HTML со встроенной визуализацией diff + timeline."""

    @staticmethod
    def generate(
        engine: DiffTemporalEngine,
        output_path: str,
        diff_result: Optional[GraphDiffResult] = None,
        trends: Optional[List[TimelineTrend]] = None,
        anomalies: Optional[List[Dict]] = None,
        title: str = "Firewall Analyzer — Diff Mode + Temporal View",
    ) -> bool:
        """
        Генерирует единый HTML документ.
        Включает:
        - Timeline slider (выбор снимков)
        - Side-by-side diff view (до/после)
        - Trend charts (rules count, risk score, changes)
        - Anomaly panel
        - Change summary cards
        """
        try:
            html = DiffTimelineHTML._build_html(
                engine, diff_result, trends, anomalies, title
            )
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            return True
        except Exception as e:
            print(f"[ERROR] HTML generation: {e}")
            return False

    @staticmethod
    def _build_html(
        engine: DiffTemporalEngine,
        diff_result: Optional[GraphDiffResult],
        trends: Optional[List[TimelineTrend]],
        anomalies: Optional[List[Dict]],
        title: str,
    ) -> str:
        snapshots_json = json.dumps([
            {
                'id': s.id,
                'timestamp': s.timestamp.isoformat(),
                'label': s.label,
                'rules_count': s.rules_count,
                'nodes_count': s.nodes_count,
                'edges_count': s.edges_count,
                'risk_score': s.risk_score,
                'risk_max': s.risk_max,
                'changes': s.changes_from_previous,
            }
            for s in engine.snapshots
        ], ensure_ascii=False)

        diff_json = json.dumps(diff_result_to_dict(diff_result), ensure_ascii=False) if diff_result else 'null'

        trends_json = json.dumps([
            {
                'date': t.date,
                'risk_avg': t.risk_avg,
                'risk_max': t.risk_max,
                'rules_count': t.rules_count,
                'nodes_count': t.nodes_count,
                'edges_count': t.edges_count,
                'changes': t.changes,
            }
            for t in (trends or [])
        ], ensure_ascii=False)

        anomalies_json = json.dumps(anomalies or [], ensure_ascii=False)

        summary = engine.get_change_summary(days=30)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f1923;
            color: #e0e6ed;
            overflow-x: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1a2332, #2c3e50);
            padding: 20px 30px;
            border-bottom: 1px solid #34495e;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ font-size: 20px; color: #5dade2; }}
        .header .subtitle {{ font-size: 12px; color: #7f8c8d; margin-top: 4px; }}

        .container {{ padding: 20px; max-width: 1600px; margin: 0 auto; }}

        /* Summary Cards */
        .summary-row {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .card {{
            background: #1a2332;
            border: 1px solid #2c3e50;
            border-radius: 8px;
            padding: 18px;
        }}
        .card .value {{ font-size: 28px; font-weight: 700; margin: 6px 0; }}
        .card .label {{ font-size: 12px; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; }}
        .card.green .value {{ color: #27ae60; }}
        .card.red .value {{ color: #e74c3c; }}
        .card.orange .value {{ color: #f39c12; }}
        .card.blue .value {{ color: #3498db; }}
        .card .trend {{ font-size: 13px; margin-top: 4px; }}
        .card .trend.up {{ color: #e74c3c; }}
        .card .trend.down {{ color: #27ae60; }}
        .card .trend.stable {{ color: #7f8c8d; }}

        /* Timeline */
        .timeline-section {{
            background: #1a2332;
            border: 1px solid #2c3e50;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }}
        .timeline-controls {{
            display: flex;
            gap: 10px;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}
        .btn {{
            background: #2c3e50;
            border: 1px solid #34495e;
            color: #e0e6ed;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: background 0.2s;
        }}
        .btn:hover {{ background: #34495e; }}
        .btn.active {{ background: #3498db; border-color: #3498db; }}
        .btn.small {{ padding: 4px 10px; font-size: 11px; }}

        .timeline-slider {{
            width: 100%;
            height: 40px;
            position: relative;
            margin: 10px 0;
        }}
        .timeline-slider input[type=range] {{
            width: 100%;
            accent-color: #3498db;
            height: 6px;
        }}
        .snapshot-markers {{
            display: flex;
            justify-content: space-between;
            font-size: 10px;
            color: #7f8c8d;
            margin-top: 4px;
            padding: 0 2px;
        }}

        /* Diff Panel */
        .diff-section {{
            background: #1a2332;
            border: 1px solid #2c3e50;
            border-radius: 8px;
            margin-bottom: 25px;
        }}
        .diff-header {{
            padding: 15px 20px;
            border-bottom: 1px solid #2c3e50;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .diff-header h2 {{ font-size: 16px; }}
        .diff-side-by-side {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1px;
            background: #2c3e50;
        }}
        .diff-pane {{
            background: #1a2332;
            padding: 20px;
            max-height: 500px;
            overflow-y: auto;
        }}
        .diff-pane h3 {{ font-size: 14px; color: #5dade2; margin-bottom: 12px; }}
        .diff-pane.old h3 {{ color: #e74c3c; }}
        .diff-pane.new h3 {{ color: #27ae60; }}

        .diff-item {{
            display: flex;
            align-items: flex-start;
            gap: 8px;
            padding: 6px 0;
            border-bottom: 1px solid #1e2d3d;
            font-size: 13px;
        }}
        .diff-item .badge {{
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        .badge.added {{ background: rgba(39,174,96,0.2); color: #27ae60; }}
        .badge.removed {{ background: rgba(231,76,60,0.2); color: #e74c3c; }}
        .badge.modified {{ background: rgba(243,156,18,0.2); color: #f39c12; }}

        /* Changes Table */
        .changes-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        .changes-table th {{
            background: #2c3e50;
            padding: 10px 12px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #7f8c8d;
        }}
        .changes-table td {{
            padding: 8px 12px;
            border-bottom: 1px solid #1e2d3d;
            font-size: 13px;
        }}
        .changes-table tr:hover {{ background: rgba(52,152,219,0.05); }}

        /* Charts */
        .charts-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .chart-container {{
            background: #1a2332;
            border: 1px solid #2c3e50;
            border-radius: 8px;
            padding: 20px;
        }}
        .chart-container h3 {{
            font-size: 13px;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 15px;
        }}
        .chart {{
            height: 200px;
            display: flex;
            align-items: flex-end;
            gap: 4px;
            padding: 10px 0;
        }}
        .chart .bar {{
            flex: 1;
            background: #3498db;
            border-radius: 3px 3px 0 0;
            min-height: 2px;
            transition: background 0.3s;
            position: relative;
        }}
        .chart .bar:hover {{ background: #5dade2; }}
        .chart .bar .bar-tooltip {{
            display: none;
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: #000;
            color: #fff;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            white-space: nowrap;
            pointer-events: none;
        }}
        .chart .bar:hover .bar-tooltip {{ display: block; }}

        /* Anomaly Panel */
        .anomaly-section {{
            background: #1a2332;
            border: 1px solid #2c3e50;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }}
        .anomaly-section h2 {{ font-size: 16px; margin-bottom: 15px; }}
        .anomaly-item {{
            display: flex;
            gap: 10px;
            padding: 10px;
            margin-bottom: 8px;
            border-radius: 4px;
            font-size: 13px;
        }}
        .anomaly-item.critical {{ background: rgba(231,76,60,0.1); border-left: 3px solid #e74c3c; }}
        .anomaly-item.high {{ background: rgba(231,76,60,0.05); border-left: 3px solid #f39c12; }}
        .anomaly-item.medium {{ background: rgba(243,156,18,0.05); border-left: 3px solid #f1c40f; }}

        .severity-dot {{
            width: 10px; height: 10px;
            border-radius: 50%;
            margin-top: 3px;
            flex-shrink: 0;
        }}
        .severity-dot.critical {{ background: #e74c3c; }}
        .severity-dot.high {{ background: #f39c12; }}
        .severity-dot.medium {{ background: #f1c40f; }}

        /* Status bar */
        .status-bar {{
            display: flex;
            gap: 20px;
            padding: 10px 20px;
            background: #141e2b;
            border-top: 1px solid #2c3e50;
            font-size: 12px;
            color: #7f8c8d;
        }}
        .status-bar span {{ color: #5dade2; }}

        /* Responsive */
        @media (max-width: 768px) {{
            .diff-side-by-side {{ grid-template-columns: 1fr; }}
            .summary-row {{ grid-template-columns: 1fr 1fr; }}
            .charts-section {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔍 Diff Mode + Temporal View</h1>
            <div class="subtitle">Firewall Analyzer v3.0 — Unified Change Management</div>
        </div>
        <div style="font-size:12px;color:#7f8c8d;">
            {datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp; GMT+3
        </div>
    </div>

    <div class="container">

        <!-- Summary Cards -->
        <div class="summary-row" id="summaryCards">
            <div class="card blue">
                <div class="label">Snapshots</div>
                <div class="value">{summary['snapshots_count']}</div>
                <div class="trend stable">Total in history</div>
            </div>
            <div class="card orange">
                <div class="label">Total Changes</div>
                <div class="value">{summary['total_changes']}</div>
                <div class="trend stable">Last {summary['period_days']} days</div>
            </div>
            <div class="card" id="riskCard">
                <div class="label">Avg Risk Score</div>
                <div class="value" id="avgRiskValue">{summary['avg_risk']}</div>
                <div class="trend {summary['risk_trend']}" id="riskTrend">
                    {'▲ Increasing' if summary['risk_trend'] == 'up' else '▼ Decreasing' if summary['risk_trend'] == 'down' else '— Stable'}
                </div>
            </div>
            <div class="card green">
                <div class="label">Current Rules</div>
                <div class="value">{summary['current_rules']}</div>
                <div class="trend stable">{summary['current_nodes']} nodes, {summary['current_edges']} edges</div>
            </div>
        </div>

        <!-- Timeline Section -->
        <div class="timeline-section">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                <h2 style="font-size:16px;">📅 Timeline</h2>
                <div id="timelineCurrent" style="font-size:13px;color:#5dade2;">{engine.snapshots[-1].timestamp.strftime('%Y-%m-%d %H:%M') if engine.snapshots else 'No data'}</div>
            </div>
            <div class="timeline-controls">
                <button class="btn small" onclick="timelineStep(-1)">◀◀ Prev</button>
                <button class="btn small" id="playBtn" onclick="togglePlay()">▶ Play</button>
                <button class="btn small" onclick="timelineStep(1)">Next ▶▶</button>
                <span style="color:#7f8c8d;font-size:12px;">Speed:</span>
                <button class="btn small active" onclick="setSpeed(1)" id="speed1">1×</button>
                <button class="btn small" onclick="setSpeed(2)" id="speed2">2×</button>
                <button class="btn small" onclick="setSpeed(5)" id="speed5">5×</button>
                <span style="flex:1;"></span>
                <button class="btn small" onclick="diffSelected()">🔍 Diff Selected</button>
            </div>
            <div class="timeline-slider">
                <input type="range" id="timelineSlider" min="0" max="{max(0, len(engine.snapshots) - 1)}" value="{max(0, len(engine.snapshots) - 1)}" oninput="updateTimeline(this.value)">
                <div class="snapshot-markers" id="snapshotMarkers"></div>
            </div>
        </div>

        <!-- Diff Section -->
        <div class="diff-section" id="diffSection">
            <div class="diff-header">
                <h2>📊 Configuration Diff</h2>
                <span style="font-size:12px;color:#7f8c8d;" id="diffRange">Latest comparison</span>
            </div>
            <div class="diff-side-by-side" id="diffSideBySide">
                <div class="diff-pane old" id="paneOld">
                    <h3>⬅ Before</h3>
                    <div id="oldContent"><p style="color:#7f8c8d;">Select two snapshots to compare</p></div>
                </div>
                <div class="diff-pane new" id="paneNew">
                    <h3>➡ After</h3>
                    <div id="newContent"><p style="color:#7f8c8d;">Select two snapshots to compare</p></div>
                </div>
            </div>
        </div>

        <!-- Charts -->
        <div class="charts-section">
            <div class="chart-container" id="chartRules">
                <h3>📈 Rules Count Over Time</h3>
                <div class="chart" id="chartRulesBars"></div>
            </div>
            <div class="chart-container" id="chartRisk">
                <h3>⚠️ Risk Score Trend</h3>
                <div class="chart" id="chartRiskBars"></div>
            </div>
            <div class="chart-container" id="chartChanges">
                <h3>🔄 Changes Per Day</h3>
                <div class="chart" id="chartChangesBars"></div>
            </div>
        </div>

        <!-- Changes Table -->
        <div class="diff-section" id="changesDetail">
            <div class="diff-header">
                <h2>📋 Change Details</h2>
            </div>
            <div style="padding:20px;">
                <table class="changes-table" id="changesTable">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Element</th>
                            <th>Source</th>
                            <th>Target</th>
                            <th>Action</th>
                            <th>Risk Δ</th>
                        </tr>
                    </thead>
                    <tbody id="changesTbody">
                        <tr><td colspan="6" style="text-align:center;color:#7f8c8d;">No changes to display</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Anomalies -->
        <div class="anomaly-section" id="anomalyPanel">
            <h2>🚨 Anomalies</h2>
            <div id="anomalyContent"></div>
        </div>

    </div>

    <div class="status-bar">
        <div>Period: <span id="statusPeriod">{summary['first_snapshot']} → {summary['last_snapshot']}</span></div>
        <div>Snapshots: <span id="statusSnapshots">{summary['snapshots_count']}</span></div>
        <div>Anomalies: <span id="statusAnomalies">{len(anomalies or [])}</span></div>
    </div>

    <script>
        // Data
        const snapshots = {snapshots_json};
        const trends = {trends_json};
        const anomalies = {anomalies_json};
        const diffData = {diff_json};

        let currentIndex = snapshots.length - 1;
        let selectedOld = null;
        let selectedNew = null;
        let playInterval = null;
        let playSpeed = 1;

        // Init
        function init() {{
            renderTimelineMarkers();
            renderCharts();
            renderAnomalies();
            updateTimeline(currentIndex);
            if (snapshots.length >= 2) {{
                selectedOld = 0;
                selectedNew = snapshots.length - 1;
                renderDiff();
            }}
        }}

        // Timeline
        function updateTimeline(idx) {{
            idx = Math.max(0, Math.min(idx, snapshots.length - 1));
            currentIndex = idx;
            document.getElementById('timelineSlider').value = idx;
            const s = snapshots[idx];
            document.getElementById('timelineCurrent').textContent = s.label + ' · ' + s.timestamp;
        }}

        function timelineStep(dir) {{
            updateTimeline(currentIndex + dir);
        }}

        function togglePlay() {{
            if (playInterval) {{
                clearInterval(playInterval);
                playInterval = null;
                document.getElementById('playBtn').textContent = '▶ Play';
            }} else {{
                document.getElementById('playBtn').textContent = '⏸ Pause';
                playInterval = setInterval(() => {{
                    if (currentIndex < snapshots.length - 1) {{
                        updateTimeline(currentIndex + 1);
                    }} else {{
                        updateTimeline(0);
                    }}
                }}, 1000 / playSpeed);
            }}
        }}

        function setSpeed(s) {{
            playSpeed = s;
            document.querySelectorAll('[id^="speed"]').forEach(b => b.classList.remove('active'));
            document.getElementById('speed' + s).classList.add('active');
            if (playInterval) {{
                clearInterval(playInterval);
                playInterval = setInterval(() => {{
                    if (currentIndex < snapshots.length - 1) {{ updateTimeline(currentIndex + 1); }}
                    else {{ updateTimeline(0); }}
                }}, 1000 / playSpeed);
            }}
        }}

        function renderTimelineMarkers() {{
            const markers = document.getElementById('snapshotMarkers');
            if (snapshots.length <= 10) {{
                markers.innerHTML = snapshots.map(s => s.label).join(' · ');
            }} else {{
                const step = Math.floor(snapshots.length / 8);
                const labels = [];
                for (let i = 0; i < snapshots.length; i += step) {{
                    labels.push(snapshots[i].label);
                }}
                markers.innerHTML = labels.join(' · ');
            }}
        }}

        // Diff
        function diffSelected() {{
            if (selectedOld === null) selectedOld = currentIndex;
            else {{
                selectedNew = currentIndex;
                renderDiff();
                selectedOld = null;
                selectedNew = null;
            }}
            document.getElementById('timelineCurrent').textContent =
                selectedOld === null ? 'Select OLD snapshot' : 'Now select NEW snapshot';
        }}

        function renderDiff() {{
            const oldIdx = selectedOld ?? (snapshots.length - 2);
            const newIdx = selectedNew ?? (snapshots.length - 1);
            const oldSnap = snapshots[oldIdx];
            const newSnap = snapshots[newIdx];

            document.getElementById('diffRange').textContent =
                oldSnap.label + ' → ' + newSnap.label;

            // Old pane
            const paneOld = document.getElementById('oldContent');
            paneOld.innerHTML = `
                <p style="color:#e74c3c;font-weight:700;margin-bottom:10px;">${{oldSnap.label}} (${{oldSnap.timestamp}})</p>
                <div class="diff-item"><span style="color:#7f8c8d;">Rules:</span> ${{oldSnap.rules_count}}</div>
                <div class="diff-item"><span style="color:#7f8c8d;">Nodes:</span> ${{oldSnap.nodes_count}}</div>
                <div class="diff-item"><span style="color:#7f8c8d;">Edges:</span> ${{oldSnap.edges_count}}</div>
                <div class="diff-item"><span style="color:#7f8c8d;">Risk Avg:</span> ${{oldSnap.risk_score.toFixed(1)}}</div>
                <div class="diff-item"><span style="color:#7f8c8d;">Risk Max:</span> ${{oldSnap.risk_max.toFixed(1)}}</div>
            `;

            // New pane
            const paneNew = document.getElementById('newContent');
            paneNew.innerHTML = `
                <p style="color:#27ae60;font-weight:700;margin-bottom:10px;">${{newSnap.label}} (${{newSnap.timestamp}})</p>
                <div class="diff-item"><span style="color:#7f8c8d;">Rules:</span> ${{newSnap.rules_count}}</div>
                <div class="diff-item"><span style="color:#7f8c8d;">Nodes:</span> ${{newSnap.nodes_count}}</div>
                <div class="diff-item"><span style="color:#7f8c8d;">Edges:</span> ${{newSnap.edges_count}}</div>
                <div class="diff-item"><span style="color:#7f8c8d;">Risk Avg:</span> ${{newSnap.risk_score.toFixed(1)}}</div>
                <div class="diff-item"><span style="color:#7f8c8d;">Risk Max:</span> ${{newSnap.risk_max.toFixed(1)}}</div>
            `;

            // Changes table
            const tbody = document.getElementById('changesTbody');
            const rulesDelta = newSnap.rules_count - oldSnap.rules_count;
            const nodesDelta = newSnap.nodes_count - oldSnap.nodes_count;
            const edgesDelta = newSnap.edges_count - oldSnap.edges_count;
            const riskDelta = (newSnap.risk_score - oldSnap.risk_score).toFixed(1);

            const rows = [
                {{ type: 'Rules', element: 'Total rules', source: oldSnap.rules_count, target: newSnap.rules_count,
                   action: rulesDelta > 0 ? '+' + rulesDelta : rulesDelta, severity: rulesDelta > 0 ? 'added' : rulesDelta < 0 ? 'removed' : 'unchanged' }},
                {{ type: 'Nodes', element: 'Graph nodes', source: oldSnap.nodes_count, target: newSnap.nodes_count,
                   action: nodesDelta > 0 ? '+' + nodesDelta : nodesDelta, severity: nodesDelta > 0 ? 'added' : nodesDelta < 0 ? 'removed' : 'unchanged' }},
                {{ type: 'Edges', element: 'Graph edges', source: oldSnap.edges_count, target: newSnap.edges_count,
                   action: edgesDelta > 0 ? '+' + edgesDelta : edgesDelta, severity: edgesDelta > 0 ? 'added' : edgesDelta < 0 ? 'removed' : 'unchanged' }},
                {{ type: 'Risk', element: 'Avg risk score', source: oldSnap.risk_score.toFixed(1), target: newSnap.risk_score.toFixed(1),
                   action: (riskDelta > 0 ? '+' : '') + riskDelta, severity: riskDelta > 0 ? 'removed' : riskDelta < 0 ? 'added' : 'unchanged' }},
            ];

            tbody.innerHTML = rows.map(r => `
                <tr>
                    <td>${{r.type}}</td>
                    <td>${{r.element}}</td>
                    <td>${{r.source}}</td>
                    <td>${{r.target}}</td>
                    <td><span class="badge ${{r.severity}}">${{r.action}}</span></td>
                    <td style="color:${{r.severity === 'added' ? '#27ae60' : r.severity === 'removed' ? '#e74c3c' : '#7f8c8d'}}">—</td>
                </tr>
            `).join('');
        }}

        // Charts
        function renderCharts() {{
            if (!trends.length) return;

            const maxRules = Math.max(...trends.map(t => t.rules_count), 1);
            const maxRisk = Math.max(...trends.map(t => t.risk_avg), 0.1);
            const maxChanges = Math.max(...trends.map(t => t.changes), 1);

            document.getElementById('chartRulesBars').innerHTML = trends.map(t => {{
                const h = Math.max(2, (t.rules_count / maxRules) * 100);
                return `<div class="bar" style="height:${{h}}%;background:${{h > 70 ? '#27ae60' : '#3498db'}}">
                    <div class="bar-tooltip">${{t.date}}: ${{t.rules_count}}</div>
                </div>`;
            }}).join('');

            document.getElementById('chartRiskBars').innerHTML = trends.map(t => {{
                const h = Math.max(2, (t.risk_avg / maxRisk) * 100);
                const color = t.risk_avg > 7 ? '#e74c3c' : t.risk_avg > 4 ? '#f39c12' : '#27ae60';
                return `<div class="bar" style="height:${{h}}%;background:${{color}}">
                    <div class="bar-tooltip">${{t.date}}: ${{t.risk_avg.toFixed(1)}}</div>
                </div>`;
            }}).join('');

            document.getElementById('chartChangesBars').innerHTML = trends.map(t => {{
                const h = Math.max(2, (t.changes / maxChanges) * 100);
                const color = t.changes > 10 ? '#e74c3c' : t.changes > 3 ? '#f39c12' : '#3498db';
                return `<div class="bar" style="height:${{h}}%;background:${{color}}">
                    <div class="bar-tooltip">${{t.date}}: ${{t.changes}} changes</div>
                </div>`;
            }}).join('');
        }}

        // Anomalies
        function renderAnomalies() {{
            const container = document.getElementById('anomalyContent');
            if (!anomalies.length) {{
                container.innerHTML = '<p style="color:#7f8c8d;font-size:13px;">✅ No anomalies detected — all changes within normal range</p>';
                return;
            }}
            container.innerHTML = anomalies.map(a => `
                <div class="anomaly-item ${{a.severity}}">
                    <div class="severity-dot ${{a.severity}}"></div>
                    <div>
                        <strong>${{a.type.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase())}}</strong>
                        <span style="color:#7f8c8d;font-size:11px;margin-left:10px;">${{a.timestamp}}</span>
                        <p style="margin-top:4px;font-size:12px;">${{a.description}}</p>
                    </div>
                </div>
            `).join('');
        }}

        init();
    </script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def diff_result_to_dict(d: Optional[GraphDiffResult]) -> Optional[Dict]:
    if not d:
        return None
    return {
        'snapshot_old': d.snapshot_old,
        'snapshot_new': d.snapshot_new,
        'nodes': {
            'added': [{'id': n.node_id, 'label': n.node_label, 'group': n.group,
                       'risk_old': n.risk_old, 'risk_new': n.risk_new}
                      for n in d.nodes_added],
            'removed': [{'id': n.node_id, 'label': n.node_label, 'group': n.group,
                         'risk_old': n.risk_old, 'risk_new': n.risk_new}
                        for n in d.nodes_removed],
            'modified': [{'id': n.node_id, 'label': n.node_label, 'group': n.group,
                          'risk_old': n.risk_old, 'risk_new': n.risk_new}
                         for n in d.nodes_modified],
        },
        'edges': {
            'added': [{'source': e.source_id, 'target': e.target_id,
                       'source_label': e.source_label, 'target_label': e.target_label,
                       'action': e.action_new, 'risk': e.risk_new, 'services': e.services}
                      for e in d.edges_added],
            'removed': [{'source': e.source_id, 'target': e.target_id,
                         'source_label': e.source_label, 'target_label': e.target_label,
                         'action': e.action_old, 'risk': e.risk_old, 'services': e.services}
                        for e in d.edges_removed],
            'modified': [{'source': e.source_id, 'target': e.target_id,
                          'source_label': e.source_label, 'target_label': e.target_label,
                          'action_old': e.action_old, 'action_new': e.action_new,
                          'risk_old': e.risk_old, 'risk_new': e.risk_new, 'services': e.services}
                         for e in d.edges_modified],
        },
        'summary': d.summary(),
        'total_changes': d.total_changes,
    }


# ─────────────────────────────────────────────────────────
# Graph Data Extraction
# ─────────────────────────────────────────────────────────

def _build_access_graph_visjs(analyzer) -> Dict:
    """Извлекает Vis.js данные (nodes + edges) из графа доступа FirewallAnalyzer."""
    nodes = []
    edges = []

    if not hasattr(analyzer, 'graph') or analyzer.graph is None:
        return {'nodes': nodes, 'edges': edges}

    G = analyzer.graph

    for node_id in G.nodes():
        node_data = G.nodes[node_id]
        nodes.append({
            'id': str(node_id),
            'label': node_data.get('label', str(node_id)),
            'group': node_data.get('group', node_data.get('zone', 'default')),
            'type': node_data.get('type', 'host'),
            'risk_score': node_data.get('risk_score', 0),
            'color': node_data.get('color'),
            'size': node_data.get('size', 25),
            'level': node_data.get('level', 0),
        })

    for u, v, data in G.edges(data=True):
        edges.append({
            'from': str(u),
            'to': str(v),
            'fromLabel': G.nodes[u].get('label', str(u)),
            'toLabel': G.nodes[v].get('label', str(v)),
            'label': data.get('label', ''),
            'action': data.get('action', 'accept'),
            'color': data.get('color'),
            'width': data.get('width', 1),
            'risk_score': data.get('risk_score', 0),
            'services': data.get('services', []),
        })

    return {'nodes': nodes, 'edges': edges}


# ─────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────

def build_diff_temporal_html(
    config_dir: str,
    output_path: str,
    storage_dir: str = ".temporal_storage",
    days: int = 30,
) -> bool:
    """
    Быстрый запуск: парсит конфиги, собирает снимок, генерирует HTML.
    Используется из CLI/main как единая точка входа для Diff + Temporal.
    """
    import sys
    from pathlib import Path

    # Добавляем workspace в path если нужно
    workspace = Path(__file__).resolve().parents[3]  # firewall-analyzer/
    if str(workspace) not in sys.path:
        sys.path.insert(0, str(workspace))

    from src.parsers import get_parser_for_file
    from src.core import FirewallAnalyzer

    config_path = Path(config_dir)
    if not config_path.exists():
        print(f"[ERROR] Config directory not found: {config_path}")
        return False

    engine = DiffTemporalEngine(storage_dir=storage_dir)

    # Собираем все конфиги
    config_files = []
    if config_path.is_file():
        config_files = [config_path]
    else:
        for ext in ('.txt', '.conf', '.cfg', '.json', '.acl'):
            config_files.extend(config_path.rglob(f'*{ext}'))
        config_files = sorted(config_files)

    if not config_files:
        print("[ERROR] No configuration files found")
        return False

    print(f"Processing {len(config_files)} configuration files...")

    # Парсим конфиги
    analyzer = FirewallAnalyzer()
    all_rules = []
    for fp in config_files:
        try:
            parser = get_parser_for_file(fp)
            if parser is None:
                continue
            rules = parser.parse(fp)
            if rules:
                analyzer.add_rules(rules, str(fp))
                all_rules.extend(rules)
        except Exception as e:
            print(f"  [WARN] {fp.name}: {e}")

    if not all_rules:
        print("[ERROR] No rules parsed from configurations")
        return False

    # Строим граф
    analyzer.build_graph(aggregate_subnets=True, aggregate_threshold=24)

    # Экспортируем Vis.js данные (access graph из графа NetworkX)
    vis_data = _build_access_graph_visjs(analyzer)

    # Добавляем снимок
    label = config_path.stem if config_path.is_file() else config_path.name
    engine.add_snapshot(
        file_path=str(config_files[0]) if config_files else 'multi',
        rules=all_rules,
        nodes_data=vis_data.get('nodes', []),
        edges_data=vis_data.get('edges', []),
        label=label,
    )

    # Получаем последние два снимка для diff
    diff_result = engine.diff_last_two()
    trends = engine.get_trends(days=days)
    anomalies = engine.detect_anomalies()

    # Генерируем HTML
    ok = DiffTimelineHTML.generate(
        engine=engine,
        output_path=output_path,
        diff_result=diff_result,
        trends=trends,
        anomalies=anomalies,
        title=f"Firewall Analyzer — Diff Mode + Temporal View ({label})",
    )

    if ok:
        print(f"[OK] Diff + Temporal HTML: {output_path}")

    return ok


def export_unified_json(
    engine: DiffTemporalEngine,
    output_path: str,
) -> bool:
    """Экспортирует всю timeline в единый JSON."""
    data = {
        'generated': datetime.now().isoformat(),
        'total_snapshots': len(engine.snapshots),
        'snapshots': [
            {
                'id': s.id,
                'timestamp': s.timestamp.isoformat(),
                'label': s.label,
                'file_path': s.file_path,
                'file_hash': s.file_hash,
                'rules_count': s.rules_count,
                'nodes_count': s.nodes_count,
                'edges_count': s.edges_count,
                'risk_score': s.risk_score,
                'risk_max': s.risk_max,
                'changes': s.changes_from_previous,
            }
            for s in engine.snapshots
        ],
        'trends': [
            {
                'date': t.date,
                'risk_avg': t.risk_avg,
                'risk_max': t.risk_max,
                'rules_count': t.rules_count,
                'nodes_count': t.nodes_count,
                'edges_count': t.edges_count,
                'changes': t.changes,
            }
            for t in engine.get_trends(days=365)
        ],
        'anomalies': engine.detect_anomalies(),
        'change_summary': engine.get_change_summary(days=30),
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return True


# Экспорт
__all__ = [
    'DiffTemporalEngine',
    'DiffTimelineHTML',
    'GraphDiffResult',
    'NodeChange',
    'EdgeChange',
    'TimelineSnapshot',
    'TimelineTrend',
    'ChangeType',
    'build_diff_temporal_html',
    'export_unified_json',
    'diff_result_to_dict',
]
