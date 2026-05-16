"""
Модуль анализа качества правил межсетевого экрана.

Обнаруживает:
- Shadowing (правило A полностью перекрывает правило B)
- Conflicts (одинаковый scope, разный action)
- Redundancy (идентичные правила на разных устройствах)
- Unused (правила без hit-count)
- Вычисляет quality_score (0-100)
"""

from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict

from ..models.rule import FirewallRule
from ..models.endpoint import Endpoint
from ..models.service import Service


# ─── Data-классы ─────────────────────────────────────────────────

@dataclass
class ShadowedRule:
    """Правило, перекрытое более общим правилом выше."""
    shadowed_name: str
    shadowed_id: Optional[str]
    shadower_name: str
    shadower_id: Optional[str]
    reason: str


@dataclass
class RuleConflict:
    """Конфликт между правилами: одинаковый scope, разный action."""
    rule_a: str
    rule_a_id: Optional[str]
    rule_a_action: str
    rule_b: str
    rule_b_id: Optional[str]
    rule_b_action: str
    scope_description: str


@dataclass
class RedundantRule:
    """Идентичные правила на разных устройствах."""
    rules: List[str]
    rule_ids: List[Optional[str]]
    signature: str  # хеш-строка scope+action


@dataclass
class UnusedRule:
    """Правило без hit-count (или помечено 'unknown')."""
    rule_name: str
    rule_id: Optional[str]
    status: str  # 'unused', 'unknown', 'low_hits'


@dataclass
class QualityReport:
    """Полный отчёт о качестве правил."""
    shadowed: List[Dict]
    conflicts: List[Dict]
    redundant: List[Dict]
    unused: List[Dict]
    total_rules: int
    quality_score: int  # 0-100
    summary: Dict[str, int] = field(default_factory=dict)


# ─── Вспомогательные функции ────────────────────────────────────

def _endpoint_signature(endpoints: List[Endpoint]) -> str:
    """Создаёт стабильную строку-сигнатуру для списка endpoint'ов."""
    names = sorted(ep.name for ep in endpoints)
    return '|'.join(names) if names else 'any'


def _service_signature(services: List[Service]) -> str:
    """Создаёт стабильную строку-сигнатуру для списка сервисов."""
    parts = []
    for svc in sorted(services, key=lambda s: s.name):
        ports = sorted(svc.ports) if svc.ports else []
        ports_str = ','.join(str(p) for p in ports[:20])  # limit
        parts.append(f"{svc.name}:{svc.protocol}:{ports_str}")
    return ';'.join(parts) if parts else 'any'


def _rule_scope_signature(rule: FirewallRule) -> str:
    """Создаёт сигнатуру scope правила (src + dst + svc, без action)."""
    src = _endpoint_signature(rule.sources)
    dst = _endpoint_signature(rule.destinations)
    svc = _service_signature(rule.services)
    return f"SRC:{src}|DST:{dst}|SVC:{svc}"


def _rule_full_signature(rule: FirewallRule) -> str:
    """Создаёт полную сигнатуру правила (scope + action)."""
    scope = _rule_scope_signature(rule)
    return f"{scope}|ACT:{rule.action}"


def _endpoints_overlap(a: List[Endpoint], b: List[Endpoint]) -> Tuple[bool, str]:
    """
    Проверяет, покрывает ли набор a набор b (a перекрывает b).
    Возвращает (covered, reason).
    """
    a_any = any(ep.name == 'any' or '0.0.0.0/0' in ep.cidrs for ep in a)
    b_any = any(ep.name == 'any' or '0.0.0.0/0' in ep.cidrs for ep in b)

    # any перекрывает всё
    if a_any:
        return True, "any source/destination"
    if b_any and not a_any:
        return False, "b has any but a doesn't"

    # Получаем все CIDR
    a_cidrs = {c for ep in a for c in ep.cidrs}
    b_cidrs = {c for ep in b for c in ep.cidrs}

    if not a_cidrs or not b_cidrs:
        return a_cidrs == b_cidrs, "no cidr overlap check"

    try:
        import ipaddress
        a_nets = [ipaddress.ip_network(c, strict=False) for c in a_cidrs if c]
        b_nets = [ipaddress.ip_network(c, strict=False) for c in b_cidrs if c]
        # Проверяем: каждый b_net должен перекрываться хотя бы одним a_net
        for b_net in b_nets:
            covered = False
            for a_net in a_nets:
                try:
                    if b_net.subnet_of(a_net) or a_net.supernet_of(b_net) or a_net.overlaps(b_net):
                        covered = True
                        break
                except (ValueError, TypeError):
                    continue
            if not covered:
                return False, f"{b_net} not covered"
        return True, f"all {len(b_nets)} subnets covered by {len(a_nets)}"
    except (ValueError, TypeError):
        pass

    return a_cidrs == b_cidrs, "exact match only"


def _services_overlap(a: List[Service], b: List[Service]) -> Tuple[bool, str]:
    """
    Проверяет, покрывают ли сервисы a сервисы b.
    """
    a_any = any(s.name == 'any' or s.protocol == 'ip' for s in a)
    b_any = any(s.name == 'any' or s.protocol == 'ip' for s in b)

    if a_any:
        return True, "any service"
    if b_any and not a_any:
        return False, "b has any but a doesn't"

    a_ports: Set[int] = set()
    b_ports: Set[int] = set()
    for s in a:
        a_ports.update(s.ports if s.ports else set())
    for s in b:
        b_ports.update(s.ports if s.ports else set())

    if not a_ports or not b_ports:
        return a_ports == b_ports, "no port overlap check"

    return b_ports.issubset(a_ports), f"b_ports subset of a_ports: {b_ports.issubset(a_ports)}"


# ─── Основной анализатор ────────────────────────────────────────

class RuleQualityAnalyzer:
    """
    Анализатор качества правил.
    Выполняет все проверки и вычисляет quality_score.
    """

    # Штрафы за проблемы (в баллах из 100)
    PENALTY_SHADOWED = 10    # за каждое перекрытое правило
    PENALTY_CONFLICT = 15    # за каждый конфликт
    PENALTY_REDUNDANT = 5    # за каждое избыточное правило (на одно устройство)
    PENALTY_UNUSED = 8       # за каждое неиспользуемое правило

    def __init__(self, rules: List[FirewallRule]):
        self.rules = [r for r in rules if r.enabled]
        self.total = len(self.rules)

    # ─── Shadowing Detection ─────────────────────────────────────

    def detect_shadowing(self) -> List[ShadowedRule]:
        """
        Находит правила, перекрытые более широкими правилами выше.
        A перекрывает B если: A выше (раньше в списке), тот же src+dst+svc scope.
        """
        results: List[ShadowedRule] = []

        for i, rule_b in enumerate(self.rules):
            for j in range(i):  # только правила ВЫШЕ
                rule_a = self.rules[j]

                src_overlap, src_reason = _endpoints_overlap(rule_a.sources, rule_b.sources)
                if not src_overlap:
                    continue
                dst_overlap, dst_reason = _endpoints_overlap(rule_a.destinations, rule_b.destinations)
                if not dst_overlap:
                    continue
                svc_overlap, svc_reason = _services_overlap(rule_a.services, rule_b.services)
                if not svc_overlap:
                    continue

                results.append(ShadowedRule(
                    shadowed_name=rule_b.name,
                    shadowed_id=rule_b.rule_id,
                    shadower_name=rule_a.name,
                    shadower_id=rule_a.rule_id,
                    reason=f"src={src_reason}, dst={dst_reason}, svc={svc_reason}",
                ))
                break  # достаточно одного shadow-источника

        return results

    # ─── Conflict Detection ──────────────────────────────────────

    def detect_conflicts(self) -> List[RuleConflict]:
        """
        Находит конфликтующие правила: одинаковый scope, разный action.
        """
        results: List[RuleConflict] = []
        scope_map: Dict[str, List[FirewallRule]] = defaultdict(list)

        for rule in self.rules:
            scope = _rule_scope_signature(rule)
            scope_map[scope].append(rule)

        for scope, scope_rules in scope_map.items():
            if len(scope_rules) < 2:
                continue
            actions = {r.action for r in scope_rules}
            if len(actions) > 1:
                # Есть разные actions — конфликт
                src_str = _endpoint_signature(scope_rules[0].sources)
                dst_str = _endpoint_signature(scope_rules[0].destinations)
                svc_str = _service_signature(scope_rules[0].services)

                for i in range(len(scope_rules)):
                    for j in range(i + 1, len(scope_rules)):
                        ra, rb = scope_rules[i], scope_rules[j]
                        if ra.action != rb.action:
                            results.append(RuleConflict(
                                rule_a=ra.name,
                                rule_a_id=ra.rule_id,
                                rule_a_action=ra.action,
                                rule_b=rb.name,
                                rule_b_id=rb.rule_id,
                                rule_b_action=rb.action,
                                scope_description=f"{src_str} → {dst_str} [{svc_str}]",
                            ))

        return results

    # ─── Redundancy Detection ────────────────────────────────────

    def detect_redundancy(self) -> List[RedundantRule]:
        """
        Находит идентичные правила на разных устройствах (разные vendor/source_file).
        """
        results: List[RedundantRule] = []
        sig_map: Dict[str, List[FirewallRule]] = defaultdict(list)

        for rule in self.rules:
            sig = _rule_full_signature(rule)
            sig_map[sig].append(rule)

        for sig, sig_rules in sig_map.items():
            if len(sig_rules) < 2:
                continue
            # Проверяем, что они действительно с разных устройств/файлов
            vendors = {getattr(r, 'vendor', 'unknown') for r in sig_rules}
            if len(vendors) < 2:
                # Если vendor одинаковый, проверяем source_file
                source_files = {getattr(r, 'source_file', None) for r in sig_rules}
                if len(source_files) < 2:
                    continue  # действительно дубликаты в одном файле — не считаем redundant

            results.append(RedundantRule(
                rules=[r.name for r in sig_rules],
                rule_ids=[r.rule_id for r in sig_rules],
                signature=sig[:80],
            ))

        return results

    # ─── Unused Detection ────────────────────────────────────────

    def detect_unused(self) -> List[UnusedRule]:
        """
        Находит правила без hit-count.
        Если данных о hit-count нет — помечает 'unknown'.
        """
        results: List[UnusedRule] = []

        for rule in self.rules:
            hit_count = getattr(rule, 'hit_count', None)
            last_hit = getattr(rule, 'last_hit', None)

            if hit_count is None and last_hit is None:
                results.append(UnusedRule(
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    status='unknown',
                ))
            elif hit_count == 0:
                results.append(UnusedRule(
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    status='unused',
                ))
            elif isinstance(hit_count, (int, float)) and hit_count < 5:
                results.append(UnusedRule(
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    status='low_hits',
                ))

        return results

    # ─── Quality Score ───────────────────────────────────────────

    def compute_quality_score(self) -> int:
        """
        Вычисляет quality_score (0-100) на основе найденных проблем.
        """
        total_penalty = 0

        shadowed = self.detect_shadowing()
        conflicts = self.detect_conflicts()
        redundant = self.detect_redundancy()
        unused_list = self.detect_unused()

        total_penalty += len(shadowed) * self.PENALTY_SHADOWED
        total_penalty += len(conflicts) * self.PENALTY_CONFLICT
        total_penalty += sum(len(r.rules) for r in redundant) * self.PENALTY_REDUNDANT
        total_penalty += len(unused_list) * self.PENALTY_UNUSED

        score = max(0, 100 - total_penalty)
        # Ограничиваем снизу 0, сверху 100
        return min(100, score)

    # ─── Full Report ─────────────────────────────────────────────

    def analyze(self) -> QualityReport:
        """
        Выполняет полный анализ качества правил.
        """
        shadowed = self.detect_shadowing()
        conflicts = self.detect_conflicts()
        redundant_list = self.detect_redundancy()
        unused_list = self.detect_unused()
        quality_score = self.compute_quality_score()

        shadowed_dicts = [
            {
                'shadowed_name': s.shadowed_name,
                'shadowed_id': s.shadowed_id,
                'shadower_name': s.shadower_name,
                'shadower_id': s.shadower_id,
                'reason': s.reason,
            }
            for s in shadowed
        ]

        conflict_dicts = [
            {
                'rule_a': c.rule_a,
                'rule_a_id': c.rule_a_id,
                'rule_a_action': c.rule_a_action,
                'rule_b': c.rule_b,
                'rule_b_id': c.rule_b_id,
                'rule_b_action': c.rule_b_action,
                'scope_description': c.scope_description,
            }
            for c in conflicts
        ]

        redundant_dicts = [
            {
                'rules': r.rules,
                'rule_ids': r.rule_ids,
                'signature': r.signature,
                'count': len(r.rules),
            }
            for r in redundant_list
        ]

        unused_dicts = [
            {
                'rule_name': u.rule_name,
                'rule_id': u.rule_id,
                'status': u.status,
            }
            for u in unused_list
        ]

        summary = {
            'total_rules': self.total,
            'shadowed_rules': len(shadowed),
            'conflicts': len(conflicts),
            'redundant_rules': len(redundant_list),
            'unused_rules': len(unused_list),
            'quality_score': quality_score,
        }

        return QualityReport(
            shadowed=shadowed_dicts,
            conflicts=conflict_dicts,
            redundant=redundant_dicts,
            unused=unused_dicts,
            total_rules=self.total,
            quality_score=quality_score,
            summary=summary,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Экспорт полного отчёта в словарь."""
        report = self.analyze()
        return {
            'shadowed': report.shadowed,
            'conflicts': report.conflicts,
            'redundant': report.redundant,
            'unused': report.unused,
            'total_rules': report.total_rules,
            'quality_score': report.quality_score,
            'summary': report.summary,
        }
