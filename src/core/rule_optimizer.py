"""
A1 — Rule Optimization Engine

Группировка правил, IP-агрегация, preview и применение оптимизаций.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

from ..models.rule import FirewallRule


@dataclass
class RuleGrouping:
    """Группа правил, кандидатов на консолидацию."""
    source_subnet: str
    destination: str
    service: str
    rules: List[FirewallRule] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.rules)

    @property
    def can_consolidate(self) -> bool:
        return self.count >= 2


@dataclass
class OptimizationScore:
    """Метрики оптимизации до/после."""
    original_count: int
    consolidated_count: int
    savings_count: int
    savings_percent: float
    complexity_before: float
    complexity_after: float
    complexity_reduction_pct: float


@dataclass
class OptimizationPreview:
    """Предпросмотр оптимизации без применения."""
    original_rules: List[Dict[str, Any]]
    consolidated_rules: List[Dict[str, Any]]
    savings_count: int
    savings_percent: float
    groupings: List[Dict[str, Any]]
    score: OptimizationScore


class RuleOptimizer:
    """Оптимизатор правил межсетевого экрана."""

    def __init__(self, rules: List[FirewallRule]):
        self.rules = list(rules)
        self._groupings: List[RuleGrouping] = []

    def find_groupings(self) -> List[RuleGrouping]:
        """Группирует правила по source subnet + destination + service."""
        groups: Dict[str, RuleGrouping] = {}

        for rule in self.rules:
            for src in rule.sources:
                src_key = src.name
                for dst in rule.destinations:
                    dst_key = dst.name
                    for svc in rule.services:
                        svc_key = svc.name
                        group_key = f"{src_key}|{dst_key}|{svc_key}|{rule.action}"
                        if group_key not in groups:
                            groups[group_key] = RuleGrouping(
                                source_subnet=src_key,
                                destination=dst_key,
                                service=svc_key,
                            )
                        groups[group_key].rules.append(rule)

        self._groupings = [g for g in groups.values() if g.can_consolidate]
        return self._groupings

    def _collapse_subnets(self, subnets: Set[str]) -> List[str]:
        """Агрегирует смежные подсети в более крупные."""
        if not subnets:
            return []
        networks = []
        for s in subnets:
            try:
                networks.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                continue
        if not networks:
            return []
        collapsed = list(ipaddress.collapse_addresses(networks))
        return [str(c) for c in collapsed]

    def _build_consolidated_rule(
        self, grouping: RuleGrouping, name_prefix: str = "consolidated"
    ) -> Dict[str, Any]:
        """Строит консолидированное правило из группы."""
        from ..models.endpoint import Endpoint
        from ..models.service import Service

        # Collect all unique source CIDRs
        all_src_cidrs: Set[str] = set()
        all_dst_cidrs: Set[str] = set()
        all_ports: Set[str] = set()
        protocols: Set[str] = set()
        src_zones: Set[str] = set()
        dst_zones: Set[str] = set()

        for rule in grouping.rules:
            for src in rule.sources:
                all_src_cidrs.update(src.cidrs or set())
                if src.zone:
                    src_zones.add(src.zone)
            for dst in rule.destinations:
                all_dst_cidrs.update(dst.cidrs or set())
                if dst.zone:
                    dst_zones.add(dst.zone)
            for svc in rule.services:
                all_ports.update(svc.ports or set())
                protocols.add(svc.protocol)

        # Collapse subnets
        collapsed_src = self._collapse_subnets(all_src_cidrs)
        collapsed_dst = self._collapse_subnets(all_dst_cidrs)

        action = grouping.rules[0].action if grouping.rules else "accept"

        rule_name = f"{name_prefix}_{grouping.source_subnet}_to_{grouping.destination}_{grouping.service}"

        return {
            "name": rule_name,
            "action": action,
            "sources": collapsed_src if collapsed_src else [grouping.source_subnet],
            "destinations": collapsed_dst if collapsed_dst else [grouping.destination],
            "services": [grouping.service],
            "original_rules_count": grouping.count,
            "original_rule_names": [r.name for r in grouping.rules],
            "collapsed_source_cidrs": collapsed_src,
            "collapsed_dest_cidrs": collapsed_dst,
            "protocols_merged": sorted(protocols),
            "ports_merged": sorted(all_ports),
        }

    def optimize_preview(self) -> OptimizationPreview:
        """Возвращает preview оптимизации без применения изменений."""
        self.find_groupings()

        original_rules = []
        for rule in self.rules:
            original_rules.append({
                "name": rule.name,
                "action": rule.action,
                "sources": [s.name for s in rule.sources],
                "destinations": [d.name for d in rule.destinations],
                "services": [s.name for s in rule.services],
            })

        consolidated_rules = []
        groupings_data = []
        remaining_indices: Set[int] = set()

        for grouping in self._groupings:
            cons = self._build_consolidated_rule(grouping)
            consolidated_rules.append(cons)
            groupings_data.append({
                "source_subnet": grouping.source_subnet,
                "destination": grouping.destination,
                "service": grouping.service,
                "rule_count": grouping.count,
                "original_rule_names": [r.name for r in grouping.rules],
                "consolidated": cons,
            })
            for rule in grouping.rules:
                # Mark as consumed
                for i, r in enumerate(self.rules):
                    if r is rule:
                        remaining_indices.add(i)

        # Rules that were NOT grouped stay as-is
        for i, rule in enumerate(self.rules):
            if i not in remaining_indices:
                consolidated_rules.append({
                    "name": rule.name,
                    "action": rule.action,
                    "sources": [s.name for s in rule.sources],
                    "destinations": [d.name for d in rule.destinations],
                    "services": [s.name for s in rule.services],
                    "original_rules_count": 1,
                    "original_rule_names": [rule.name],
                })

        original_count = len(self.rules)
        consolidated_count = len(consolidated_rules)
        savings = original_count - consolidated_count
        savings_pct = round(savings / max(1, original_count) * 100, 1)

        # Complexity scoring: more services/ports = higher complexity
        complexity_before = sum(
            len(r.sources) * len(r.destinations) * len(r.services)
            for r in self.rules
        )
        complexity_after = sum(
            len(r.get("sources", [])) * len(r.get("destinations", [])) * len(r.get("services", []))
            for r in consolidated_rules
        )
        complexity_reduction = round(
            (1 - complexity_after / max(1, complexity_before)) * 100, 1
        )

        score = OptimizationScore(
            original_count=original_count,
            consolidated_count=consolidated_count,
            savings_count=savings,
            savings_percent=savings_pct,
            complexity_before=complexity_before,
            complexity_after=complexity_after,
            complexity_reduction_pct=complexity_reduction,
        )

        return OptimizationPreview(
            original_rules=original_rules,
            consolidated_rules=consolidated_rules,
            savings_count=savings,
            savings_percent=savings_pct,
            groupings=groupings_data,
            score=score,
        )

    def apply_optimization(self) -> List[Dict[str, Any]]:
        """Применяет оптимизацию и возвращает новый список правил."""
        preview = self.optimize_preview()
        return preview.consolidated_rules

    def to_dict(self) -> Dict[str, Any]:
        """Возвращает результат в словаре для API."""
        preview = self.optimize_preview()
        return {
            "preview": {
                "original_rules": preview.original_rules,
                "consolidated_rules": preview.consolidated_rules,
                "groupings": preview.groupings,
            },
            "score": {
                "original_count": preview.score.original_count,
                "consolidated_count": preview.score.consolidated_count,
                "savings_count": preview.score.savings_count,
                "savings_percent": preview.score.savings_percent,
                "complexity_before": preview.score.complexity_before,
                "complexity_after": preview.score.complexity_after,
                "complexity_reduction_pct": preview.score.complexity_reduction_pct,
            },
        }
