"""
MITRE ATT&CK Mapper — сопоставляет findings аудита с техниками MITRE ATT&CK.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field


@dataclass
class MitreMatch:
    finding: dict
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str  # high/medium/low
    description: str


@dataclass
class MitreReport:
    matches: List[MitreMatch] = field(default_factory=list)
    total_findings: int = 0
    matched_findings: int = 0
    tactics_covered: Set[str] = field(default_factory=set)
    techniques_used: Set[str] = field(default_factory=set)


class MitreMapper:
    """Сопоставляет security findings с MITRE ATT&CK техниками."""

    def __init__(self, mapping_path: Optional[str] = None):
        if mapping_path is None:
            mapping_path = str(Path(__file__).parent.parent.parent / "data" / "mitre_mapping.json")
        with open(mapping_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.mappings = data.get("mappings", [])
        self.tactics = data.get("tactics", [])

    def _match_text(self, text: str, pattern: str) -> bool:
        """Проверяет вхождение pattern в text (case-insensitive, word boundary)."""
        return pattern.lower() in text.lower()

    def match_finding(self, finding: dict) -> Optional[MitreMatch]:
        """Сопоставляет один finding с MITRE техникой."""
        check_type = finding.get("type", "")
        description = finding.get("description", "")
        recommendation = finding.get("recommendation", "")
        combined = f"{check_type} {description} {recommendation}"

        # Severity-based confidence boost
        severity = finding.get("severity", "low")
        conf_boost = {"critical": "high", "high": "high", "medium": "medium"}.get(severity, "low")

        for mapping in self.mappings:
            pattern = mapping["finding_pattern"]
            if self._match_text(combined, pattern):
                technique_id = mapping["technique_id"]
                confidence = conf_boost

                # Downgrade if only partial match
                if pattern != "any-any rule" and "any-any" in combined:
                    continue  # prefer specific matches

                return MitreMatch(
                    finding=finding,
                    technique_id=technique_id,
                    technique_name=mapping["technique_name"],
                    tactic=mapping["tactic"],
                    confidence=confidence,
                    description=mapping["description"],
                )

        return None

    def map_all(self, audit_issues: List[dict]) -> MitreReport:
        """Сопоставляет все findings с MITRE."""
        report = MitreReport(total_findings=len(audit_issues))

        for issue in audit_issues:
            match = self.match_finding(issue)
            if match:
                report.matches.append(match)
                report.tactics_covered.add(match.tactic)
                report.techniques_used.add(match.technique_id)

        report.matched_findings = len(report.matches)
        return report

    def get_matrix_data(self, audit_issues: List[dict]) -> dict:
        """Возвращает данные для визуализации MITRE матрицы."""
        report = self.map_all(audit_issues)

        # Построить матрицу: tactic → {technique_id: count}
        matrix = {}
        for tactic in self.tactics:
            matrix[tactic] = {}

        for match in report.matches:
            tactic = match.tactic
            technique = match.technique_id
            if tactic not in matrix:
                matrix[tactic] = {}
            matrix[tactic][technique] = matrix[tactic].get(technique, 0) + 1

        # Удалить пустые тактики
        matrix = {k: v for k, v in matrix.items() if v}

        return {
            "matrix": matrix,
            "total_matches": len(report.matches),
            "total_findings": report.total_findings,
            "matched_findings": report.matched_findings,
            "tactics_covered": sorted(report.tactics_covered),
            "techniques_used": sorted(report.techniques_used),
            "matches": [
                {
                    "finding_type": m.finding.get("type", ""),
                    "severity": m.finding.get("severity", ""),
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                    "confidence": m.confidence,
                }
                for m in report.matches
            ],
        }
