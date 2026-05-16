"""
SIEM Live Correlation
Сопоставляет результаты аудита firewall с логами syslog/событиями
для обнаружения реальных инцидентов безопасности.

Поддерживает:
- Парсинг syslog-файлов (RFC 3164 / 5424)
- Сопоставление IP-адресов из audit findings с event logs
- Корреляция по severity, времени, источнику/назначению
- Генерация SIEM detection rules (Sigma-подобный формат)
- Вывод correlated alerts и рекомендаций
"""

import re
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class SyslogEvent:
    """Разобранное syslog-событие."""
    timestamp: Optional[datetime]
    hostname: str
    facility: str
    severity: str
    message: str
    raw: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None


@dataclass
class CorrelatedAlert:
    """Скоррелированное предупреждение."""
    audit_issue: Dict
    matched_events: List[SyslogEvent] = field(default_factory=list)
    correlation_score: float = 0.0
    detection_rule: Optional[str] = None
    recommendation: str = ""
    severity: str = "low"
    timestamp: Optional[datetime] = None


class SyslogParser:
    """Парсер syslog-файлов (RFC 3164 + 5424)."""
    
    # RFC 3164: <PRI>TIMESTAMP HOSTNAME MSG
    RFC3164_PATTERN = re.compile(
        r'^<?(\d{1,3})>?'                          # PRI (optional brackets)
        r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'  # timestamp
        r'\s+(\S+)'                                 # hostname
        r'\s+(.*)$'                                 # message
    )
    
    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    RFC5424_PATTERN = re.compile(
        r'^<(\d{1,3})>(\d+)\s+'                     # PRI VERSION
        r'(\S+)\s+'                                  # TIMESTAMP
        r'(\S+)\s+'                                  # HOSTNAME
        r'(\S+)\s+'                                  # APP-NAME
        r'(\S+)\s+'                                  # PROCID
        r'(\S+)\s+'                                  # MSGID
        r'(\S+)\s+'                                  # STRUCTURED-DATA
        r'(.*)$'                                     # MSG
    )
    
    # Alternative: simpler format with ISO timestamp
    ISO_PATTERN = re.compile(
        r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)'
        r'\s+(\S+)'                                  # hostname
        r'\s+(\S+)'                                  # program/process
        r'(?::\s+)?(.*)$'                            # message
    )
    
    # Severity from PRI
    SEVERITIES = {
        0: 'emergency', 1: 'alert', 2: 'critical',
        3: 'error', 4: 'warning', 5: 'notice',
        6: 'info', 7: 'debug'
    }
    
    def parse_file(self, file_path: str) -> List[SyslogEvent]:
        """Парсит syslog-файл и возвращает список событий."""
        events = []
        
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                event = self._parse_line(line)
                if event:
                    events.append(event)
        
        return events
    
    def _parse_line(self, line: str) -> Optional[SyslogEvent]:
        """Парсит одну строку syslog."""
        timestamp = None
        hostname = "unknown"
        facility = "local"
        severity = "info"
        message = line
        raw = line
        
        # Пробуем RFC 3164
        m = self.RFC3164_PATTERN.match(line)
        if m:
            pri = int(m.group(1))
            severity = self.SEVERITIES.get(pri & 0x07, 'info')
            facility_str = (pri >> 3) & 0x1f
            ts_str = m.group(2)
            hostname = m.group(3)
            message = m.group(4)
            
            # Парсим timestamp
            try:
                # Format: "Apr 24 17:49:10"
                ts = datetime.strptime(ts_str, "%b %d %H:%M:%S")
                ts = ts.replace(year=datetime.utcnow().year)
            except ValueError:
                ts = None
            timestamp = ts
            
            event = SyslogEvent(
                timestamp=timestamp,
                hostname=hostname,
                facility=str(facility_str),
                severity=severity,
                message=message,
                raw=raw
            )
        else:
            # Пробуем ISO timestamp формат
            m = self.ISO_PATTERN.match(line)
            if m:
                ts_str = m.group(1)
                hostname = m.group(2)
                message = m.group(4) if m.lastindex >= 4 else m.group(3)
                
                try:
                    ts_str = ts_str.replace('Z', '+00:00').replace(' ', 'T')
                    timestamp = datetime.fromisoformat(ts_str)
                except ValueError:
                    try:
                        timestamp = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
                    except ValueError:
                        timestamp = None
                
                event = SyslogEvent(
                    timestamp=timestamp,
                    hostname=hostname,
                    facility="local",
                    severity=severity,
                    message=message,
                    raw=raw
                )
            else:
                # Unknown format — сохраняем как есть
                event = SyslogEvent(
                    timestamp=None,
                    hostname="unknown",
                    facility="unknown",
                    severity="unknown",
                    message=line,
                    raw=raw
                )
        
        # Извлекаем IP и порты из сообщения
        event = self._extract_ips(event)
        
        return event
    
    def _extract_ips(self, event: SyslogEvent) -> SyslogEvent:
        """Извлекает IP-адреса и порты из сообщения."""
        msg = event.message
        
        # IPv4
        ipv4_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        ips = ipv4_pattern.findall(msg)
        
        if ips:
            # Фильтруем private/localhost если много адресов
            valid_ips = [ip for ip in ips if not ip.startswith('127.')
                         and not ip.startswith('0.')
                         and not ip.startswith('255.')]
            
            if valid_ips:
                if len(valid_ips) >= 2:
                    # source/dest пара
                    event.source_ip = valid_ips[0]
                    event.dest_ip = valid_ips[-1]
                else:
                    event.source_ip = valid_ips[0]
            elif ips:
                event.source_ip = ips[0]
        
        # Порт
        port_pattern = re.compile(r'\b(?:port|dport|DPT|dst_port)[=:\s]+(\d{1,5})\b', re.IGNORECASE)
        m = port_pattern.search(msg)
        if m:
            event.port = int(m.group(1))
        
        # Действие (accept/deny/drop/allow/block)
        action_pattern = re.compile(r'\b(accept|deny|drop|allow|block|permit)\b', re.IGNORECASE)
        m = action_pattern.search(msg)
        if m:
            event.action = m.group(1).lower()
        
        # Протокол
        proto_pattern = re.compile(r'\b(?:proto|protocol)[=:\s]+(tcp|udp|icmp)\b', re.IGNORECASE)
        m = proto_pattern.search(msg)
        if m:
            event.protocol = m.group(1).lower()
        
        return event


class SIEMCorrelator:
    """Коррелятор: сопоставляет audit findings с логами."""
    
    # Пороги для корреляции
    DEFAULT_TIME_WINDOW_HOURS = 24
    MIN_CORRELATION_SCORE = 0.3
    
    # Ключевые слова для severity повышения
    CRITICAL_KEYWORDS = [
        'exploit', 'overflow', 'injection', 'bypass', 'root',
        'backdoor', 'trojan', 'ransomware', 'breach'
    ]
    
    HIGH_KEYWORDS = [
        'scan', 'brute', 'unauthorized', 'suspicious', 'anomaly',
        'malware', 'phishing', 'spoof', 'flood'
    ]
    
    MEDIUM_KEYWORDS = [
        'failed', 'error', 'timeout', 'reset', 'refused',
        'blocked', 'dropped', 'rejected'
    ]
    
    def __init__(
        self,
        audit_issues: List[Dict],
        syslog_events: Optional[List[SyslogEvent]] = None,
        time_window_hours: int = DEFAULT_TIME_WINDOW_HOURS,
    ):
        self.audit_issues = audit_issues
        self.events = syslog_events or []
        self.time_window = timedelta(hours=time_window_hours)
        
        # Индексируем события по IP
        self._events_by_ip: Dict[str, List[SyslogEvent]] = defaultdict(list)
        self._build_index()
    
    def _build_index(self):
        """Строит индекс событий по IP."""
        for event in self.events:
            if event.source_ip:
                self._events_by_ip[event.source_ip].append(event)
            if event.dest_ip:
                self._events_by_ip[event.dest_ip].append(event)
    
    def correlate(self) -> List[CorrelatedAlert]:
        """Выполняет корреляцию audit issues с syslog событиями."""
        alerts = []
        
        for issue in self.audit_issues:
            src_ip = issue.get('source_ip')
            dst_ip = issue.get('destination_ip')
            issue_port = issue.get('port')
            issue_severity = issue.get('severity', 'low')
            issue_ts = self._get_issue_timestamp(issue)
            
            # Находим matching events
            matched = []
            
            # Ищем по source IP
            if src_ip:
                matched.extend(self._find_matching(src_ip, issue, issue_ts))
            
            # Ищем по dest IP (без дублирования)
            if dst_ip and dst_ip != src_ip:
                dest_events = self._find_matching(dst_ip, issue, issue_ts)
                seen_ids = {id(e) for e in matched}
                for e in dest_events:
                    if id(e) not in seen_ids:
                        matched.append(e)
            
            if not matched and not self.events:
                # No events to correlate — create rule-only alert
                alert = CorrelatedAlert(
                    audit_issue=issue,
                    matched_events=[],
                    correlation_score=0.0,
                    detection_rule=self._generate_detection_rule(issue),
                    recommendation=self._generate_recommendation(issue, []),
                    severity=issue_severity,
                    timestamp=issue_ts,
                )
                alerts.append(alert)
                continue
            
            # Подсчитываем correlation score
            score = self._calculate_score(issue, matched)
            
            if score >= self.MIN_CORRELATION_SCORE or not self.events:
                # Повышаем severity если есть критические keywords в событиях
                final_severity = self._elevate_severity(issue_severity, matched)
                
                alert = CorrelatedAlert(
                    audit_issue=issue,
                    matched_events=matched,
                    correlation_score=score,
                    detection_rule=self._generate_detection_rule(issue),
                    recommendation=self._generate_recommendation(issue, matched),
                    severity=final_severity,
                    timestamp=max(
                        [e.timestamp for e in matched if e.timestamp] + 
                        ([issue_ts] if issue_ts else [])
                    ) if matched else issue_ts,
                )
                alerts.append(alert)
        
        # Сортируем по severity и score
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        alerts.sort(key=lambda a: (severity_order.get(a.severity, 4), -a.correlation_score))
        
        return alerts
    
    def _get_issue_timestamp(self, issue: Dict) -> Optional[datetime]:
        """Извлекает timestamp из issue."""
        ts = issue.get('timestamp') or issue.get('found_at')
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except (ValueError, TypeError):
                pass
        return None
    
    def _find_matching(
        self, ip: str, issue: Dict, issue_ts: Optional[datetime]
    ) -> List[SyslogEvent]:
        """Находит события по IP с временной фильтрацией."""
        candidates = self._events_by_ip.get(ip, [])
        
        if not candidates:
            return []
        
        matched = []
        issue_port = issue.get('port')
        
        for event in candidates:
            # Временная фильтрация
            if issue_ts and event.timestamp:
                diff = abs((event.timestamp - issue_ts).total_seconds())
                if diff > self.time_window.total_seconds():
                    continue
            
            # Если есть порт в issue и event — проверяем совпадение
            if issue_port and event.port:
                if str(issue_port) != str(event.port):
                    # Не строгий match — добавляем с пониженным весом
                    # (порты могут быть range или другие related)
                    pass
            
            matched.append(event)
        
        return matched
    
    def _calculate_score(self, issue: Dict, events: List[SyslogEvent]) -> float:
        """Вычисляет correlation score (0.0 - 1.0)."""
        if not events:
            return 0.0
        
        score = 0.0
        issue_port = issue.get('port')
        
        for event in events:
            event_score = 0.1  # базовый балл за наличие события
            
            # Совпадение IP
            if event.source_ip and (
                event.source_ip == issue.get('source_ip') or
                event.dest_ip == issue.get('destination_ip')
            ):
                event_score += 0.3
            
            # Совпадение порта
            if issue_port and event.port and str(issue_port) == str(event.port):
                event_score += 0.2
            
            # Совпадение severity
            issue_sev = issue.get('severity', 'low')
            if event.severity in ('critical', 'error') and issue_sev in ('critical', 'high'):
                event_score += 0.2
            
            # Совпадение action
            if event.action and issue.get('action'):
                if event.action.lower() == issue['action'].lower():
                    event_score += 0.1
            
            # Ключевые слова в сообщении
            msg_lower = event.message.lower()
            if any(kw in msg_lower for kw in self.CRITICAL_KEYWORDS):
                event_score += 0.2
            elif any(kw in msg_lower for kw in self.HIGH_KEYWORDS):
                event_score += 0.1
            
            score = max(score, min(event_score, 1.0))
        
        # Бонус за количество событий
        if len(events) > 3:
            score = min(score + 0.1, 1.0)
        if len(events) > 10:
            score = min(score + 0.1, 1.0)
        
        return round(score, 2)
    
    def _elevate_severity(self, base_severity: str, events: List[SyslogEvent]) -> str:
        """Повышает severity на основе ключевых слов в событиях."""
        severity_order = ['low', 'medium', 'high', 'critical']
        current = severity_order.index(base_severity) if base_severity in severity_order else 0
        
        for event in events:
            msg_lower = event.message.lower()
            
            if any(kw in msg_lower for kw in self.CRITICAL_KEYWORDS):
                current = max(current, severity_order.index('critical'))
                break
            elif any(kw in msg_lower for kw in self.HIGH_KEYWORDS):
                current = max(current, severity_order.index('high'))
        
        return severity_order[min(current, 3)]
    
    def _generate_detection_rule(self, issue: Dict) -> str:
        """Генерирует Sigma-подобное detection rule."""
        src = issue.get('source_ip', 'any')
        dst = issue.get('destination_ip', 'any')
        port = issue.get('port', 'any')
        action = issue.get('action', '')
        check_type = issue.get('check_type', 'unknown')
        risk = issue.get('risk_score', 0)
        
        rule = f"""title: Firewall Analyzer Detection - {check_type}
id: fa-{hash(src + dst + str(port)) & 0xFFFFFFFF:08x}
status: experimental
description: {issue.get('description', 'Auto-generated rule from firewall audit')}
author: Firewall Analyzer v3.0
date: {datetime.utcnow().strftime('%Y-%m-%d')}
tags:
  - attack.initial_access
  - firewall.audit
logsource:
  category: firewall
detection:
  selection:
    src_ip: '{src}'
    dst_ip: '{dst}'
    dst_port: {port}
    action: '{action}'
  condition: selection
falsepositives:
  - Legitimate administrative access
level: {self._risk_to_level(risk)}
risk_score: {risk}"""
        return rule
    
    def _generate_recommendation(
        self, issue: Dict, events: List[SyslogEvent]
    ) -> str:
        """Генерирует рекомендации на основе корреляции."""
        base_rec = f"Review firewall rule: {issue.get('rule_name', 'unknown')}"
        
        if not events:
            return f"{base_rec}. No live events correlated — review rule statically."
        
        critical_events = sum(
            1 for e in events
            if any(kw in e.message.lower() for kw in self.CRITICAL_KEYWORDS)
        )
        high_events = sum(
            1 for e in events
            if any(kw in e.message.lower() for kw in self.HIGH_KEYWORDS)
        )
        
        if critical_events > 0:
            return (
                f"IMMEDIATE ACTION: {critical_events} critical events correlated. "
                f"Review and potentially disable rule {issue.get('rule_name', 'unknown')}. "
                f"Investigate source {issue.get('source_ip', 'unknown')}."
            )
        elif high_events > 3:
            return (
                f"Investigate: {high_events} suspicious events detected. "
                f"Consider restricting rule {issue.get('rule_name', 'unknown')}. "
                f"Check SIEM dashboard for details."
            )
        elif len(events) > 10:
            return (
                f"Monitor: {len(events)} events matched. "
                f"Rule {issue.get('rule_name', 'unknown')} is active — review periodically."
            )
        else:
            return (
                f"Low activity: {len(events)} events matched. "
                f"Rule {issue.get('rule_name', 'unknown')} appears normal. "
                f"Continue monitoring."
            )
    
    def _risk_to_level(self, risk: float) -> str:
        """Конвертирует risk score в уровень."""
        if risk >= 8:
            return 'critical'
        elif risk >= 6:
            return 'high'
        elif risk >= 4:
            return 'medium'
        else:
            return 'low'
    
    def get_summary(self) -> Dict:
        """Возвращает сводку корреляции."""
        alerts = self.correlate()
        
        total_correlated = sum(1 for a in alerts if a.matched_events)
        by_severity = defaultdict(int)
        for a in alerts:
            by_severity[a.severity] += 1
        
        return {
            'total_issues': len(self.audit_issues),
            'total_correlated': total_correlated,
            'total_events_analyzed': len(self.events),
            'alerts_by_severity': dict(by_severity),
            'high_confidence_alerts': sum(
                1 for a in alerts if a.correlation_score >= 0.7
            ),
            'generated_rules': len(alerts),
        }
    
    def export_alerts_json(self, output_path: str):
        """Экспортирует скоррелированные алерты в JSON."""
        alerts = self.correlate()
        
        data = {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'summary': self.get_summary(),
            'alerts': [
                {
                    'audit_issue': a.audit_issue,
                    'matched_events_count': len(a.matched_events),
                    'correlation_score': a.correlation_score,
                    'detection_rule': a.detection_rule,
                    'recommendation': a.recommendation,
                    'severity': a.severity,
                    'timestamp': a.timestamp.isoformat() if a.timestamp else None,
                    'sample_events': [
                        {
                            'timestamp': e.timestamp.isoformat() if e.timestamp else None,
                            'hostname': e.hostname,
                            'severity': e.severity,
                            'message': e.message[:200],
                            'source_ip': e.source_ip,
                            'dest_ip': e.dest_ip,
                            'port': e.port,
                        }
                        for e in a.matched_events[:5]
                    ]
                }
                for a in alerts
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        return output_path


def run_correlation(
    audit_issues: List[Dict],
    syslog_path: Optional[str] = None,
    time_window_hours: int = 24,
    output_path: Optional[str] = None,
) -> Dict:
    """
    Запускает процесс SIEM-корреляции.
    
    Args:
        audit_issues: Список findings из аудита безопасности
        syslog_path: Путь к файлу syslog/event log
        time_window_hours: Временное окно для корреляции
        output_path: Путь для сохранения JSON-отчёта
        
    Returns:
        Словарь с результатами корреляции
    """
    events = []
    if syslog_path and Path(syslog_path).exists():
        parser = SyslogParser()
        events = parser.parse_file(syslog_path)
        print(f"  [SIEM] Parsed {len(events)} events from {syslog_path}")
    
    correlator = SIEMCorrelator(
        audit_issues=audit_issues,
        syslog_events=events,
        time_window_hours=time_window_hours,
    )
    
    summary = correlator.get_summary()
    
    print(f"  [SIEM] Correlation complete:")
    print(f"    Issues analyzed: {summary['total_issues']}")
    print(f"    Events analyzed: {summary['total_events_analyzed']}")
    print(f"    Correlated alerts: {summary['total_correlated']}")
    print(f"    High confidence: {summary['high_confidence_alerts']}")
    print(f"    By severity: {summary['alerts_by_severity']}")
    
    if output_path:
        correlator.export_alerts_json(output_path)
        print(f"  [SIEM] Correlation report: {output_path}")
    
    return summary


__all__ = [
    'SyslogParser', 'SyslogEvent', 'SIEMCorrelator', 'CorrelatedAlert',
    'run_correlation',
]
