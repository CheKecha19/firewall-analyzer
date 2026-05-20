"""
Парсер ACL для Cisco, Juniper, Huawei.
"""
import re
from pathlib import Path
from typing import List, Optional, Set, Tuple
from .base_parser import BaseParser
from ..models.endpoint import Endpoint
from ..models.service import Service
from ..models.rule import FirewallRule


class ACLParser(BaseParser):
    """Парсер ACL для Cisco, Juniper и Huawei."""
    
    VENDOR = "acl"
    
    def __init__(self):
        self.current_vendor = None
    
    def can_parse(self, file_path: Path, content: Optional[str] = None) -> bool:
        """Проверяет, является ли файл ACL конфигурацией."""
        if content is None:
            try:
                content = self.read_file(file_path)
            except Exception:
                return False
        
        content_upper = content.upper()
        
        # Проверяем Cisco/Huawei ACL
        if re.search(r'ip\s+access-list\s+(standard|extended)', content, re.IGNORECASE):
            return True
        if re.search(r'^\s*access-list\s+\d+', content, re.MULTILINE | re.IGNORECASE):
            return True
        
        # Huawei: acl number XXXX
        if re.search(r'^\s*acl\s+(number|name)\s+\w+', content, re.MULTILINE | re.IGNORECASE):
            return True
        
        # Проверяем Juniper
        if 'firewall {' in content or 'filter ' in content:
            return True
        if re.search(r'term\s+\w+\s+{', content, re.IGNORECASE):
            return True
        
        # HP ip authorized-managers
        if re.search(r'ip\s+authorized-managers', content, re.IGNORECASE):
            return True
        
        # ArubaOS-CX access-list
        if re.search(r'access-list\s+ip\s+\w+', content, re.IGNORECASE):
            return True
        
        # Aruba Wireless Controller: ip access-list session
        if re.search(r'ip\s+access-list\s+session\s+\S+', content, re.IGNORECASE):
            return True
        
        return False
    
    def detect_vendor(self, content: str) -> str:
        """Определяет вендора по содержимому."""
        content_lower = content.lower()
        
        # Juniper характерные признаки
        if 'firewall {' in content_lower or 'filter ' in content_lower:
            if re.search(r'term\s+\w+\s+{', content_lower):
                return 'juniper'
        
        # Aruba Wireless Controller: ip access-list session
        if re.search(r'ip\s+access-list\s+session\s+', content_lower):
            return 'aruba'
        
        # ArubaOS-CX access-list ip
        if re.search(r'access-list\s+ip\s+\w+', content_lower):
            return 'aruba'
        
        # Cisco стандартный синтаксис
        if re.search(r'ip\s+access-list\s+(standard|extended)', content_lower):
            return 'cisco'
        
        # Huawei похож на Cisco
        if re.search(r'acl\s+(number|name)', content_lower):
            return 'huawei'
        
        # Общий ACL синтаксис
        if re.search(r'^\s*access-list\s+', content, re.MULTILINE | re.IGNORECASE):
            return 'cisco'
        
        return 'cisco'  # По умолчанию
    
    def parse(self, file_path: Path) -> List[FirewallRule]:
        """Парсит ACL файл."""
        content = self.read_file(file_path)
        self.current_vendor = self.detect_vendor(content)
        
        if self.current_vendor == 'juniper':
            return self._parse_juniper(content)
        elif self.current_vendor == 'aruba':
            return self._parse_aruba_session(content)
        else:
            return self._parse_cisco_huawei(content)
    
    def _parse_cisco_huawei(self, content: str) -> List[FirewallRule]:
        """Парсит ACL Cisco/Huawei/HP/Aruba."""
        rules = []
        lines = content.split('\n')
        
        current_acl_name = None
        current_acl_num = None
        current_aruba_acl = None
        in_aruba_acl = False
        
        for line_num, line in enumerate(lines, 1):
            original_line = line
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            # HP ip authorized-managers
            hp_auth_match = re.match(
                r'ip\s+authorized-managers\s+(\S+)\s+(\S+)(?:\s+access\s+(\S+))?(?:\s+access-method\s+(\S+))?',
                line, re.IGNORECASE
            )
            if hp_auth_match:
                rule = self._parse_hp_authorized_manager(line, hp_auth_match, line_num)
                if rule:
                    rules.append(rule)
                continue
            
            # ArubaOS-CX access-list ip
            if re.match(r'access-list\s+ip\s+(\w+)', line, re.IGNORECASE):
                match = re.match(r'access-list\s+ip\s+(\w+)', line, re.IGNORECASE)
                current_aruba_acl = match.group(1)
                in_aruba_acl = True
                continue
            
            # Применение Aruba ACL
            if in_aruba_acl and re.match(r'apply\s+access-list', line, re.IGNORECASE):
                in_aruba_acl = False
                current_aruba_acl = None
                continue
            
            # Строки внутри Aruba ACL
            if in_aruba_acl and current_aruba_acl:
                # Проверяем отступ - Aruba ACL использует отступы
                if original_line.startswith('    ') or original_line.startswith('\t'):
                    rule = self._parse_aruba_acl_line(line, current_aruba_acl, line_num)
                    if rule:
                        rules.append(rule)
                else:
                    # Выходим из ACL если нет отступа
                    in_aruba_acl = False
                    current_aruba_acl = None
                continue
            
            # Huawei именованный ACL: acl name NAME
            huawei_named_match = re.match(
                r'acl\s+name\s+(\S+)',
                line, re.IGNORECASE
            )
            if huawei_named_match:
                current_acl_name = huawei_named_match.group(1)
                current_acl_num = None
                continue
            
            # Huawei нумерованный ACL: acl number XXXX
            huawei_num_match = re.match(
                r'acl\s+number\s+(\d+)',
                line, re.IGNORECASE
            )
            if huawei_num_match:
                current_acl_num = huawei_num_match.group(1)
                current_acl_name = f"acl_{current_acl_num}"
                continue
            
            # Cisco именованный ACL
            cisco_named_match = re.match(
                r'ip\s+access-list\s+(standard|extended)\s+(\S+)',
                line, re.IGNORECASE
            )
            if cisco_named_match:
                current_acl_name = cisco_named_match.group(2)
                current_acl_num = None
                continue
            
            # Правило внутри Huawei ACL: rule X permit|deny ...
            if current_acl_name and re.match(r'rule\s+\d+\s+(permit|deny|allow|drop)', line, re.IGNORECASE):
                rule = self._parse_huawei_rule_line(line, current_acl_name, line_num)
                if rule:
                    rules.append(rule)
                continue
            
            # Правило внутри именованного Cisco ACL
            if current_acl_name and re.match(r'\s*(\d*)\s*(permit|deny)', line, re.IGNORECASE):
                rule = self._parse_named_acl_line(line, current_acl_name, line_num)
                if rule:
                    rules.append(rule)
                continue
            
            # Нумерованный ACL: access-list NUMBER permit ...
            numbered_match = re.match(
                r'access-list\s+(\d+)\s+(permit|deny)\s+(.+)',
                line, re.IGNORECASE
            )
            if numbered_match:
                rule = self._parse_numbered_acl_line(line, line_num)
                if rule:
                    rules.append(rule)
                continue
        
        return rules
    
    def _parse_huawei_rule_line(self, line: str, acl_name: str, line_num: int) -> Optional[FirewallRule]:
        """Парсит строку правила Huawei ACL.
        
        Формат: rule X permit|deny [protocol] source [SOP] [port] destination [DOP] [port]
        Пример: rule 0 permit source 192.168.232.204 0 
        Пример: rule 1 permit source 192.168.253.0 0.0.0.255
        """
        # Убираем description если есть
        line = re.sub(r'description\s+.*$', '', line, flags=re.IGNORECASE).strip()
        
        # Извлекаем номер правила и action
        rule_match = re.match(r'rule\s+(\d+)\s+(permit|deny|allow|drop)', line, re.IGNORECASE)
        if not rule_match:
            return None
        
        rule_id = rule_match.group(1)
        action_str = rule_match.group(2).lower()
        action = 'accept' if action_str in ['permit', 'allow'] else 'deny'
        
        # Парсим source
        sources = []
        src_match = re.search(r'source\s+(\S+)(?:\s+(\S+))?', line, re.IGNORECASE)
        if src_match:
            src_spec = src_match.group(1)
            src_mask = src_match.group(2) if src_match.group(2) else '0'
            
            if src_spec.lower() == 'any':
                sources = [Endpoint('any', 'host', {'0.0.0.0/0'})]
            elif re.match(r'\d+\.\d+\.\d+\.\d+', src_spec):
                if src_mask and src_mask != '0' and src_mask != '0.0.0.0':
                    cidr = self._wildcard_to_cidr(src_mask)
                    network = f"{src_spec}/{cidr}"
                    sources = [Endpoint(network, 'subnet', {network})]
                else:
                    sources = [Endpoint(src_spec, 'host', {src_spec})]
        else:
            sources = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        
        # Парсим destination (если есть)
        destinations = []
        dst_match = re.search(r'destination\s+(\S+)(?:\s+(\S+))?', line, re.IGNORECASE)
        if dst_match:
            dst_spec = dst_match.group(1)
            dst_mask = dst_match.group(2) if dst_match.group(2) else '0'
            
            if dst_spec.lower() == 'any':
                destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
            elif re.match(r'\d+\.\d+\.\d+\.\d+', dst_spec):
                if dst_mask and dst_mask != '0' and dst_mask != '0.0.0.0':
                    cidr = self._wildcard_to_cidr(dst_mask)
                    network = f"{dst_spec}/{cidr}"
                    destinations = [Endpoint(network, 'subnet', {network})]
                else:
                    destinations = [Endpoint(dst_spec, 'host', {dst_spec})]
        else:
            # Если destination не указан - значит any
            destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        
        # Парсим порты (service) - для Huawei
        services = []
        port_match = re.search(r'(eq|gt|lt|range)\s+(\d+)', line, re.IGNORECASE)
        if port_match:
            services = self._parse_ports_from_acl(line, 'tcp')
        else:
            protocol_match = re.search(r'(permit|deny|allow|drop)\s+(tcp|udp|ip|icmp|gre|esp)', line, re.IGNORECASE)
            if protocol_match:
                protocol = protocol_match.group(2).lower()
                services = self._parse_ports_from_acl(line, protocol)
            else:
                services = [Service('ip', 'ip', set())]
        
        return FirewallRule(
            name=f"{acl_name}_rule_{rule_id}",
            rule_id=f"{acl_name}.{rule_id}",
            sources=sources,
            destinations=destinations,
            services=services,
            action=action,
            enabled=True,
            description=f"Huawei ACL rule {rule_id} from {acl_name}",
            vendor='huawei'
        )
    
    def _parse_named_acl_line(self, line: str, acl_name: str, line_num: int) -> Optional[FirewallRule]:
        """Парсит строку именованного ACL."""
        # Убираем ведущий номер если есть
        line = re.sub(r'^\s*\d+\s+', '', line)
        
        # Формат: permit tcp|udp|ip|icmp source destination [eq|gt|lt|neq port]
        match = re.match(
            r'(permit|allow)\s+(tcp|udp|ip|icmp|gre|esp|ah)\s+'
            r'(\S+)\s+(\S+)?\s*'
            r'(?:destination\s+)?(\S+)?\s*(\S+)?'
            r'(?:\s+(eq|gt|lt|neq)\s+(\S+))?',
            line, re.IGNORECASE
        )
        
        if not match:
            # Упрощенный парсинг
            return self._parse_simple_acl_line(line, acl_name, line_num)
        
        action = match.group(1).lower()
        protocol = match.group(2).lower()
        
        # Источник
        src_spec = match.group(3)
        sources = self._parse_endpoint_spec(src_spec)
        
        # Назначение - упрощенно берем остаток строки
        dst_start = match.end(3) if match.end(3) else len(line)
        rest = line[dst_start:].strip()
        
        # Ищем ключевые слова для разделения
        destinations = []
        services = []
        
        if ' any ' in rest or rest.endswith(' any'):
            destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        elif ' host ' in rest:
            host_match = re.search(r'host\s+(\S+)', rest, re.IGNORECASE)
            if host_match:
                destinations = [Endpoint(host_match.group(1), 'host', {host_match.group(1)})]
        else:
            # Пробуем извлечь IP/сеть
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+\.\d+\.\d+\.\d+))?', rest)
            if ip_match:
                ip = ip_match.group(1)
                mask = ip_match.group(2)
                if mask:
                    cidr = self._wildcard_to_cidr(mask)
                    destinations = [Endpoint(f"{ip}/{cidr}", 'subnet', {f"{ip}/{cidr}"})]
                else:
                    destinations = [Endpoint(ip, 'host', {ip})]
        
        if not destinations:
            destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        
        # Сервисы - улучшенный парсинг портов
        services = self._parse_ports_from_acl(rest, protocol)
        
        return FirewallRule(
            name=f"{acl_name}_rule_{line_num}",
            rule_id=str(line_num),
            sources=sources if sources else [Endpoint('any', 'host', {'0.0.0.0/0'})],
            destinations=destinations,
            services=services,
            action='accept',
            enabled=True,
            description=f"Parsed from ACL {acl_name}",
            vendor=self.current_vendor
        )
    
    def _parse_ports_from_acl(self, line: str, protocol: str) -> List[Service]:
        """Парсит порты из ACL строки.
        
        Поддерживает:
        - eq port - равен порту
        - gt port - больше порта
        - lt port - меньше порта
        - range start end - диапазон
        - established - установленные соединения
        """
        services = []
        
        # established
        if re.search(r'\bestablished\b', line, re.IGNORECASE):
            return [Service(f"{protocol}_established", protocol, {'established'})]
        
        # eq port
        eq_match = re.search(r'\beq\s+(\d+|\w+)', line, re.IGNORECASE)
        if eq_match:
            port = eq_match.group(1)
            # Проверяем, является ли порт числом или именем (http, https, ssh)
            if port.isdigit():
                services = [Service(f"{protocol}_{port}", protocol, {port})]
            else:
                # Именованный порт - добавляем как есть
                services = [Service(f"{protocol}_{port}", protocol, {port})]
        
        # gt port (greater than)
        gt_match = re.search(r'\bgt\s+(\d+)', line, re.IGNORECASE)
        if gt_match:
            port = int(gt_match.group(1))
            services = [Service(f"{protocol}_gt{port}", protocol, {f"{port+1}-65535"})]
        
        # lt port (less than)
        lt_match = re.search(r'\blt\s+(\d+)', line, re.IGNORECASE)
        if lt_match:
            port = int(lt_match.group(1))
            services = [Service(f"{protocol}_lt{port}", protocol, {f"1-{port-1}"})]
        
        # range start end
        range_match = re.search(r'\brange\s+(\d+)\s+(\d+)', line, re.IGNORECASE)
        if range_match:
            start_port = range_match.group(1)
            end_port = range_match.group(2)
            services = [Service(f"{protocol}_{start_port}-{end_port}", protocol, {f"{start_port}-{end_port}"})]
        
        # neq port (not equal) - редко используется
        neq_match = re.search(r'\bneq\s+(\d+)', line, re.IGNORECASE)
        if neq_match:
            port = neq_match.group(1)
            services = [Service(f"{protocol}_neq{port}", protocol, {f"!{port}"})]
        
        if not services:
            # Если протокол ip или icmp - без портов
            if protocol in ['ip', 'icmp', 'gre', 'esp', 'ah']:
                services = [Service(protocol, protocol, set())]
            else:
                # Для tcp/udp без указания портов - any
                services = [Service(f"{protocol}_any", protocol, {'any'})]
        
        return services
    
    def _parse_simple_acl_line(self, line: str, acl_name: str, line_num: int) -> Optional[FirewallRule]:
        """Упрощенный парсинг ACL строки."""
        tokens = line.split()
        if len(tokens) < 2:
            return None
        
        action = tokens[0].lower()
        if action not in ['permit', 'allow']:
            return None
        
        protocol = tokens[1].lower() if len(tokens) > 1 else 'ip'
        
        # Источник и назначение - упрощенно
        sources = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        services = [Service(protocol, protocol, set())]
        
        return FirewallRule(
            name=f"{acl_name}_rule_{line_num}",
            rule_id=str(line_num),
            sources=sources,
            destinations=destinations,
            services=services,
            action='accept',
            enabled=True,
            description=f"Simple parsed from ACL {acl_name}",
            vendor=self.current_vendor
        )
    
    def _parse_numbered_acl_line(self, line: str, line_num: int) -> Optional[FirewallRule]:
        """Парсит нумерованную ACL строку."""
        match = re.match(
            r'access-list\s+(\d+)\s+(permit)\s+(\S+)\s+(.+)',
            line, re.IGNORECASE
        )
        if not match:
            return None
        
        acl_num = match.group(1)
        protocol = match.group(3).lower()
        rest = match.group(4)
        
        sources = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        services = [Service(protocol, protocol, set())]
        
        # Парсим источник
        if rest.startswith('host '):
            host_match = re.match(r'host\s+(\S+)', rest, re.IGNORECASE)
            if host_match:
                sources = [Endpoint(host_match.group(1), 'host', {host_match.group(1)})]
        elif rest.startswith('any'):
            pass  # already any
        else:
            # IP wildcard mask
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', rest)
            if ip_match:
                ip = ip_match.group(1)
                wildcard = ip_match.group(2)
                cidr = self._wildcard_to_cidr(wildcard)
                sources = [Endpoint(f"{ip}/{cidr}", 'subnet', {f"{ip}/{cidr}"})]
        
        return FirewallRule(
            name=f"acl_{acl_num}_rule_{line_num}",
            rule_id=f"{acl_num}.{line_num}",
            sources=sources,
            destinations=destinations,
            services=services,
            action='accept',
            enabled=True,
            description=f"Numbered ACL {acl_num}",
            vendor=self.current_vendor
        )
    
    def _parse_hp_authorized_manager(self, line: str, match, line_num: int) -> Optional[FirewallRule]:
        """Парсит HP ip authorized-managers.
        
        Формат: ip authorized-managers IP MASK [access LEVEL] [access-method METHOD]
        Пример: ip authorized-managers 192.168.232.204 255.255.255.255 access manager access-method ssh
        """
        ip = match.group(1)
        mask = match.group(2)
        access_level = match.group(3) if match.group(3) else 'operator'
        access_method = match.group(4) if match.group(4) else 'any'
        
        # Преобразуем в CIDR
        if '/' in mask:
            cidr = mask
        else:
            cidr = self._wildcard_to_cidr(mask)
        
        # Определяем источник
        if ip == 'any':
            sources = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        else:
            try:
                network = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
                sources = [Endpoint(str(network), 'subnet', {str(network)})]
            except:
                sources = [Endpoint(ip, 'host', {ip})]
        
        # Сервис по методу доступа
        services = []
        if access_method == 'ssh':
            services = [Service('ssh', 'tcp', {'22'})]
        elif access_method == 'snmp':
            services = [Service('snmp', 'udp', {'161'})]
        elif access_method == 'telnet':
            services = [Service('telnet', 'tcp', {'23'})]
        elif access_method == 'http' or access_method == 'https':
            services = [Service(access_method, 'tcp', {'80' if access_method == 'http' else '443'})]
        else:
            # any method - разрешаем управление любым протоколом
            services = [Service('mgmt', 'tcp', {'22', '23', '80', '443', '161'})]
        
        return FirewallRule(
            name=f"hp_auth_mgr_{line_num}",
            rule_id=f"hp_auth.{line_num}",
            sources=sources,
            destinations=[Endpoint('switch_mgmt', 'host', {'switch_mgmt'})],
            services=services,
            action='accept',
            enabled=True,
            description=f"HP authorized-manager {access_level} via {access_method} from {ip}/{cidr}",
            vendor='hp'
        )
    
    def _parse_aruba_acl_line(self, line: str, acl_name: str, line_num: int) -> Optional[FirewallRule]:
        """Парсит ArubaOS-CX access-list строку.
        
        Формат: NUMBER permit|deny PROTOCOL SOURCE DESTINATION
        Пример: 10 permit any 192.168.253.0/255.255.255.0 any
        """
        match = re.match(
            r'(\d+)\s+(permit|deny)\s+(\S+)\s+(\S+)\s+(\S+)',
            line, re.IGNORECASE
        )
        
        if not match:
            return None
        
        rule_num = match.group(1)
        action = 'accept' if match.group(2).lower() == 'permit' else 'deny'
        protocol = match.group(3).lower()
        src = match.group(4)
        dst = match.group(5)
        
        # Парсим источник
        if '/' in src:
            # Уже CIDR или с маской
            src_ip = src.split('/')[0]
            src_mask = src.split('/')[1] if '/' in src else '32'
            if src_mask.isdigit():
                sources = [Endpoint(f"{src_ip}/{src_mask}", 'subnet', {f"{src_ip}/{src_mask}"})]
            else:
                cidr = self._wildcard_to_cidr(src_mask)
                sources = [Endpoint(f"{src_ip}/{cidr}", 'subnet', {f"{src_ip}/{cidr}"})]
        elif src == 'any':
            sources = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        else:
            sources = [Endpoint(src, 'host', {src})]
        
        # Парсим назначение
        if '/' in dst:
            dst_ip = dst.split('/')[0]
            dst_mask = dst.split('/')[1] if '/' in dst else '32'
            if dst_mask.isdigit():
                destinations = [Endpoint(f"{dst_ip}/{dst_mask}", 'subnet', {f"{dst_ip}/{dst_mask}"})]
            else:
                cidr = self._wildcard_to_cidr(dst_mask)
                destinations = [Endpoint(f"{dst_ip}/{cidr}", 'subnet', {f"{dst_ip}/{cidr}"})]
        elif dst == 'any':
            destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        else:
            destinations = [Endpoint(dst, 'host', {dst})]
        
        # Сервис
        services = []
        if protocol == 'tcp':
            services = [Service('tcp', 'tcp', set())]
        elif protocol == 'udp':
            services = [Service('udp', 'udp', set())]
        elif protocol == 'icmp':
            services = [Service('icmp', 'icmp', set())]
        else:
            services = [Service(protocol, protocol, set())]
        
        return FirewallRule(
            name=f"{acl_name}_rule_{rule_num}",
            rule_id=f"{acl_name}.{rule_num}",
            sources=sources,
            destinations=destinations,
            services=services,
            action=action,
            enabled=True,
            description=f"Aruba {acl_name} ACL rule {rule_num}",
            vendor='aruba'
        )
    
    def _parse_juniper(self, content: str) -> List[FirewallRule]:
        """Парсит Juniper JunOS firewall filter."""
        rules = []
        
        # Ищем блоки term
        filter_blocks = re.findall(
            r'filter\s+(\w+)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
            content, re.DOTALL | re.IGNORECASE
        )
        
        for filter_name, filter_content in filter_blocks:
            # Ищем term внутри filter
            term_blocks = re.findall(
                r'term\s+(\w+)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
                filter_content, re.DOTALL | re.IGNORECASE
            )
            
            for term_name, term_content in term_blocks:
                # Проверяем action
                if re.search(r'then\s+(accept|permit)', term_content, re.IGNORECASE):
                    rule = self._parse_juniper_term(term_name, term_content, filter_name)
                    if rule:
                        rules.append(rule)
        
        return rules
    
    def _parse_juniper_term(self, term_name: str, term_content: str, filter_name: str) -> Optional[FirewallRule]:
        """Парсит отдельный term Juniper."""
        sources = []
        destinations = []
        services = []
        
        # From (источники и сервисы)
        from_match = re.search(
            r'from\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
            term_content, re.DOTALL | re.IGNORECASE
        )
        if from_match:
            from_block = from_match.group(1)
            
            # Источники
            src_match = re.findall(r'source-address\s+(\S+);', from_block)
            for src in src_match:
                sources.append(Endpoint(src, 'subnet', {src}))
            
            # Протокол
            proto_match = re.search(r'protocol\s+(\S+);', from_block, re.IGNORECASE)
            protocol = proto_match.group(1).lower() if proto_match else 'ip'
            
            # Порты
            port_match = re.findall(r'(source|destination)-port\s+"?([^";]+)"?;', from_block)
            ports = set()
            for _, port_spec in port_match:
                ports.add(port_spec.replace(' ', ''))
            
            if ports:
                services = [Service(f"{protocol}_{list(ports)[0]}", protocol, ports)]
            else:
                services = [Service(protocol, protocol, set())]
        
        # To (назначения)
        to_match = re.search(
            r'to\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
            term_content, re.DOTALL | re.IGNORECASE
        )
        if to_match:
            to_block = to_match.group(1)
            dst_match = re.findall(r'destination-address\s+(\S+);', to_block)
            for dst in dst_match:
                destinations.append(Endpoint(dst, 'subnet', {dst}))
        
        if not sources:
            sources = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        if not destinations:
            destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        if not services:
            services = [Service('ip', 'ip', set())]
        
        return FirewallRule(
            name=f"{filter_name}_{term_name}",
            rule_id=term_name,
            sources=sources,
            destinations=destinations,
            services=services,
            action='accept',
            enabled=True,
            description=f"Juniper term from filter {filter_name}",
            vendor='juniper'
        )
    
    # =========================================================================
    # Aruba Wireless Controller: ip access-list session parser
    # =========================================================================
    
    def _parse_aruba_session(self, content: str) -> List[FirewallRule]:
        """
        Парсит Aruba Wireless Controller running-config с ip access-list session.
        
        Синтаксис:
          ip access-list session <ACL_NAME>
            <SRC> <DST> <SVC> <ACTION> [queue high] [tos N] [dot1p-priority N] [src-nat] [dst-nat N]
        
        Где:
          <SRC>/<DST> = any | host <IP> | network <IP> <MASK> | alias <NAME> | user | ipv6 ...
          <SVC> = any | svc-<NAME> | tcp <PORT> | udp <PORT> | icmp echo | app <NAME>
          <ACTION> = permit | deny | src-nat | dst-nat N
        
        Также парсит netservice и netdestination для резолва имён.
        """
        # Phase 1: Parse netservice definitions
        netservices = self._parse_aruba_netservices(content)
        
        # Phase 2: Parse netdestination definitions (aliases)
        netdestinations = self._parse_aruba_netdestinations(content)
        
        # Phase 3: Parse access-list session rules
        rules = []
        lines = content.split('\n')
        
        current_acl = None
        rule_counter = 0
        
        for line_num, line in enumerate(lines, 1):
            original_line = line
            line_stripped = line.strip()
            
            # Skip comments and empty lines
            if not line_stripped or line_stripped.startswith('#') or line_stripped.startswith('!'):
                # ! ends an ACL block in Aruba
                if line_stripped == '!' and current_acl:
                    current_acl = None
                continue
            
            # Detect ACL start: ip access-list session <NAME>
            acl_match = re.match(r'ip\s+access-list\s+session\s+(\S+)', line_stripped, re.IGNORECASE)
            if acl_match:
                current_acl = acl_match.group(1)
                rule_counter = 0
                continue
            
            # If not inside an ACL, skip
            if not current_acl:
                continue
            
            # Skip empty ACLs
            if line_stripped == '!':
                current_acl = None
                continue
            
            # Skip lines without permit/deny/src-nat/dst-nat - these are not rules
            if not re.search(r'\b(permit|deny|src-nat|dst-nat)\b', line_stripped, re.IGNORECASE):
                continue
            
            # Parse the rule
            rule = self._parse_aruba_session_rule(
                line_stripped, current_acl, line_num, rule_counter,
                netservices, netdestinations
            )
            if rule:
                rules.append(rule)
                rule_counter += 1
        
        return rules
    
    def _parse_aruba_netservices(self, content: str) -> dict:
        """
        Парсит netservice определения.
        
        netservice svc-http tcp 80
        netservice svc-https tcp 443
        netservice svc-dns udp 53 alg dns
        netservice svc-icmp 1
        netservice svc-esp 50
        """
        services = {}
        
        for match in re.finditer(
            r'netservice\s+(\S+)\s+(tcp|udp|ip)\s+(\d+)(?:\s+alg\s+(\S+))?',
            content, re.IGNORECASE
        ):
            name = match.group(1)
            protocol = match.group(2).lower()
            port = match.group(3)
            services[name] = {'protocol': protocol, 'port': port}
        
        # Также обрабатываем netservice без порта (icmp, esp, gre - номер протокола)
        for match in re.finditer(
            r'netservice\s+(\S+)\s+(\d+)',
            content, re.IGNORECASE
        ):
            name = match.group(1)
            proto_num = match.group(2)
            if name not in services:
                proto_map = {'1': 'icmp', '50': 'esp', '47': 'gre', '58': 'icmpv6'}
                protocol = proto_map.get(proto_num, f'proto_{proto_num}')
                services[name] = {'protocol': protocol, 'port': None}
        
        # netservice с tcp/udp и списком портов
        for match in re.finditer(
            r'netservice\s+(\S+)\s+tcp\s+list\s+"(\S+)"',
            content, re.IGNORECASE
        ):
            name = match.group(1)
            services[name] = {'protocol': 'tcp', 'port': 'list'}
        
        return services
    
    def _parse_aruba_netdestinations(self, content: str) -> dict:
        """
        Парсит netdestination определения (alias'ы).
        
        netdestination guest-printers
            host 10.0.0.1
            host 10.0.0.2
        !
        netdestination cu-mm-computers
            network 10.1.0.0 255.255.255.0
        !
        """
        destinations = {}
        lines = content.split('\n')
        
        current_dest = None
        current_hosts = []
        
        for line in lines:
            line_stripped = line.strip()
            
            # Начало netdestination
            dest_match = re.match(r'netdestination\s+(\S+)', line_stripped, re.IGNORECASE)
            if dest_match:
                # Сохраняем предыдущий
                if current_dest and current_hosts:
                    destinations[current_dest] = current_hosts
                current_dest = dest_match.group(1)
                current_hosts = []
                continue
            
            # Конец блока
            if line_stripped == '!' and current_dest is not None:
                if current_hosts:
                    destinations[current_dest] = current_hosts
                current_dest = None
                current_hosts = []
                continue
            
            # Строки внутри блока
            if current_dest and line_stripped and not line_stripped.startswith('!'):
                # description "..."
                if line_stripped.startswith('description'):
                    continue
                # invert
                if line_stripped == 'invert':
                    continue
                # name hostname.domain
                if line_stripped.startswith('name '):
                    name_val = line_stripped.split(None, 1)[1] if len(line_stripped.split()) > 1 else ''
                    current_hosts.append({'type': 'name', 'value': name_val})
                    continue
                # host IP
                host_match = re.match(r'host\s+(\S+)', line_stripped, re.IGNORECASE)
                if host_match:
                    current_hosts.append({'type': 'host', 'value': host_match.group(1)})
                    continue
                # network IP MASK
                net_match = re.match(r'network\s+(\S+)\s+(\S+)', line_stripped, re.IGNORECASE)
                if net_match:
                    current_hosts.append({
                        'type': 'network',
                        'ip': net_match.group(1),
                        'mask': net_match.group(2)
                    })
                    continue
                # name (продолжение списка)
                name_match = re.match(r'name\s+(\S+)', line_stripped, re.IGNORECASE)
                if name_match:
                    current_hosts.append({'type': 'name', 'value': name_match.group(1)})
                    continue
        
        # Последний блок
        if current_dest and current_hosts:
            destinations[current_dest] = current_hosts
        
        return destinations
    
    def _parse_aruba_session_rule(
        self, line: str, acl_name: str, line_num: int, rule_idx: int,
        netservices: dict, netdestinations: dict
    ) -> Optional[FirewallRule]:
        """
        Парсит одну строку правила Aruba ip access-list session.
        
        Формат: <SRC> <DST> <SVC> <ACTION> [queue high] ...
        """
        tokens = line.split()
        if len(tokens) < 4:
            return None
        
        # Определяем позицию action (permit/deny/src-nat/dst-nat) - она может быть не последней
        action_idx = None
        action = None
        for i, t in enumerate(tokens):
            if t.lower() in ('permit', 'deny', 'src-nat', 'dst-nat'):
                action_idx = i
                action = t.lower()
                break
        
        if action_idx is None:
            return None
        
        # Нормализуем action
        if action in ('permit', 'src-nat', 'dst-nat'):
            action = 'accept'
        else:
            action = 'deny'
        
        # Токены до action: src dst svc (но может быть разный порядок!)
        # В Aruba формат строгий: <SRC> <DST> <SVC> <ACTION>
        pre_tokens = tokens[:action_idx]
        post_tokens = tokens[action_idx + 1:]
        
        if len(pre_tokens) < 1:
            return None
        
        # Парсим src, dst, svc из pre_tokens
        # Порядок: SRC DST SVC (может быть 3 токена для any any any)
        # Или: alias NAME alias NAME svc-NAME
        # Или: any host IP any / any network IP MASK any
        
        sources = []
        destinations = []
        services = []
        
        pos = 0
        n = len(pre_tokens)
        
        # Парсим source
        src_token = pre_tokens[pos] if pos < n else 'any'
        if src_token == 'any':
            sources = [Endpoint('any', 'host', {'0.0.0.0/0'})]
            pos += 1
        elif src_token == 'user':
            sources = [Endpoint('user', 'group', set())]
            pos += 1
        elif src_token == 'alias':
            pos += 1
            if pos < n:
                alias_name = pre_tokens[pos]
                sources = self._resolve_aruba_endpoint(alias_name, netdestinations)
                pos += 1
        elif src_token == 'host':
            pos += 1
            if pos < n:
                ip = pre_tokens[pos]
                sources = [Endpoint(ip, 'host', {ip})]
                pos += 1
        elif src_token == 'network':
            pos += 1
            if pos + 1 < n:
                ip = pre_tokens[pos]
                mask = pre_tokens[pos + 1]
                cidr = self._netmask_to_cidr(mask)
                network = f"{ip}/{cidr}"
                sources = [Endpoint(network, 'subnet', {network})]
                pos += 2
        elif src_token.startswith('ipv6'):
            # ipv6 any ... - пропускаем
            sources = [Endpoint('ipv6_any', 'host', set())]
            pos += 1
        else:
            # Возможно это IP-адрес или alias без ключевого слова
            sources = [Endpoint(src_token, 'host', {src_token})]
            pos += 1
        
        # Парсим destination
        if pos < n:
            dst_token = pre_tokens[pos]
            if dst_token.lower() in ('permit', 'deny', 'src-nat', 'dst-nat'):
                # action встретился раньше - значит dst не указан
                pass
            elif dst_token == 'any':
                destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
                pos += 1
            elif dst_token == 'user':
                destinations = [Endpoint('user', 'group', set())]
                pos += 1
            elif dst_token == 'alias':
                pos += 1
                if pos < n:
                    alias_name = pre_tokens[pos]
                    destinations = self._resolve_aruba_endpoint(alias_name, netdestinations)
                    pos += 1
            elif dst_token == 'host':
                pos += 1
                if pos < n:
                    ip = pre_tokens[pos]
                    destinations = [Endpoint(ip, 'host', {ip})]
                    pos += 1
            elif dst_token == 'network':
                pos += 1
                if pos + 1 < n:
                    ip = pre_tokens[pos]
                    mask = pre_tokens[pos + 1]
                    cidr = self._netmask_to_cidr(mask)
                    network = f"{ip}/{cidr}"
                    destinations = [Endpoint(network, 'subnet', {network})]
                    pos += 2
            elif dst_token.startswith('ipv6'):
                destinations = [Endpoint('ipv6_any', 'host', set())]
                pos += 1
            else:
                destinations = [Endpoint(dst_token, 'host', {dst_token})]
                pos += 1
        
        if not destinations:
            destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        
        # Парсим service
        if pos < n:
            svc_token = pre_tokens[pos]
            if svc_token == 'any':
                services = [Service('any', 'ip', {'any'})]
                pos += 1
            elif svc_token.startswith('svc-'):
                svc_info = netservices.get(svc_token, {})
                if svc_info:
                    ports = {svc_info['port']} if svc_info.get('port') else set()
                    services = [Service(svc_token, svc_info.get('protocol', 'ip'), ports)]
                else:
                    services = [Service(svc_token, 'ip', set())]
                pos += 1
            elif svc_token == 'sys-svc-dhcp':
                services = [Service('dhcp', 'udp', {'67', '68'})]
                pos += 1
            elif svc_token == 'sys-svc-esp':
                services = [Service('esp', 'esp', set())]
                pos += 1
            elif svc_token == 'sys-svc-natt':
                services = [Service('natt', 'udp', {'4500'})]
                pos += 1
            elif svc_token == 'sys-svc-ike':
                services = [Service('ike', 'udp', {'500'})]
                pos += 1
            elif svc_token == 'sys-svc-icmp':
                services = [Service('icmp', 'icmp', set())]
                pos += 1
            elif svc_token == 'sys-svc-icmp6':
                services = [Service('icmpv6', 'icmpv6', set())]
                pos += 1
            elif svc_token == 'sys-svc-v6-dhcp':
                services = [Service('dhcpv6', 'udp', {'546', '547'})]
                pos += 1
            elif svc_token == 'sys-svc-snmp':
                services = [Service('snmp', 'udp', {'161'})]
                pos += 1
            elif svc_token == 'sys-svc-snmp-trap':
                services = [Service('snmp-trap', 'udp', {'162'})]
                pos += 1
            elif svc_token == 'sys-svc-ntp':
                services = [Service('ntp', 'udp', {'123'})]
                pos += 1
            elif svc_token == 'sys-svc-ftp':
                services = [Service('ftp', 'tcp', {'21'})]
                pos += 1
            elif svc_token == 'sys-svc-telnet':
                services = [Service('telnet', 'tcp', {'23'})]
                pos += 1
            elif svc_token == 'sys-svc-ssh':
                services = [Service('ssh', 'tcp', {'22'})]
                pos += 1
            elif svc_token in ('tcp', 'udp'):
                protocol = svc_token
                pos += 1
                if pos < n:
                    port_token = pre_tokens[pos]
                    if port_token.isdigit():
                        services = [Service(f"{protocol}/{port_token}", protocol, {port_token})]
                        pos += 1
                    else:
                        services = [Service(protocol, protocol, set())]
                else:
                    services = [Service(protocol, protocol, set())]
            elif svc_token in ('icmp', 'icmpv6'):
                pos += 1
                if pos < n and pre_tokens[pos] in ('echo', 'rtr-adv'):
                    services = [Service(f"{svc_token}-{pre_tokens[pos]}", svc_token, set())]
                    pos += 1
                else:
                    services = [Service(svc_token, svc_token, set())]
            elif svc_token.isdigit():
                # Номер протокола (1=icmp, 50=esp и т.д.)
                proto_map = {'1': 'icmp', '50': 'esp', '47': 'gre', '58': 'icmpv6'}
                protocol = proto_map.get(svc_token, f'proto_{svc_token}')
                services = [Service(f'proto_{svc_token}', protocol, set())]
                pos += 1
            elif svc_token == 'app':
                # app alg-* - application-level ALG
                pos += 1
                if pos < n:
                    services = [Service(f"app/{pre_tokens[pos]}", 'app', set())]
                    pos += 1
            else:
                services = [Service(svc_token, 'ip', set())]
                pos += 1
        
        if not services:
            services = [Service('any', 'ip', {'any'})]
        
        # Пост-токены: queue, tos, dot1p-priority и т.д. - игнорируем
        
        return FirewallRule(
            name=f"{acl_name}_r{rule_idx}",
            rule_id=f"{acl_name}.{rule_idx}",
            sources=sources,
            destinations=destinations,
            services=services,
            action=action,
            enabled=True,
            description=f"Aruba session ACL {acl_name} rule #{rule_idx}",
            vendor='aruba'
        )
    
    def _resolve_aruba_endpoint(self, alias_name: str, netdestinations: dict) -> List[Endpoint]:
        """
        Разворачивает alias в список Endpoint'ов.
        
        Если alias найден в netdestinations - создаёт отдельные Endpoint для каждого host/network.
        Иначе возвращает один Endpoint с типом 'group'.
        """
        entries = netdestinations.get(alias_name, [])
        if not entries:
            return [Endpoint(alias_name, 'group', set())]
        
        endpoints = []
        for entry in entries:
            if entry['type'] == 'host':
                ip = entry['value']
                endpoints.append(Endpoint(ip, 'host', {ip}, description=f"alias:{alias_name}"))
            elif entry['type'] == 'network':
                ip = entry['ip']
                mask = entry['mask']
                cidr = self._netmask_to_cidr(mask)
                network = f"{ip}/{cidr}"
                endpoints.append(Endpoint(network, 'subnet', {network}, description=f"alias:{alias_name}"))
            elif entry['type'] == 'name':
                # DNS name - создаём symbolic endpoint
                endpoints.append(Endpoint(entry['value'], 'host', set(), description=f"alias:{alias_name}"))
        
        return endpoints if endpoints else [Endpoint(alias_name, 'group', set())]
    
    def _netmask_to_cidr(self, mask: str) -> int:
        """Конвертирует subnet mask (255.255.255.0) в CIDR (24)."""
        try:
            parts = mask.split('.')
            if len(parts) != 4:
                return 32
            mask_int = 0
            for part in parts:
                mask_int = (mask_int << 8) | int(part)
            if mask_int == 0:
                return 0
            # Считаем leading 1-bits
            bits = 0
            while mask_int & 0x80000000:
                bits += 1
                mask_int = (mask_int << 1) & 0xFFFFFFFF
            return bits
        except (ValueError, AttributeError):
            return 32

    def _parse_endpoint_spec(self, spec: str) -> List[Endpoint]:
        """Парсит спецификацию endpoint."""
        if not spec:
            return [Endpoint('any', 'host', {'0.0.0.0/0'})]
        
        spec = spec.strip().lower()
        
        if spec == 'any':
            return [Endpoint('any', 'host', {'0.0.0.0/0'})]
        
        if spec == 'host':
            return [Endpoint('any', 'host', {'0.0.0.0/0'})]
        
        # Проверяем IP адрес или сеть
        if re.match(r'\d+\.\d+\.\d+\.\d+', spec):
            return [Endpoint(spec, 'host', {spec})]
        
        return [Endpoint(spec, 'unknown', set())]
    
    def _wildcard_to_cidr(self, wildcard: str) -> int:
        """Конвертирует wildcard mask в CIDR."""
        try:
            parts = wildcard.split('.')
            if len(parts) != 4:
                return 32
            
            # Wildcard mask обратная subnet mask
            mask = 0
            for part in parts:
                mask = (mask << 8) | (255 - int(part))
            
            # Считаем биты
            bits = bin(mask).count('1')
            return bits
        except (ValueError, AttributeError):
            return 32
    
    def parse_topology(self, file_path: Path) -> Tuple[List[Interface], List[StaticRoute]]:
        """
        Парсит топологию (интерфейсы и маршруты) из файла конфигурации.
        
        Для чистых ACL-файлов возвращает пустые списки.
        Дополняется полными конфигурациями устройств.
        
        Returns:
            Tuple (list of Interface, list of StaticRoute)
        """
        interfaces = []
        routes = []
        
        try:
            content = self.read_file(file_path)
            vendor = self.detect_vendor(content)
            
            if vendor == 'cisco':
                interfaces, routes = self._parse_cisco_topology(content)
            elif vendor == 'huawei':
                interfaces, routes = self._parse_huawei_topology(content)
            elif vendor == 'juniper':
                interfaces, routes = self._parse_juniper_topology(content)
                
        except Exception as e:
            pass  # При ошибке парсинга - возвращаем пустые списки
        
        return interfaces, routes
    
    def _parse_cisco_topology(self, content: str) -> Tuple[List[Interface], List[StaticRoute]]:
        """Парсит интерфейсы и маршруты из Cisco IOS/ASA."""
        from ..models.interface import Interface
        from ..models.route import StaticRoute
        
        interfaces = []
        routes = []
        
        lines = content.split('\n')
        current_interface = None
        current_block = []
        
        for line in lines:
            line_stripped = line.strip()
            
            # Начало интерфейса
            if line_stripped.lower().startswith('interface '):
                # Сохраняем предыдущий интерфейс
                if current_interface:
                    iface = self._parse_cisco_interface(current_interface, current_block)
                    if iface:
                        interfaces.append(iface)
                
                current_interface = line_stripped.split()[1]
                current_block = [line_stripped]
            elif current_interface is not None:
                if line_stripped == '!' or line_stripped.lower().startswith('interface '):
                    # Конец блока интерфейса
                    if current_interface:
                        iface = self._parse_cisco_interface(current_interface, current_block)
                        if iface:
                            interfaces.append(iface)
                    current_interface = None
                    current_block = []
                    
                    # Новый интерфейс?
                    if line_stripped.lower().startswith('interface '):
                        current_interface = line_stripped.split()[1]
                        current_block = [line_stripped]
                else:
                    current_block.append(line_stripped)
        
        # Не забудем последний интерфейс
        if current_interface:
            iface = self._parse_cisco_interface(current_interface, current_block)
            if iface:
                interfaces.append(iface)
        
        # Парсим маршруты построчно
        for line in lines:
            line_lower = line.lower().strip()
            if line_lower.startswith('ip route '):
                parts = line.split()
                if len(parts) >= 4:
                    dest_ip = parts[2]
                    dest_mask = parts[3]
                    next_hop = parts[4] if len(parts) > 4 else None
                    admin_dist = parts[5] if len(parts) > 5 and parts[5].isdigit() else None
                    
                    if next_hop:
                        try:
                            from ipaddress import IPv4Network
                            network = IPv4Network(f'{dest_ip}/{dest_mask}', strict=False)
                            dest_cidr = str(network)
                        except:
                            dest_cidr = f'{dest_ip}/32'
                        
                        routes.append(StaticRoute(
                            destination=dest_cidr,
                            next_hop=next_hop,
                            admin_distance=int(admin_dist) if admin_dist else 1
                        ))
        
        return interfaces, routes
    
    def _parse_cisco_interface(self, name: str, lines: List[str]) -> Optional[Interface]:
        """Парсит данные интерфейса из блока строк Cisco."""
        from ..models.interface import Interface
        from ..models.vlan import VlanInterface, VlanMode
        
        description = None
        ip_address = None
        acl_in = None
        acl_out = None
        vlan_interface = None
        
        for line in lines:
            line_lower = line.lower()
            
            if line_lower.startswith('description '):
                description = line.split(None, 1)[1] if len(line.split()) > 1 else ''
            elif line_lower.startswith('ip address ') and 'dhcp' not in line_lower:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[2]
                    mask = parts[3]
                    try:
                        from ipaddress import IPv4Network
                        network = IPv4Network(f'0.0.0.0/{mask}', strict=False)
                        cidr = network.prefixlen
                        ip_address = f'{ip}/{cidr}'
                    except:
                        ip_address = f'{ip}/24'
            elif line_lower.startswith('ip access-group '):
                parts = line.split()
                if len(parts) >= 3:
                    if 'in' in line_lower:
                        acl_in = parts[2]
                    elif 'out' in line_lower:
                        acl_out = parts[2]
            elif line_lower.startswith('switchport mode '):
                # Access или Trunk
                mode = line_lower.split()[-1]
                if mode == 'access':
                    vlan_match = re.search(r'switchport\s+access\s+vlan\s+(\d+)', '\n'.join(lines), re.IGNORECASE)
                    if vlan_match:
                        vlan_id = int(vlan_match.group(1))
                        vlan_interface = VlanInterface(
                            interface_name=name,
                            vlan_id=vlan_id,
                            mode=VlanMode.ACCESS
                        )
                elif mode == 'trunk':
                    # Native VLAN
                    native_match = re.search(r'switchport\s+trunk\s+native\s+vlan\s+(\d+)', '\n'.join(lines), re.IGNORECASE)
                    native_vlan = int(native_match.group(1)) if native_match else 1
                    
                    # Allowed VLANs
                    allowed_match = re.search(r'switchport\s+trunk\s+allowed\s+vlan\s+([\d,-]+)', '\n'.join(lines), re.IGNORECASE)
                    allowed_vlans = set()
                    if allowed_match:
                        vlan_list = allowed_match.group(1)
                        for part in vlan_list.split(','):
                            if '-' in part:
                                start, end = part.split('-')
                                allowed_vlans.update(range(int(start), int(end) + 1))
                            else:
                                allowed_vlans.add(int(part))
                    else:
                        # По умолчанию все VLAN разрешены
                        allowed_vlans = set(range(1, 4095))  # all except reserved
                    
                    vlan_interface = VlanInterface(
                        interface_name=name,
                        vlan_id=native_vlan,
                        mode=VlanMode.TRUNK,
                        is_native=True,
                        allowed_vlans=allowed_vlans
                    )
        
        if ip_address or vlan_interface:  # Возвращаем если есть IP или VLAN
            iface = Interface(
                name=name,
                ip_address=ip_address,
                description=description,
                acl_in=acl_in,
                acl_out=acl_out
            )
            if vlan_interface:
                iface.vlan_interface = vlan_interface
            return iface
        return None
    
    def _parse_huawei_topology(self, content: str) -> Tuple[List[Interface], List[StaticRoute]]:
        """Парсит интерфейсы и маршруты из Huawei VRP."""
        from ..models.interface import Interface
        from ..models.route import StaticRoute
        
        interfaces = []
        routes = []
        lines = content.split('\n')
        
        current_interface = None
        current_block = []
        
        for line in lines:
            line_stripped = line.strip()
            
            # Начало интерфейса
            if line_stripped.lower().startswith('interface '):
                if current_interface:
                    iface = self._parse_huawei_interface(current_interface, current_block)
                    if iface:
                        interfaces.append(iface)
                
                current_interface = line_stripped.split()[1]
                current_block = [line_stripped]
            elif current_interface is not None:
                if line_stripped == '#' or line_stripped.lower().startswith('interface '):
                    if current_interface:
                        iface = self._parse_huawei_interface(current_interface, current_block)
                        if iface:
                            interfaces.append(iface)
                    current_interface = None
                    current_block = []
                    
                    if line_stripped.lower().startswith('interface '):
                        current_interface = line_stripped.split()[1]
                        current_block = [line_stripped]
                else:
                    current_block.append(line_stripped)
        
        # Последний интерфейс
        if current_interface:
            iface = self._parse_huawei_interface(current_interface, current_block)
            if iface:
                interfaces.append(iface)
        
        # Маршруты
        for line in lines:
            line_lower = line.lower().strip()
            if line_lower.startswith('ip route-static '):
                parts = line.split()
                if len(parts) >= 5:
                    dest_ip = parts[2]
                    dest_mask = parts[3]
                    next_hop = parts[4]
                    preference = parts[6] if len(parts) > 7 and parts[5].lower() == 'preference' else None
                    
                    try:
                        from ipaddress import IPv4Network
                        network = IPv4Network(f'{dest_ip}/{dest_mask}', strict=False)
                        dest_cidr = str(network)
                    except:
                        dest_cidr = f'{dest_ip}/32'
                    
                    routes.append(StaticRoute(
                        destination=dest_cidr,
                        next_hop=next_hop,
                        admin_distance=int(preference) if preference else 1
                    ))
        
        return interfaces, routes
    
    def _parse_huawei_interface(self, name: str, lines: List[str]) -> Optional[Interface]:
        """Парсит данные интерфейса Huawei из блока строк."""
        from ..models.interface import Interface
        
        description = None
        ip_address = None
        
        for line in lines:
            line_lower = line.lower()
            
            if line_lower.startswith('description '):
                description = line.split(None, 1)[1] if len(line.split()) > 1 else ''
            elif line_lower.startswith('ip address ') and 'dhcp' not in line_lower:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[2]
                    mask = parts[3]
                    try:
                        from ipaddress import IPv4Network
                        network = IPv4Network(f'0.0.0.0/{mask}', strict=False)
                        cidr = network.prefixlen
                        ip_address = f'{ip}/{cidr}'
                    except:
                        ip_address = f'{ip}/24'
        
        if ip_address:
            return Interface(name=name, ip_address=ip_address, description=description)
        return None
    
    def _parse_juniper_topology(self, content: str) -> Tuple[List[Interface], List[StaticRoute]]:
        """Парсит интерфейсы и маршруты из Juniper SRX/Junos."""
        from ..models.interface import Interface
        from ..models.route import StaticRoute
        
        interfaces = []
        routes = []
        
        # Интерфейсы в иерархическом формате
        iface_pattern = re.compile(
            r'interface\s+(\S+)\s*\{[^}]*?unit\s+\d+\s*\{[^}]*?family\s+inet\s*\{[^}]*?address\s+(\S+);',
            re.MULTILINE | re.IGNORECASE | re.DOTALL
        )
        
        for match in iface_pattern.finditer(content):
            name = match.group(1)
            address = match.group(2)
            
            interfaces.append(Interface(
                name=name,
                ip_address=address
            ))
        
        # Статические маршруты
        route_pattern = re.compile(
            r'static\s*\{[^}]*?route\s+(\S+)\s+next-hop\s+(\S+);',
            re.MULTILINE | re.IGNORECASE | re.DOTALL
        )
        
        for match in route_pattern.finditer(content):
            dest = match.group(1)
            next_hop = match.group(2)
            
            routes.append(StaticRoute(
                destination=dest,
                next_hop=next_hop
            ))
        
        return interfaces, routes
