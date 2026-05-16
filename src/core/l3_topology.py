"""
L3 Logical Topology Builder — граф IP-маршрутизации.

Строит направленный граф маршрутов:
- Узлы: IP-сети (subnet) + роутеры/L3-устройства
- Рёбра: маршруты (static/connected/dynamic/OSPF/BGP)

Источники данных:
- Статические маршруты: ip route / ip route-static
- Connected networks: интерфейсы с IP-адресами
- Динамические маршруты: OSPF/BGP (из дополнительных show-выводов)

Выход: nodes + edges для Vis.js, совместим с существующим визуализатором.
"""

import re
from typing import Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from pathlib import Path
from ipaddress import ip_interface, ip_network, IPv4Network
import networkx as nx


# ─── Data models ────────────────────────────────────────────────────────────

@dataclass
class L3Route:
    """
    Маршрут L3 уровня.

    Attributes:
        destination: Целевая сеть (CIDR, например "10.0.0.0/24")
        next_hop: IP next-hop (или имя интерфейса для connected)
        device: Устройство-источник этого маршрута
        route_type: 'static', 'connected', 'dynamic', 'ospf', 'bgp'
        admin_distance: Административная дистанция
        metric: Метрика маршрута
        outgoing_interface: Исходящий интерфейс (если известен)
        vrf: VRF имя (если есть)
        description: Описание маршрута
    """
    destination: str           # CIDR: "10.0.0.0/24"
    next_hop: str              # IP или "interface <name>" или "connected"
    device: str                # hostname устройства
    route_type: str = 'static' # static / connected / dynamic / ospf / bgp
    admin_distance: int = 1
    metric: int = 0
    outgoing_interface: Optional[str] = None
    vrf: Optional[str] = None
    description: str = ''


@dataclass
class L3DeviceInfo:
    """L3-сводка устройства."""
    hostname: str
    vendor: str
    management_ip: Optional[str] = None
    routes: List[L3Route] = field(default_factory=list)
    connected_networks: List[str] = field(default_factory=list)  # CIDR
    interfaces_ip: Dict[str, str] = field(default_factory=dict)   # iface_name -> CIDR


# ─── Parser ─────────────────────────────────────────────────────────────────

class L3RouteParser:
    """
    Парсер L3-маршрутов и connected-сетей из конфигураций.

    Поддерживаемые форматы:
    - Cisco IOS:  ip route <dest> <mask> <next-hop> [distance] [tag] [name NAME]
    - Huawei VRP: ip route-static <dest> <mask> <next-hop> [preference N] [description NAME]
    - Aruba CX:   ip route <dest/mask> <next-hop> [distance]
    - HP ProCurve: ip route <dest> <mask> <next-hop>
    - Connected:  interface с ip address (все вендоры)

    Работает как с реальными IP, так и с обфусцированными (ipNNN формат).
    """

    VENDOR_SIGNATURES = {
        'aruba_cx':  [r'ArubaOS-CX', r'vsf member', r'interface lag\s'],
        'hp_aruba':  [r'hostname\s+"', r'ProCurve', r'Aruba\s+\d'],
        'cisco_ios': [r'Cisco IOS', r'boot-start-marker', r'^!\s*$'],
        'huawei':    [r'sysname\s+\S+', r'Huawei\s+VRP', r'irf member'],
    }

    def detect_vendor(self, content: str) -> str:
        for vendor, patterns in self.VENDOR_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, content, re.IGNORECASE | re.MULTILINE):
                    return vendor
        return 'unknown'

    def parse_device(
        self,
        filepath: Path,
        vendor: Optional[str] = None,
        known_hostname: Optional[str] = None
    ) -> L3DeviceInfo:
        """Парсит файл конфигурации → L3DeviceInfo."""
        content = filepath.read_text(encoding='utf-8', errors='ignore')

        if not vendor:
            vendor = self.detect_vendor(content)

        hostname = known_hostname or self._extract_hostname(content, vendor, filepath)
        mgmt_ip = self._extract_mgmt_ip(content, vendor)

        interfaces = self._parse_interface_ip(content, vendor, hostname)
        routes = self._parse_routes(content, vendor, hostname)

        # Connected-сети — все интерфейсы с IP
        connected = list(interfaces.values())

        return L3DeviceInfo(
            hostname=hostname,
            vendor=vendor,
            management_ip=mgmt_ip,
            routes=routes,
            connected_networks=connected,
            interfaces_ip=interfaces,
        )

    def _extract_hostname(self, content: str, vendor: str, filepath: Path) -> str:
        patterns = {
            'aruba_cx':  r'hostname\s+(\S+)',
            'hp_aruba':  r'hostname\s+"(.+?)"',
            'cisco_ios': r'hostname\s+(\S+)',
            'huawei':    r'sysname\s+(\S+)',
        }
        pat = patterns.get(vendor, r'hostname\s+(\S+)')
        m = re.search(pat, content, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        return filepath.stem

    def _extract_mgmt_ip(self, content: str, vendor: str) -> Optional[str]:
        if vendor in ('aruba_cx', 'hp_aruba'):
            m = re.search(r'interface\s+mgmt\s*\n.+?ip\s+static\s+(\S+)', content, re.DOTALL | re.IGNORECASE)
            if m:
                return m.group(1)
        elif vendor == 'cisco_ios':
            m = re.search(r'interface\s+[Mm]gmt.*?\n.+?ip\s+address\s+(\S+\s+\S+)', content, re.DOTALL)
            if m:
                return m.group(1)
        return None

    # ── Interface IP parsing ────────────────────────────────────────────

    def _parse_interface_ip(
        self, content: str, vendor: str, device: str
    ) -> Dict[str, str]:
        """
        Извлекает все интерфейсы с IP-адресами → {iface_name: CIDR}.
        Для connected-сетей.
        """
        result: Dict[str, str] = {}

        if vendor == 'huawei':
            result = self._parse_huawei_interface_ip(content)
        elif vendor == 'aruba_cx':
            result = self._parse_aruba_cx_interface_ip(content)
        elif vendor == 'cisco_ios':
            result = self._parse_cisco_interface_ip(content)
        elif vendor == 'hp_aruba':
            result = self._parse_hp_interface_ip(content)
        else:
            result = self._parse_generic_interface_ip(content)

        return result

    def _parse_huawei_interface_ip(self, content: str) -> Dict[str, str]:
        """Huawei: interface → ip address ip mask (или обфусцированный ipNNN maskNNN)."""
        result: Dict[str, str] = {}

        # Ищем блоки interface ... ip address ...
        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^#\s*$).)*?)'
            r'ip\s+address\s+(\S+)\s+(\S+)',
            content,
            re.DOTALL | re.IGNORECASE | re.MULTILINE
        ):
            iface_name = m.group(1)
            ip = m.group(3)
            mask = m.group(4)

            # Пропускаем DHCP/BOOTP
            if 'dhcp' in ip.lower() or 'bootp' in ip.lower():
                continue
            # Пропускаем служебные интерфейсы
            if any(iface_name.lower().startswith(p) for p in
                   ('null', 'loopback', 'register', 'mgmt')):
                continue

            cidr = self._ip_mask_to_cidr(ip, mask)
            if cidr:
                result[iface_name] = cidr

        return result

    def _parse_aruba_cx_interface_ip(self, content: str) -> Dict[str, str]:
        """Aruba CX: interface → ip address CIDR."""
        result: Dict[str, str] = {}

        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!interface\s).)*?)'
            r'ip\s+address\s+(\S+)',
            content,
            re.DOTALL | re.IGNORECASE
        ):
            iface_name = m.group(1)
            cidr = m.group(3)

            if '/' not in cidr:
                continue
            # Пропускаем VLAN-интерфейсы без реального IP
            if any(iface_name.lower().startswith(p) for p in ('mgmt',)):
                continue

            result[iface_name] = cidr

        return result

    def _parse_cisco_interface_ip(self, content: str) -> Dict[str, str]:
        """Cisco IOS: interface → ip address ip mask."""
        result: Dict[str, str] = {}

        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^interface\s).)*?)'
            r'ip\s+address\s+(\S+)\s+(\S+)',
            content,
            re.DOTALL | re.IGNORECASE | re.MULTILINE
        ):
            iface_name = m.group(1)
            ip = m.group(3)
            mask = m.group(4)

            if any(iface_name.lower().startswith(p) for p in
                   ('vlan', 'loopback', 'tunnel', 'bdi',
                    'null', 'mgmt')):
                continue
            if 'dhcp' in ip.lower():
                continue

            cidr = self._ip_mask_to_cidr(ip, mask)
            if cidr:
                result[iface_name] = cidr

        return result

    def _parse_hp_interface_ip(self, content: str) -> Dict[str, str]:
        """HP ProCurve."""
        result: Dict[str, str] = {}
        for m in re.finditer(
            r'interface\s+(vlan\s*\d+)\s*\n((?:(?!^interface\s).)*?)'
            r'ip\s+address\s+(\S+)\s+(\S+)',
            content,
            re.DOTALL | re.IGNORECASE | re.MULTILINE
        ):
            iface_name = m.group(1).replace(' ', '')
            ip = m.group(3)
            mask = m.group(4)
            if 'dhcp' in ip.lower():
                continue
            cidr = self._ip_mask_to_cidr(ip, mask)
            if cidr:
                result[iface_name] = cidr
        return result

    def _parse_generic_interface_ip(self, content: str) -> Dict[str, str]:
        """Fallback для любых конфигов."""
        result: Dict[str, str] = {}
        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^interface\s).)*?)'
            r'ip\s+address\s+(\S+)\s+(\S+)',
            content,
            re.DOTALL | re.IGNORECASE | re.MULTILINE
        ):
            iface_name = m.group(1)
            ip = m.group(3)
            mask = m.group(4)
            if 'dhcp' in ip.lower() or 'bootp' in ip.lower():
                continue
            cidr = self._ip_mask_to_cidr(ip, mask)
            if cidr:
                result[iface_name] = cidr

        # Aruba CX CIDR format
        for m in re.finditer(
            r'interface\s+(\S+)\s*\n.*?ip\s+address\s+(\S+/\d+)',
            content,
            re.DOTALL | re.IGNORECASE
        ):
            iface_name = m.group(1)
            cidr = m.group(2)
            if iface_name not in result:
                result[iface_name] = cidr

        return result

    @staticmethod
    def _ip_mask_to_cidr(ip: str, mask: str) -> Optional[str]:
        """Конвертирует ip + mask → CIDR."""
        # Пытаемся парсить как нормальный IP
        try:
            # Если mask — subnet mask в dotted notation
            if '.' in mask:
                net = ip_network(f"{ip}/{mask}", strict=False)
            else:
                # Если mask — число префикса
                net = ip_network(f"{ip}/{mask}", strict=False)
            return str(net)
        except ValueError:
            pass

        # Обфусцированный формат (ipNNN): сохраняем как есть
        # Парсим префикс из mask если это число
        if mask.isdigit():
            return f"{ip}/{mask}"
        # Если mask в dotted — просто комбинируем
        return f"{ip}/{mask}"

    def _huawei_route_cidr(self, dest: str, mask: str, next_hop: str, rest: str) -> Optional[str]:
        """
        Определяет CIDR для Huawei-маршрута.

        Huawei формат может быть:
        1. ip route-static <dest> <mask> <next-hop>  — 4+ токенов
        2. ip route-static <dest> <next-hop>          — 3 токена (маска не указана)
        3. ip route-static <dest> <mask> <next-hop> preference N ...

        Эвристика: если mask похож на IP/next-hop (phone15..., ipNNN),
        то это случай #2 и mask на самом деле next-hop.
        """
        # Проверяем: mask — это на самом деле next-hop?
        # (phone15..., или другой не-маска паттерн)
        looks_like_nh = (
            'phone' in mask.lower()
            or mask.startswith('ip') and mask[2:].isdigit()
        )
        if looks_like_nh:
            # Случай #2: ip route-static <dest> <next-hop>
            # next_hop из группы #3 уже правильный, mask это на самом деле next-hop
            # Но dest уже корректный
            pass  # cidr строится из dest + /32 по умолчанию если нет маски

        return self._ip_mask_to_cidr(dest, mask)

    # ── Route parsing ───────────────────────────────────────────────────

    def _parse_routes(
        self, content: str, vendor: str, device: str
    ) -> List[L3Route]:
        """Извлекает все маршруты."""
        routes: List[L3Route] = []

        # Статические маршруты
        if vendor == 'huawei':
            routes.extend(self._parse_huawei_routes(content, device))
        elif vendor == 'aruba_cx':
            routes.extend(self._parse_aruba_cx_routes(content, device))
        elif vendor == 'cisco_ios':
            routes.extend(self._parse_cisco_routes(content, device))
        elif vendor == 'hp_aruba':
            routes.extend(self._parse_hp_routes(content, device))
        else:
            # Fallback: пробуем все форматы
            routes.extend(self._parse_huawei_routes(content, device))
            routes.extend(self._parse_cisco_routes(content, device))
            routes.extend(self._parse_aruba_cx_routes(content, device))

        return routes

    def _parse_huawei_routes(self, content: str, device: str) -> List[L3Route]:
        """
        Huawei: ip route-static <dest> <mask> <next-hop>
                [preference N] [description NAME] [tag TAG]
        Also handles: ip route-static <dest> <next-hop> (no mask)
        """
        routes: List[L3Route] = []

        # Основной формат с маской: ip route-static <dest> <mask> <next-hop>
        # Используем [ \t] вместо \s чтобы не матчить newline между mask и next-hop
        for m in re.finditer(
            r'ip\s+route-static\s+(\S+)\s+(\S+)[ \t]+(\S+)'
            r'(.*?)(?=\n\s*(?:ip\s+route-static|#|interface|\Z|^[^\s]))',
            content,
            re.DOTALL | re.IGNORECASE | re.MULTILINE
        ):
            dest = m.group(1)
            mask = m.group(2)
            next_hop = m.group(3)
            rest = m.group(4) or ''

            cidr = self._huawei_route_cidr(dest, mask, next_hop, rest)
            if not cidr:
                continue

            ad = 60  # Huawei default
            metric = 0
            desc = ''
            vrf = None
            out_iface = None

            # preference
            pref_m = re.search(r'preference\s+(\d+)', rest, re.IGNORECASE)
            if pref_m:
                ad = int(pref_m.group(1))

            # description
            desc_m = re.search(r'description\s+(\S.+)', rest, re.IGNORECASE)
            if desc_m:
                desc = desc_m.group(1).strip()
                # Убираем trailing комментарии
                desc = re.sub(r'\s*#.*', '', desc).strip()

            # tag
            tag_m = re.search(r'tag\s+(\d+)', rest, re.IGNORECASE)
            tag = int(tag_m.group(1)) if tag_m else None

            route = L3Route(
                destination=cidr,
                next_hop=next_hop,
                device=device,
                route_type='static',
                admin_distance=ad,
                metric=metric,
                outgoing_interface=out_iface,
                vrf=vrf,
                description=desc,
            )
            routes.append(route)

        # OSPF (если есть в конфиге)
        if 'ospf' in content.lower():
            for m in re.finditer(
                r'network\s+(\S+)\s+(\S+)',
                content,
                re.IGNORECASE
            ):
                net = m.group(1)
                mask = m.group(2)
                cidr = self._ip_mask_to_cidr(net, mask)
                if cidr:
                    routes.append(L3Route(
                        destination=cidr,
                        next_hop='OSPF',
                        device=device,
                        route_type='ospf',
                        admin_distance=110,
                    ))

        # BGP
        bgp_section = re.search(
            r'bgp\s+\d+.*?\n((?:(?!^#).)*?)(?=^\S|\Z)',
            content, re.DOTALL | re.IGNORECASE | re.MULTILINE
        )
        if bgp_section:
            for m in re.finditer(
                r'peer\s+(\S+)\s.*?connect-interface',
                bgp_section.group(1),
                re.IGNORECASE
            ):
                routes.append(L3Route(
                    destination=m.group(1),
                    next_hop='BGP',
                    device=device,
                    route_type='bgp',
                    admin_distance=20,
                ))

        # Вариант без маски (2 токена): ip route-static <dest> <next-hop>
        for m in re.finditer(
            r'ip\s+route-static\s+(\S+)[ \t]+(\S+)'
            r'(.*?)(?=\n\s*(?:ip\s+route-static|#|interface|\Z|^\S))',
            content,
            re.DOTALL | re.IGNORECASE | re.MULTILINE
        ):
            dest = m.group(1)
            arg2 = m.group(2)
            rest = m.group(3) or ''

            first_line = rest.split('\n')[0].strip() if rest else ''
            first_text = first_line.split()[0] if first_line else ''
            nh_keywords = ('preference', 'description', 'tag', 'permanent', 'track')
            is_2token = (
                not first_text
                or first_text.startswith('#')
                or first_text in nh_keywords
            )
            if not is_2token:
                continue

            cidr = f"{dest}/32"
            desc = ''
            desc_m = re.search(r'description\s+(\S.+)', rest, re.IGNORECASE)
            if desc_m:
                desc = desc_m.group(1).strip()
                desc = re.sub(r'\s*#.*', '', desc).strip()

            already = any(
                r.destination == cidr and r.next_hop == arg2
                for r in routes
            )
            if not already:
                routes.append(L3Route(
                    destination=cidr,
                    next_hop=arg2,
                    device=device,
                    route_type='static',
                    admin_distance=60,
                    description=desc,
                ))

        return routes

    def _parse_cisco_routes(self, content: str, device: str) -> List[L3Route]:
        """
        Cisco: ip route <dest> <mask> <next-hop> [distance] [tag TAG] [name NAME]
        """
        routes: List[L3Route] = []

        for m in re.finditer(
            r'ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)'
            r'(.*?)(?=\n\s*(?:ip\s+route|^!|interface|\Z))',
            content,
            re.DOTALL | re.IGNORECASE
        ):
            dest = m.group(1)
            mask = m.group(2)
            next_hop = m.group(3)
            rest = m.group(4) or ''

            # Пропускаем VRF-маршруты
            if dest.lower() == 'vrf':
                continue

            cidr = self._ip_mask_to_cidr(dest, mask)
            if not cidr:
                cidr = f"{dest}/{mask}"

            ad = 1  # Cisco static default
            metric = 0
            desc = ''
            out_iface = None

            # Извлекаем опциональные параметры
            tokens = rest.strip().split()
            i = 0
            while i < len(tokens):
                tok = tokens[i].lower()
                if tok == 'name' and i + 1 < len(tokens):
                    desc = tokens[i + 1]
                    i += 2
                elif tok == 'tag' and i + 1 < len(tokens):
                    i += 2
                elif tok == 'track' and i + 1 < len(tokens):
                    i += 2
                elif tok == 'global':
                    i += 1
                elif tok.isdigit():
                    ad = int(tok)
                    i += 1
                elif tokens[i] in ('GigabitEthernet', 'FastEthernet',
                                   'Serial', 'Vlan', 'Tunnel'):
                    out_iface = tokens[i]
                    if i + 1 < len(tokens) and '/' in tokens[i + 1]:
                        out_iface += tokens[i + 1]
                        i += 1
                    i += 1
                else:
                    i += 1

            route = L3Route(
                destination=cidr,
                next_hop=next_hop,
                device=device,
                route_type='static',
                admin_distance=ad,
                metric=metric,
                outgoing_interface=out_iface,
                description=desc,
            )
            routes.append(route)

        return routes

    def _parse_aruba_cx_routes(self, content: str, device: str) -> List[L3Route]:
        """Aruba CX: ip route <dest/mask> <next-hop> [distance]"""
        routes: List[L3Route] = []

        for m in re.finditer(
            r'ip\s+route\s+(\S+/\d+)\s+(\S+)'
            r'(.*?)(?=\n\s*(?:ip\s+route|interface|\Z))',
            content,
            re.DOTALL | re.IGNORECASE
        ):
            cidr = m.group(1)
            next_hop = m.group(2)
            rest = m.group(4) if m.lastindex >= 4 else ''

            ad = 1
            tokens = rest.strip().split()
            for tok in tokens:
                if tok.isdigit():
                    ad = int(tok)
                    break

            routes.append(L3Route(
                destination=cidr,
                next_hop=next_hop,
                device=device,
                route_type='static',
                admin_distance=ad,
            ))

        return routes

    def _parse_hp_routes(self, content: str, device: str) -> List[L3Route]:
        """HP ProCurve: ip route <dest> <mask> <next-hop>"""
        routes: List[L3Route] = []

        for m in re.finditer(
            r'ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)'
            r'(.*?)(?=\n\s*(?:ip\s+route|interface|\Z))',
            content,
            re.DOTALL | re.IGNORECASE
        ):
            dest = m.group(1)
            mask = m.group(2)
            next_hop = m.group(3)

            cidr = self._ip_mask_to_cidr(dest, mask)
            if not cidr:
                cidr = f"{dest}/{mask}"

            routes.append(L3Route(
                destination=cidr,
                next_hop=next_hop,
                device=device,
                route_type='static',
                admin_distance=1,
            ))

        return routes


# ─── Builder ────────────────────────────────────────────────────────────────

class L3TopologyBuilder:
    """
    Строитель L3 логической топологии (граф маршрутизации).

    Алгоритм:
    1. Парсинг конфигов → L3DeviceInfo для каждого устройства
    2. Извлечение connected-сетей из интерфейсов
    3. Разбор статических и динамических маршрутов
    4. Связывание next-hop с реальными устройствами
    5. Построение направленного графа NetworkX
    6. Экспорт в формат Vis.js

    Граф:
    - Устройство → connected-сеть: connected (зелёный)
    - Устройство → маршрут → next-hop сеть: static/dynamic (синий/оранжевый)
    - Сети отображаются как прямоугольники, устройства — как круги
    """

    def __init__(self):
        self.devices: Dict[str, L3DeviceInfo] = {}
        self.routes: List[L3Route] = []
        self.parser = L3RouteParser()
        # Кэш IP→устройство для резолвинга next-hop
        self._ip_to_device: Dict[str, str] = {}

    def load_device(
        self,
        filepath: Path,
        vendor: Optional[str] = None,
        known_hostname: Optional[str] = None
    ) -> L3DeviceInfo:
        """Парсит один файл конфигурации."""
        info = self.parser.parse_device(
            filepath, vendor=vendor, known_hostname=known_hostname
        )
        self.devices[info.hostname] = info

        # Регистрируем все IP интерфейсов для резолвинга next-hop
        for iface_name, cidr in info.interfaces_ip.items():
            ip = cidr.split('/')[0] if '/' in cidr else cidr
            self._ip_to_device[ip] = info.hostname

        return info

    def load_devices_from_dir(self, dirpath, vendor: Optional[str] = None) -> List[L3DeviceInfo]:
        """Парсит все .txt файлы в директории."""
        dirpath = Path(dirpath)
        results = []
        for f in sorted(dirpath.glob('*.txt')):
            try:
                info = self.load_device(f, vendor=vendor, known_hostname=f.stem)
                results.append(info)
            except Exception as e:
                print(f"⚠️  Ошибка парсинга {f.name}: {e}")
        return results

    def collect_all_routes(self) -> List[L3Route]:
        """Собирает все маршруты со всех устройств, включая connected."""
        all_routes: List[L3Route] = []

        for device_info in self.devices.values():
            # Connected сети
            for iface_name, cidr in device_info.interfaces_ip.items():
                route = L3Route(
                    destination=cidr,
                    next_hop='connected',
                    device=device_info.hostname,
                    route_type='connected',
                    admin_distance=0,
                    outgoing_interface=iface_name,
                )
                all_routes.append(route)

            # Статические и динамические маршруты
            all_routes.extend(device_info.routes)

        self.routes = all_routes
        return all_routes

    def resolve_next_hop_device(self, next_hop: str) -> Optional[str]:
        """
        Пытается определить, какому устройству принадлежит next-hop.

        Стратегии:
        1. Точное совпадение IP в _ip_to_device
        2. Совпадение hostname
        3. Частичное совпадение
        """
        if not next_hop or next_hop == 'connected':
            return None

        # Точное IP-совпадение
        if next_hop in self._ip_to_device:
            return self._ip_to_device[next_hop]

        # Точное hostname-совпадение
        if next_hop in self.devices:
            return next_hop

        # Обфусцированные IP (ipNNN) — ищем в списке известных IP
        if next_hop.startswith('ip') and next_hop[2:].isdigit():
            # Пробуем найти в кэше
            pass

        # Частичное hostname-совпадение
        for hostname in self.devices:
            if next_hop.lower() in hostname.lower() or hostname.lower() in next_hop.lower():
                return hostname

        return None

    # ── Graph building ──────────────────────────────────────────────────

    def build_networkx_graph(self) -> nx.DiGraph:
        """
        Строит направленный граф NetworkX.

        Узлы:
        - device:<hostname> — L3 устройства
        - subnet:<CIDR> — IP-сети

        Рёбра:
        - device → subnet: connected (тип маршрута)
        - device → subnet: static/dynamic/ospf/bgp (через next-hop)
        """
        G = nx.DiGraph()
        self.collect_all_routes()

        # Узлы устройств
        for hostname, info in self.devices.items():
            G.add_node(
                f"device:{hostname}",
                node_type='device',
                label=hostname,
                mgmt_ip=info.management_ip,
                vendor=info.vendor,
                title=f"Device: {hostname}\nIP: {info.management_ip or 'N/A'}\n"
                      f"Routes: {len(info.routes)} static\n"
                      f"Connected: {len(info.connected_networks)} networks",
            )

        # Сети + рёбра
        subnet_ids: Set[str] = set()

        for route in self.routes:
            dest = route.destination
            subnet_id = f"subnet:{dest}"

            if subnet_id not in subnet_ids:
                G.add_node(
                    subnet_id,
                    node_type='subnet',
                    label=str(dest),
                    title=f"Network: {dest}\nType: {route.route_type}",
                )
                subnet_ids.add(subnet_id)

            device_id = f"device:{route.device}"
            edge_attrs = {
                'route_type': route.route_type,
                'next_hop': route.next_hop,
                'admin_distance': route.admin_distance,
                'metric': route.metric,
                'description': route.description,
                'outgoing_interface': route.outgoing_interface or '',
                'title': f"Route: {route.device} → {dest}\n"
                         f"Next-hop: {route.next_hop}\n"
                         f"Type: {route.route_type}\n"
                         f"AD: {route.admin_distance} Metric: {route.metric}"
                         + (f"\nDesc: {route.description}" if route.description else ""),
            }

            G.add_edge(device_id, subnet_id, **edge_attrs)

        return G

    def to_visjs(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Экспорт в Vis.js формат: (nodes, edges).

        Визуальные настройки по ТЗ:
        - Сети: прямоугольники (box)
        - Устройства: круги (dot)
        - Static: синий (#0066CC)
        - Connected: зелёный (#00AA00)
        - Dynamic/OSPF/BGP: оранжевый (#FF8C00)
        """
        nodes: List[Dict] = []
        edges: List[Dict] = []

        # Цвета маршрутов по типу
        ROUTE_COLORS = {
            'connected': {'color': '#00AA00', 'width': 2, 'dashes': False},
            'static':    {'color': '#0066CC', 'width': 2, 'dashes': False},
            'ospf':      {'color': '#FF8C00', 'width': 2, 'dashes': [5, 3]},
            'bgp':       {'color': '#FF4500', 'width': 2, 'dashes': [5, 3]},
            'dynamic':   {'color': '#FF8C00', 'width': 2, 'dashes': [5, 3]},
        }

        # Узлы устройств
        for hostname, info in self.devices.items():
            nodes.append({
                'id': f"device:{hostname}",
                'label': hostname,
                'group': 'device',
                'type': 'device',
                'shape': 'dot',
                'size': 35,
                'color': {'background': '#5B9BD5', 'border': '#2E75B6'},
                'title': f"Device: {hostname}\n"
                         f"IP: {info.management_ip or 'N/A'}\n"
                         f"Routes: {len(info.routes)} static\n"
                         f"Connected: {len(info.connected_networks)} networks\n"
                         f"Interfaces with IP: {len(info.interfaces_ip)}",
                'font': {'size': 12, 'color': '#333'},
            })

        # Узлы сетей
        subnet_ids: Set[str] = set()
        for route in self.routes:
            dest = route.destination
            subnet_id = f"subnet:{dest}"
            if subnet_id not in subnet_ids:
                subnet_ids.add(subnet_id)

                # Определяем размер на основе числа маршрутов к этой сети
                route_count = sum(
                    1 for r in self.routes if r.destination == dest
                )

                nodes.append({
                    'id': subnet_id,
                    'label': str(dest),
                    'group': 'subnet',
                    'type': 'subnet',
                    'shape': 'box',
                    'size': min(15 + route_count * 3, 40),
                    'color': {
                        'background': '#FFFACD',
                        'border': '#BDB76B',
                    },
                    'title': f"Network: {dest}\n"
                             f"Routes to this network: {route_count}\n"
                             f"Type: {route.route_type}",
                    'font': {'size': 11, 'color': '#555'},
                })

        # Рёбра
        dedup_edges: Set[Tuple[str, str, str]] = set()
        for route in self.routes:
            device_id = f"device:{route.device}"
            subnet_id = f"subnet:{route.destination}"

            # Дедупликация по (from, to, route_type)
            edge_key = (device_id, subnet_id, route.route_type)
            if edge_key in dedup_edges:
                continue
            dedup_edges.add(edge_key)

            style = ROUTE_COLORS.get(route.route_type, ROUTE_COLORS['static'])

            edge_label = route.route_type.capitalize()
            if route.description:
                edge_label = route.description
            elif route.next_hop and route.next_hop != 'connected':
                if len(route.next_hop) > 15:
                    edge_label = f"via {route.next_hop[:15]}..."
                else:
                    edge_label = f"via {route.next_hop}"

            edges.append({
                'from': device_id,
                'to': subnet_id,
                'label': edge_label,
                'arrows': 'to',
                'color': {'color': style['color']},
                'width': style['width'],
                'dashes': style['dashes'],
                'title': f"Route: {route.device} → {route.destination}\n"
                         f"Next-hop: {route.next_hop}\n"
                         f"Type: {route.route_type}\n"
                         f"AD: {route.admin_distance} Metric: {route.metric}"
                         + (f"\nDesc: {route.description}" if route.description else "")
                         + (f"\nOut: {route.outgoing_interface}" if route.outgoing_interface else ""),
            })

        # Рёбра между устройствами (через next-hop резолвинг)
        # Если next-hop route'a резолвится на известное устройство, добавляем связь
        for route in self.routes:
            if route.next_hop == 'connected' or not route.next_hop:
                continue

            target_device = self.resolve_next_hop_device(route.next_hop)
            if target_device and target_device != route.device:
                device_id = f"device:{route.device}"
                target_id = f"device:{target_device}"
                edge_key = (device_id, target_id, 'next-hop')
                if edge_key not in dedup_edges:
                    dedup_edges.add(edge_key)
                    edges.append({
                        'from': device_id,
                        'to': target_id,
                        'label': f"NH: {route.next_hop}",
                        'arrows': 'to',
                        'color': {'color': '#999999'},
                        'width': 1,
                        'dashes': True,
                        'title': f"Next-hop relation\n"
                                 f"{route.device} → {target_device}\n"
                                 f"via {route.next_hop}",
                    })

        return nodes, edges

    def summary(self) -> Dict:
        """Возвращает сводную статистику."""
        route_types = {}
        for route in self.routes:
            route_types[route.route_type] = route_types.get(route.route_type, 0) + 1

        unique_subnets = set(r.destination for r in self.routes)

        return {
            'devices': len(self.devices),
            'total_routes': len(self.routes),
            'unique_subnets': len(unique_subnets),
            'route_types': route_types,
            'interfaces_with_ip': sum(
                len(d.interfaces_ip) for d in self.devices.values()
            ),
        }


# ─── CLI integration ───────────────────────────────────────────────────────

def build_l3_topology(
    config_dir,
    vendor: Optional[str] = None,
):
    """
    Точка входа: парсит конфиги, строит L3-топологию.

    Возвращает (nodes, edges) для Vis.js.

    Использование:
        from src.core.l3_topology import build_l3_topology
        nodes, edges = build_l3_topology('configs/')
    """
    builder = L3TopologyBuilder()
    path = Path(config_dir)
    builder.load_devices_from_dir(path, vendor=vendor)
    builder.collect_all_routes()

    stats = builder.summary()
    print(f"[L3 Topology] {stats['devices']} devices, {stats['total_routes']} routes")
    print(f"  Unique subnets: {stats['unique_subnets']}")
    for rtype, count in stats['route_types'].items():
        print(f"  - {rtype}: {count}")
    print(f"  Interfaces with IP: {stats['interfaces_with_ip']}")

    return builder.to_visjs()


# ── Export ──────────────────────────────────────────────────────────────────

__all__ = [
    'L3Route',
    'L3DeviceInfo',
    'L3RouteParser',
    'L3TopologyBuilder',
    'build_l3_topology',
]
