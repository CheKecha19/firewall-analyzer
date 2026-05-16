"""
Physical Topology Builder — граф физических соединений между устройствами.

Извлекает физические линки из конфигураций сетевых устройств:
- Interface parsing (HP/Aruba CX, Cisco IOS, Huawei, Juniper)
- LLDP/CDP neighbor discovery — прямое определение «кто куда подключён»
- Shared-subnet heuristics — устройства в одной сети → вероятный физический линк
- LAG/Port-channel учёт (агрегированные линки)
- Link status, speed, cable type

Выход: nodes + edges для Vis.js визуализации.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from ipaddress import ip_interface, ip_network
import networkx as nx


# ─── Data models ────────────────────────────────────────────────────────────

@dataclass
class PhysicalInterface:
    """
    Физический интерфейс (порт) устройства.
    Собирается из блока interface в конфиге.
    """
    name: str                          # GigabitEthernet0/1, 1/1/1, etc.
    device: str                        # hostname устройства
    status: str = 'unknown'            # up / down / admin-down
    speed: str = 'unknown'             # 1G, 10G, 100G, auto
    mac_address: Optional[str] = None
    description: str = ''
    is_lag: bool = False               # агрегированный (LAG/Port-channel)
    lag_id: Optional[str] = None       # идентификатор LAG-группы
    lag_members: List[str] = field(default_factory=list)  # порты-члены
    media_type: str = ''               # copper / fiber / sfp
    mtu: int = 0
    errors_enabled: bool = False       # есть ли ошибки (CRC, drops)


@dataclass
class LLDPNeighbor:
    """LLDP/CDP сосед."""
    local_device: str
    local_port: str
    remote_device: str
    remote_port: str
    remote_mgmt_ip: Optional[str] = None
    remote_description: str = ''
    protocol: str = 'LLDP'  # LLDP или CDP


@dataclass
class PhysicalLink:
    """
    Физический линк между двумя портами устройств.
    Может быть прямым (LLDP) или inferred (shared subnet).
    """
    device_a: str
    port_a: str
    device_b: str
    port_b: str
    status: str = 'up'                 # up / down
    speed: str = 'unknown'
    media_type: str = ''
    is_lag: bool = False
    discovery_method: str = 'LLDP'     # 'LLDP', 'CDP', 'subnet-heuristic'
    errors: bool = False


@dataclass
class DevicePhysicalInfo:
    """Сводка физической информации об устройстве."""
    hostname: str
    vendor: str
    management_ip: Optional[str]
    interfaces: Dict[str, PhysicalInterface] = field(default_factory=dict)
    lldp_neighbors: List[LLDPNeighbor] = field(default_factory=list)


# ─── Parser ─────────────────────────────────────────────────────────────────

class PhysicalInterfaceParser:
    """
    Парсер физических интерфейсов из конфигураций различных вендоров.
    Решает задачу извлечения port-level данных, необходимых для построения
    физической топологии.
    """

    # Вендор-специфичные сигнатуры для автоопределения
    VENDOR_SIGNATURES = {
        'aruba_cx':  [r'ArubaOS-CX', r'vsf member', r'interface lag\s'],
        'hp_aruba':  [r'hostname\s+"', r'ProCurve', r'Aruba\s+\d'],
        'cisco_ios': [r'Cisco IOS', r'boot-start-marker', r'^!\s*$'],
        'huawei':    [r'sysname\s', r'Huawei\s+VRP', r'^\s*#\s*$'],
    }

    def detect_vendor(self, content: str) -> str:
        """Автоопределение вендора по сигнатурам в тексте конфигурации."""
        for vendor, patterns in self.VENDOR_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    return vendor
        return 'unknown'

    def parse_device(
        self,
        filepath: Path,
        vendor: Optional[str] = None,
        known_hostname: Optional[str] = None
    ) -> DevicePhysicalInfo:
        """
        Парсит файл конфигурации → DevicePhysicalInfo.
        """
        content = filepath.read_text(encoding='utf-8', errors='ignore')

        if not vendor:
            vendor = self.detect_vendor(content)

        hostname = known_hostname or self._extract_hostname(content, vendor)
        mgmt_ip = self._extract_mgmt_ip(content, vendor)

        interfaces = self._parse_interfaces(content, vendor, hostname)
        lldp = self._parse_lldp_cdp(content, vendor, hostname)

        return DevicePhysicalInfo(
            hostname=hostname,
            vendor=vendor,
            management_ip=mgmt_ip,
            interfaces=interfaces,
            lldp_neighbors=lldp,
        )

    def _extract_hostname(self, content: str, vendor: str) -> str:
        patterns = {
            'aruba_cx':  r'hostname\s+(\S+)',
            'hp_aruba':  r'hostname\s+"(.+?)"',
            'cisco_ios': r'hostname\s+(\S+)',
            'huawei':    r'sysname\s+(\S+)',
        }
        pat = patterns.get(vendor, r'hostname\s+(\S+)')
        m = re.search(pat, content, re.IGNORECASE)
        return m.group(1).strip() if m else filepath.stem if hasattr(filepath, 'stem') else 'unknown'

    def _extract_mgmt_ip(self, content: str, vendor: str) -> Optional[str]:
        # Ищем static IP на management interface
        if vendor in ('aruba_cx', 'hp_aruba'):
            m = re.search(r'interface\s+mgmt\s*\n.+?ip\s+static\s+(\d+\.\d+\.\d+\.\d+)', content, re.DOTALL | re.IGNORECASE)
            if m:
                return m.group(1)
        elif vendor == 'cisco_ios':
            m = re.search(r'interface\s+[Mm]gmt.*?\n.+?ip\s+address\s+(\d+\.\d+\.\d+\.\d+)', content, re.DOTALL)
            if m:
                return m.group(1)
        return None

    # ── interface blocks ────────────────────────────────────────────────

    def _parse_interfaces(self, content: str, vendor: str, device: str) -> Dict[str, PhysicalInterface]:
        """Извлекает все физические интерфейсы."""
        result: Dict[str, PhysicalInterface] = {}

        if vendor == 'aruba_cx':
            result = self._parse_aruba_cx_interfaces(content, device)
        elif vendor == 'cisco_ios':
            result = self._parse_cisco_interfaces(content, device)
        elif vendor == 'huawei':
            result = self._parse_huawei_interfaces(content, device)
        elif vendor == 'hp_aruba':
            result = self._parse_hp_aruba_interfaces(content, device)
        else:
            result = self._parse_generic_interfaces(content, device)

        return result

    def _parse_aruba_cx_interfaces(self, content: str, device: str) -> Dict[str, PhysicalInterface]:
        """Aruba CX — interface 1/1/1, interface lag N."""
        interfaces: Dict[str, PhysicalInterface] = {}

        # Физические интерфейсы: interface 1/1/1
        for m in re.finditer(
            r'interface\s+((?:\d+/\d+/\d+(?::\d+)?))\s*\n((?:(?!interface\s).*\n)*)',
            content
        ):
            name = m.group(1)
            block = m.group(2)
            iface = self._aruba_cx_iface_block(name, block, device)
            # Пропускаем VSF и mgmt
            if iface is not None:
                interfaces[name] = iface

        # LAG интерфейсы: interface lag N
        for m in re.finditer(
            r'interface\s+lag\s+(\d+)\s*\n((?:(?!interface\s).*\n)*)',
            content
        ):
            lag_id = m.group(1)
            block = m.group(2)
            lag_name = f"Lag{lag_id}"
            iface = PhysicalInterface(
                name=lag_name,
                device=device,
                status='up',  # По умолчанию LAG — up
                is_lag=True,
                lag_id=lag_name,
            )
            # VRF / IP
            ip_m = re.search(r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)', block)
            if ip_m:
                iface.description = ip_m.group(1)

            # LACP members ищем глобально: interface 1/1/5 \n lacp mode active
            # Связываем lag и физические порты через команду 'lacp mode active'
            # Ищем члены позже в resolve_lag_memberships
            interfaces[lag_name] = iface

        # VSF links (виртуальные, но физически активные порты)
        for m in re.finditer(r'vsf\s+member\s+\d+\s*\n(.*?)(?=vsf\s+member|\Z)', content, re.DOTALL):
            vsf_block = m.group(1)
            for link_m in re.finditer(r'link\s+\d+\s+(\d+/\d+/\d+)', vsf_block):
                port = link_m.group(1)
                if port in interfaces:
                    interfaces[port].description = (interfaces[port].description + ' [VSF]').strip()

        return interfaces

    def _aruba_cx_iface_block(self, name: str, block: str, device: str) -> Optional[PhysicalInterface]:
        """Парсинг одного блока interface Aruba CX."""
        # Пропускаем VLAN-интерфейсы и mgmt
        if name.startswith('vlan') or name == 'mgmt':
            return None

        iface = PhysicalInterface(name=name, device=device)

        # Status
        if 'no shutdown' in block.lower():
            iface.status = 'up'
        elif 'shutdown' in block.lower():
            iface.status = 'admin-down'

        # Description
        desc_m = re.search(r'description\s+(.+)', block, re.IGNORECASE)
        if desc_m:
            iface.description = desc_m.group(1).strip()

        # Speed (чаще всего не указан явно в Aruba CX)
        # Media type — можно вывести из имени (1/1/1 = copper, SFP/SFP+ = fiber) — эвристика

        # LAG membership (порты с lacp mode active)
        if 'lacp mode active' in block.lower():
            iface.description = (iface.description + ' LACP').strip()

        # MTU
        mtu_m = re.search(r'mtu\s+(\d+)', block)
        if mtu_m:
            iface.mtu = int(mtu_m.group(1))

        return iface

    def _parse_cisco_interfaces(self, content: str, device: str) -> Dict[str, PhysicalInterface]:
        """Cisco IOS — interface GigabitEthernet0/1."""
        interfaces: Dict[str, PhysicalInterface] = {}

        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^interface\s).*\n)*)',
            content,
            re.MULTILINE
        ):
            name = m.group(1)
            block = m.group(2)

            # Пропускаем VLAN/loopback/tunnel
            if any(name.lower().startswith(p) for p in ('vlan', 'loopback', 'tunnel', 'port-channel', 'bdi')):
                continue

            iface = PhysicalInterface(name=name, device=device)

            # Status / admin
            if 'no shutdown' in block.lower() or 'no shut' in block.lower():
                iface.status = 'up'
            elif 'shutdown' in block.lower():
                iface.status = 'admin-down'

            # Speed
            speed_m = re.search(r'speed\s+(\d+)', block)
            if speed_m:
                speed_val = speed_m.group(1)
                iface.speed = f'{speed_val}M' if speed_val != 'auto' else 'auto'

            # Description
            desc_m = re.search(r'description\s+(.+)', block, re.IGNORECASE)
            if desc_m:
                iface.description = desc_m.group(1).strip()

            # Channel-group (LAG)
            channel_m = re.search(r'channel-group\s+(\d+)', block)
            if channel_m:
                iface.is_lag = False  # это member, не LAG

            # Media type
            media_m = re.search(r'media-type\s+(\S+)', block)
            if media_m:
                iface.media_type = media_m.group(1)

            interfaces[name] = iface

        # Port-channel интерфейсы (отдельно)
        for m in re.finditer(
            r'interface\s+Port-channel(\d+)\s*\n((?:(?!^interface\s).*\n)*)',
            content,
            re.MULTILINE
        ):
            po_id = m.group(1)
            block = m.group(2)
            iface = PhysicalInterface(
                name=f'Po{po_id}',
                device=device,
                status='up',
                is_lag=True,
                lag_id=f'Po{po_id}',
            )
            interfaces[f'Po{po_id}'] = iface

        return interfaces

    def _parse_huawei_interfaces(self, content: str, device: str) -> Dict[str, PhysicalInterface]:
        """Huawei VRP."""
        interfaces: Dict[str, PhysicalInterface] = {}

        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^#\s*$).*\n)*)',
            content,
            re.DOTALL
        ):
            name = m.group(1)
            block = m.group(2)

            if any(name.lower().startswith(p) for p in ('vlanif', 'loopback', 'null', 'eth-trunk')):
                continue

            iface = PhysicalInterface(name=name, device=device)

            if 'undo shutdown' in block.lower():
                iface.status = 'up'
            elif 'shutdown' in block.lower():
                iface.status = 'admin-down'

            desc_m = re.search(r'description\s+(.+)', block, re.IGNORECASE)
            if desc_m:
                iface.description = desc_m.group(1).strip()

            interfaces[name] = iface

        # Eth-Trunk
        for m in re.finditer(
            r'interface\s+Eth-Trunk(\d+)\s*\n((?:(?!^#\s*$).*\n)*)',
            content,
            re.DOTALL
        ):
            tr_id = m.group(1)
            interfaces[f'Eth-Trunk{tr_id}'] = PhysicalInterface(
                name=f'Eth-Trunk{tr_id}',
                device=device,
                status='up',
                is_lag=True,
                lag_id=f'Eth-Trunk{tr_id}',
            )

        return interfaces

    def _parse_hp_aruba_interfaces(self, content: str, device: str) -> Dict[str, PhysicalInterface]:
        """HP ProCurve / ArubaOS-Switch."""
        interfaces: Dict[str, PhysicalInterface] = {}

        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^interface\s).*\n)*)',
            content,
            re.MULTILINE
        ):
            name = m.group(1)
            block = m.group(2)

            if name.lower().startswith(('vlan', 'loopback')):
                continue

            iface = PhysicalInterface(name=name, device=device)

            if 'enable' in block.lower():
                iface.status = 'up'
            elif 'disable' in block.lower():
                iface.status = 'admin-down'

            desc_m = re.search(r'name\s+"(.+?)"', block)
            if desc_m:
                iface.description = desc_m.group(1)

            # Speed — дуплекс / auto
            speed_m = re.search(r'speed-duplex\s+(\S+)', block)
            if speed_m:
                iface.speed = speed_m.group(1)

            interfaces[name] = iface

        return interfaces

    def _parse_generic_interfaces(self, content: str, device: str) -> Dict[str, PhysicalInterface]:
        """Fallback: просто находим interface-блоки с IP."""
        interfaces: Dict[str, PhysicalInterface] = {}
        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^interface\s).*\n)*)',
            content,
            re.MULTILINE
        ):
            name = m.group(1)
            block = m.group(2)
            if name.lower().startswith(('vlan', 'loopback', 'tunnel', 'mgmt')):
                continue
            iface = PhysicalInterface(name=name, device=device)
            if 'no shut' in block.lower() or 'enable' in block.lower():
                iface.status = 'up'
            interfaces[name] = iface
        return interfaces

    # ── LLDP / CDP parsing ──────────────────────────────────────────────

    def _parse_lldp_cdp(self, content: str, vendor: str, device: str) -> List[LLDPNeighbor]:
        """Извлекает LLDP/CDP-соседей из вывода show-команд или из текстовых аннотаций."""
        neighbors: List[LLDPNeighbor] = []

        if vendor == 'aruba_cx':
            neighbors = self._parse_aruba_cx_lldp(content, device)
        elif vendor == 'cisco_ios':
            neighbors = self._parse_cisco_lldp_cdp(content, device)
        elif vendor == 'huawei':
            neighbors = self._parse_huawei_lldp(content, device)
        # HP и другие — аналогично, но данных в конфигах обычно нет без show-вывода

        return neighbors

    def _parse_aruba_cx_lldp(self, content: str, device: str) -> List[LLDPNeighbor]:
        """Aruba CX — аннотации в комментариях: ! LLDP: port 1/1/1 → neighbor-host port."""
        neighbors: List[LLDPNeighbor] = []

        # Ищем в комментариях формата: ! Link: 1/1/1 → remote_device (remote_port)
        link_pattern = re.compile(
            r'!\s*(?:Link|LLDP|CDP|link):\s*(\d+/\d+/\d+(?::\d+)?)\s*[:→>-]+\s*(\S+)\s*(?:\((\S+)\))?',
            re.IGNORECASE
        )
        for m in link_pattern.finditer(content):
            neighbors.append(LLDPNeighbor(
                local_device=device,
                local_port=m.group(1),
                remote_device=m.group(2),
                remote_port=m.group(3) or '',
                protocol='LLDP',
            ))

        # Также ищем "description" с подсказками соединений
        desc_pattern = re.compile(
            r'interface\s+(\d+/\d+/\d+).*?\n\s*description\s+(?:to[-_])?(\S+)',
            re.DOTALL | re.IGNORECASE
        )
        for m in desc_pattern.finditer(content):
            port = m.group(1)
            desc = m.group(2)
            # Проверяем, не дублирует ли аннотацию уже найденного Link/LLDP
            already = any(n.local_port == port for n in neighbors)
            if not already and desc:
                neighbors.append(LLDPNeighbor(
                    local_device=device,
                    local_port=port,
                    remote_device=desc,
                    remote_port='',
                    protocol='description',
                ))

        return neighbors

    def _parse_cisco_lldp_cdp(self, content: str, device: str) -> List[LLDPNeighbor]:
        """Cisco — ищем аннотации в комментариях или вывод show lldp."""
        neighbors: List[LLDPNeighbor] = []

        for m in re.finditer(
            r'!\s*(?:LLDP|CDP|Link):\s*(\S+)\s*[:→>-]+\s*(\S+)\s*(?:\((\S+)\))?',
            content,
            re.IGNORECASE
        ):
            neighbors.append(LLDPNeighbor(
                local_device=device,
                local_port=m.group(1),
                remote_device=m.group(2),
                remote_port=m.group(3) or '',
                protocol='LLDP',
            ))

        return neighbors

    def _parse_huawei_lldp(self, content: str, device: str) -> List[LLDPNeighbor]:
        """Huawei — аннотации."""
        neighbors: List[LLDPNeighbor] = []
        for m in re.finditer(
            r'#\s*(?:LLDP|CDP|Link):\s*(\S+)\s*[:→>-]+\s*(\S+)\s*(?:\((\S+)\))?',
            content,
            re.IGNORECASE
        ):
            neighbors.append(LLDPNeighbor(
                local_device=device,
                local_port=m.group(1),
                remote_device=m.group(2),
                remote_port=m.group(3) or '',
                protocol='LLDP',
            ))
        return neighbors


# ─── Builder ────────────────────────────────────────────────────────────────

class PhysicalTopologyBuilder:
    """
    Строитель физической топологии.

    Алгоритм:
    1. Парсинг конфигов → DevicePhysicalInfo для каждого файла
    2. LLDP/CDP-соседства → прямые физические линки
    3. Description-анализ → подсказки соединений (to-switch-name)
    4. Shared network detection (устройства на одной L3-сети)
    5. Экспорт nodes/edges для Vis.js

    Выходные данные готовы к визуализации в существующем GraphVisualizer.
    """

    def __init__(self):
        self.devices: Dict[str, DevicePhysicalInfo] = {}
        self.links: List[PhysicalLink] = []
        self.parser = PhysicalInterfaceParser()

    def load_device(self, filepath: Path, vendor: Optional[str] = None, known_hostname: Optional[str] = None) -> DevicePhysicalInfo:
        """Парсит один файл конфигурации и добавляет устройство."""
        info = self.parser.parse_device(filepath, vendor=vendor, known_hostname=known_hostname)
        self.devices[info.hostname] = info
        return info

    def load_devices_from_dir(self, dirpath, vendor: Optional[str] = None) -> List[DevicePhysicalInfo]:
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

    def discover_links(self) -> List[PhysicalLink]:
        """
        Основной метод: находит все физические линки.

        Методы обнаружения:
        - LLDP/CDP (прямые соседства) — высший приоритет
        - Description-анализ ('to-CoreSwitch') — средний приоритет
        - Shared-network анализ (общая подсеть) — низший приоритет
        """
        links: List[PhysicalLink] = []
        seen: Set[Tuple[str, str, str, str]] = set()  # дедупликация

        # ── LLDP/CDP links ──
        for device_info in self.devices.values():
            for neighbor in device_info.lldp_neighbors:
                remote_device = self._resolve_device_name(neighbor.remote_device)
                if not remote_device:
                    continue

                key = self._link_key(
                    device_info.hostname, neighbor.local_port,
                    remote_device, neighbor.remote_port
                )
                if key in seen:
                    continue
                seen.add(key)

                link = PhysicalLink(
                    device_a=device_info.hostname,
                    port_a=neighbor.local_port,
                    device_b=remote_device,
                    port_b=neighbor.remote_port,
                    status='up',
                    discovery_method=neighbor.protocol,
                )
                links.append(link)

        # ── Description-based links ──
        for device_info in self.devices.values():
            for iface_name, iface in device_info.interfaces.items():
                desc = iface.description.lower()
                if not desc:
                    continue

                # Паттерн: to-/from-/connected-to-/link-to- <hostname>
                link_m = re.match(
                    r'(?:to[-_]|from[-_]|connected[-_]to[-_]|link[-_]to[-_])(\S+)',
                    desc
                )
                if link_m:
                    target_name = link_m.group(1).replace('_', '-').replace(':', '-')
                    remote_device = self._resolve_device_name(target_name)
                    if remote_device and remote_device != device_info.hostname:
                        key = self._link_key(
                            device_info.hostname, iface_name,
                            remote_device, ''
                        )
                        if key not in seen:
                            seen.add(key)
                            links.append(PhysicalLink(
                                device_a=device_info.hostname,
                                port_a=iface_name,
                                device_b=remote_device,
                                port_b='',
                                status=iface.status,
                                discovery_method='description',
                            ))

        # ── Shared-network links ──
        subnet_map: Dict[str, List[Tuple[str, str]]] = {}
        for device_info in self.devices.values():
            for iface_name, iface in device_info.interfaces.items():
                if iface.description and '/' in iface.description:
                    try:
                        subnet = str(ip_network(iface.description, strict=False))
                        if subnet not in subnet_map:
                            subnet_map[subnet] = []
                        subnet_map[iface.description].append((device_info.hostname, iface_name))
                    except ValueError:
                        pass

        for subnet, members in subnet_map.items():
            if len(members) >= 2:
                for i in range(len(members)):
                    for j in range(i + 1, len(members)):
                        dev_a, port_a = members[i]
                        dev_b, port_b = members[j]
                        key = self._link_key(dev_a, port_a, dev_b, port_b)
                        if key not in seen:
                            seen.add(key)
                            links.append(PhysicalLink(
                                device_a=dev_a,
                                port_a=port_a,
                                device_b=dev_b,
                                port_b=port_b,
                                status='up',
                                discovery_method='subnet-heuristic',
                            ))

        self.links = links
        return links

    def _resolve_device_name(self, name: str) -> Optional[str]:
        """Ищет устройство по имени (точное или частичное совпадение)."""
        if not name:
            return None
        # Точное совпадение
        if name in self.devices:
            return name
        # Частичное
        for hostname in self.devices:
            if name.lower() in hostname.lower() or hostname.lower() in name.lower():
                return hostname
        return None

    @staticmethod
    def _link_key(a_dev: str, a_port: str, b_dev: str, b_port: str) -> Tuple[str, str, str, str]:
        """Нормализованный ключ для дедупликации линков (без учёта направления)."""
        if a_dev < b_dev or (a_dev == b_dev and a_port <= b_port):
            return (a_dev, a_port, b_dev, b_port)
        return (b_dev, b_port, a_dev, a_port)

    # ── Graph export ────────────────────────────────────────────────────

    def build_networkx_graph(self) -> nx.Graph:
        """Строит undirected граф физических соединений."""
        G = nx.Graph()

        for device_info in self.devices.values():
            G.add_node(device_info.hostname, type='device', mgmt_ip=device_info.management_ip)

        for link in self.links:
            G.add_edge(
                link.device_a, link.device_b,
                port_a=link.port_a,
                port_b=link.port_b,
                status=link.status,
                method=link.discovery_method,
            )

        return G

    def to_visjs(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Экспорт в формат Vis.js: (nodes, edges).
        Совместим с существующим GraphVisualizer.
        """
        nodes: List[Dict] = []
        edges: List[Dict] = []

        # Цвета статуса порта
        STATUS_COLORS = {
            'up': '#00AA00',         # зелёный
            'down': '#FF0000',       # красный
            'admin-down': '#FF8C00', # оранжевый
            'unknown': '#999999',    # серый
        }

        # Метод обнаружения → стиль ребра
        METHOD_STYLES = {
            'LLDP':   {'color': '#1f77b4', 'width': 3, 'dashes': False},
            'CDP':    {'color': '#9467bd', 'width': 3, 'dashes': False},
            'description': {'color': '#ff7f0e', 'width': 2, 'dashes': [5, 5]},
            'subnet-heuristic': {'color': '#2ca02c', 'width': 1, 'dashes': [10, 5]},
        }

        # Узлы → устройства
        device_types = self._classify_device_types()
        for hostname, device_info in self.devices.items():
            dtype = device_types.get(hostname, 'switch')
            nodes.append({
                'id': hostname,
                'label': hostname,
                'group': 'device',
                'type': dtype,
                'shape': 'image' if dtype == 'firewall' else 'dot',
                'size': 35,
                'title': f"Device: {hostname}\n"
                         f"IP: {device_info.management_ip or 'N/A'}\n"
                         f"Interfaces: {len(device_info.interfaces)}\n"
                         f"LLDP neighbors: {len(device_info.lldp_neighbors)}",
                'font': {'size': 12},
            })

        # Узлы → интерфейсы (опционально, для детального вида)
        show_interfaces = len(self.devices) <= 5  # только для малых топологий
        if show_interfaces:
            for device_info in self.devices.values():
                for iface_name, iface in device_info.interfaces.items():
                    if iface.status == 'up' or iface.is_lag:
                        node_id = f"{device_info.hostname}:{iface_name}"
                        nodes.append({
                            'id': node_id,
                            'label': iface_name,
                            'group': 'interface',
                            'type': 'interface',
                            'size': 12,
                            'color': {
                                'background': STATUS_COLORS.get(iface.status, STATUS_COLORS['unknown']),
                            },
                            'title': f"Port: {iface_name}\n"
                                     f"Status: {iface.status}\n"
                                     f"Speed: {iface.speed}\n"
                                     f"Description: {iface.description or 'N/A'}",
                        })
                        edges.append({
                            'from': device_info.hostname,
                            'to': node_id,
                            'label': 'has',
                            'color': {'color': '#CCCCCC'},
                            'dashes': True,
                            'width': 0.5,
                        })

        # Рёбра → физические линки
        for link in self.links:
            style = METHOD_STYLES.get(link.discovery_method, METHOD_STYLES['subnet-heuristic'])

            from_node = link.device_a
            to_node = link.device_b

            edge_label = ''
            if link.port_a and link.port_b:
                edge_label = f"{link.port_a} ↔ {link.port_b}"
            elif link.port_a:
                edge_label = link.port_a

            edges.append({
                'from': from_node,
                'to': to_node,
                'label': edge_label,
                'title': f"Link: {from_node} → {to_node}\n"
                         f"PortA: {link.port_a}  PortB: {link.port_b}\n"
                         f"Status: {link.status}\n"
                         f"Discovered by: {link.discovery_method}",
                'color': {'color': style['color']},
                'width': style['width'],
                'dashes': style['dashes'],
            })

        return nodes, edges

    def _classify_device_types(self) -> Dict[str, str]:
        """Эвристика: определяет тип устройства по hostname/keywords."""
        types: Dict[str, str] = {}
        for hostname in self.devices:
            lower = hostname.lower()
            if any(kw in lower for kw in ('fw', 'firewall', 'asa', 'juniper', 'ug', 'usergate', 'palo')):
                types[hostname] = 'firewall'
            elif any(kw in lower for kw in ('rt', 'router', 'isp', 'gateway', 'gw')):
                types[hostname] = 'router'
            elif any(kw in lower for kw in ('sw', 'switch', 'access', 'core', 'dist', 'hp', 'eltex')):
                types[hostname] = 'switch'
            else:
                types[hostname] = 'unknown'
        return types

    def summary(self) -> Dict:
        """Возвращает сводную статистику."""
        return {
            'devices': len(self.devices),
            'total_interfaces': sum(len(d.interfaces) for d in self.devices.values()),
            'up_interfaces': sum(
                1 for d in self.devices.values()
                for i in d.interfaces.values()
                if i.status == 'up'
            ),
            'lldp_neighbors': sum(len(d.lldp_neighbors) for d in self.devices.values()),
            'links': len(self.links),
            'link_methods': {
                method: sum(1 for l in self.links if l.discovery_method == method)
                for method in set(l.discovery_method for l in self.links)
            },
            'device_types': self._classify_device_types(),
        }


# ─── CLI integration ───────────────────────────────────────────────────────

def build_physical_topology(
    config_dir,
    vendor: Optional[str] = None,
):
    """
    Точка входа: парсит все конфиги в директории, строит физическую топологию.

    Возвращает (nodes, edges) для Vis.js.

    Использование:
        from src.core.physical_topology import build_physical_topology
        nodes, edges = build_physical_topology('configs/')
    """
    builder = PhysicalTopologyBuilder()
    path = Path(config_dir)
    builder.load_devices_from_dir(path, vendor=vendor)
    builder.discover_links()

    stats = builder.summary()
    print(f"[Physical Topology] {stats['devices']} devices, {stats['links']} links")
    for method, count in stats['link_methods'].items():
        print(f"  - {method}: {count} links")
    print(f"  - UP interfaces: {stats['up_interfaces']} / {stats['total_interfaces']}")

    return builder.to_visjs()


# Экспорт
__all__ = [
    'PhysicalInterface',
    'LLDPNeighbor',
    'PhysicalLink',
    'DevicePhysicalInfo',
    'PhysicalInterfaceParser',
    'PhysicalTopologyBuilder',
    'build_physical_topology',
]
