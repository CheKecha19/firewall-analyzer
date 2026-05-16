"""
VLAN Topology Builder — граф VLAN broadcast domains.

Строит топологию VLAN из конфигураций сетевых устройств:
- VLAN ID и имена
- Access порты: switchport access vlan / vlan access
- Trunk порты: switchport trunk allowed vlan / vlan trunk allowed
- Native VLAN
- Voice VLAN (если указан в конфиге)
- Management VLAN (эвристически — mgmt/vlan 999/etc.)

Поддерживаемые форматы конфигов:
- Aruba CX (vlan <id>, vlan access/trunk native/allowed)
- Cisco IOS (switchport access/trunk vlan)
- Huawei VRP (port link-type access/trunk, port default/trunk vlan)

Выход: nodes + edges для Vis.js, совместим с существующим GraphVisualizer.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict


# ─── Data models ────────────────────────────────────────────────────────────

@dataclass
class VLANInfo:
    """Информация о VLAN."""
    vlan_id: int
    name: str = ''
    device: str = ''                    # устройство-источник
    description: str = ''
    is_management: bool = False
    is_voice: bool = False
    is_native: bool = False
    devices_with_this_vlan: Set[str] = field(default_factory=set)


@dataclass
class VLANPortInfo:
    """Информация о порте в контексте VLAN."""
    port_name: str
    device: str
    port_type: str = 'access'           # 'access', 'trunk', 'hybrid'
    access_vlan: Optional[int] = None   # для access-портов
    trunk_native_vlan: Optional[int] = None
    trunk_allowed_vlans: List[int] = field(default_factory=list)
    voice_vlan: Optional[int] = None
    status: str = 'up'
    description: str = ''


@dataclass
class VLANDeviceInfo:
    """Сводка VLAN-информации устройства."""
    hostname: str
    vendor: str
    vlans: Dict[int, VLANInfo] = field(default_factory=dict)       # VLAN ID → VLANInfo
    ports: Dict[str, VLANPortInfo] = field(default_factory=dict)   # port_name → VLANPortInfo
    management_ip: Optional[str] = None


# ─── Parser ─────────────────────────────────────────────────────────────────

class VLANConfigParser:
    """
    Парсер VLAN-конфигурации из конфигурационных файлов.

    Извлекает:
    - VLAN definitions (id + name)
    - Access / trunk port assignments
    - Native / voice VLAN
    - Management VLAN (эвристика)
    """

    VENDOR_SIGNATURES = {
        'aruba_cx':   [r'ArubaOS-CX', r'ArubaOS', r'vsf member', r'interface lag\s'],
        'cisco_ios':  [r'Cisco IOS', r'boot-start-marker', r'^interface\s+Vlan\d+'],
        'huawei':     [r'sysname\s', r'Huawei\s+VRP', r'^\s*#\s*$'],
        'hp_aruba':   [r'hostname\s+"', r'ProCurve', r'(?:Aruba|HP)\s+\d'],
    }

    def detect_vendor(self, content: str) -> str:
        """Автоопределение вендора."""
        for vendor, patterns in self.VENDOR_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    return vendor
        return 'unknown'

    def parse_device(
        self,
        filepath: Path,
        vendor: Optional[str] = None,
        known_hostname: Optional[str] = None,
    ) -> VLANDeviceInfo:
        """Парсит файл конфигурации → VLANDeviceInfo."""
        content = filepath.read_text(encoding='utf-8', errors='ignore')

        if not vendor:
            vendor = self.detect_vendor(content)

        hostname = known_hostname or self._extract_hostname(content, vendor)
        mgmt_ip = self._extract_mgmt_ip(content, vendor)
        vlans = self._parse_vlan_definitions(content, vendor, hostname)
        ports = self._parse_vlan_ports(content, vendor, hostname)

        # Эвристика определения management / voice VLAN
        self._classify_special_vlans(vlans, ports, hostname)

        return VLANDeviceInfo(
            hostname=hostname,
            vendor=vendor,
            vlans=vlans,
            ports=ports,
            management_ip=mgmt_ip,
        )

    def _extract_hostname(self, content: str, vendor: str) -> str:
        patterns = {
            'aruba_cx':   r'hostname\s+(\S+)',
            'cisco_ios':  r'hostname\s+(\S+)',
            'huawei':     r'sysname\s+(\S+)',
            'hp_aruba':   r'hostname\s+"(.+?)"',
        }
        pat = patterns.get(vendor, r'hostname\s+(\S+)')
        m = re.search(pat, content, re.IGNORECASE)
        return m.group(1).strip() if m else 'unknown'

    def _extract_mgmt_ip(self, content: str, vendor: str) -> Optional[str]:
        if vendor in ('aruba_cx', 'hp_aruba'):
            m = re.search(
                r'interface\s+mgmt\s*\n.+?ip\s+static\s+(\d+\.\d+\.\d+\.\d+)',
                content, re.DOTALL | re.IGNORECASE
            )
            if m:
                return m.group(1)
        elif vendor == 'cisco_ios':
            m = re.search(
                r'interface\s+[Mm]gmt.*?\n.+?ip\s+address\s+(\d+\.\d+\.\d+\.\d+)',
                content, re.DOTALL
            )
            if m:
                return m.group(1)
        return None

    # ── VLAN definitions ─────────────────────────────────────────────────

    def _parse_vlan_definitions(
        self, content: str, vendor: str, device: str
    ) -> Dict[int, VLANInfo]:
        """
        Извлекает определения VLAN (vlan <id> с именем).

        Aruba CX / HP:
            vlan 1
            vlan 499
                name Data_Network

        Cisco IOS:
            vlan 10
             name Sales_Department

        Huawei VRP:
            vlan 10
             description Sales_Department
        """
        vlans: Dict[int, VLANInfo] = {}

        if vendor in ('aruba_cx', 'hp_aruba'):
            vlans = self._parse_aruba_cx_vlan_defs(content, device)
        elif vendor == 'cisco_ios':
            vlans = self._parse_cisco_vlan_defs(content, device)
        elif vendor == 'huawei':
            vlans = self._parse_huawei_vlan_defs(content, device)
        else:
            vlans = self._parse_generic_vlan_defs(content, device)

        return vlans

    def _parse_aruba_cx_vlan_defs(self, content: str, device: str) -> Dict[int, VLANInfo]:
        """Aruba CX: 'vlan <id>' с возможной 'name <name>' под ней."""
        vlans: Dict[int, VLANInfo] = {}

        # vlan <id> может быть как строка "vlan 1" или "vlan phone4"
        # В конфиге встречается "vlan phone4" но это алиас — реально парсим только числовые ID
        vlan_pattern = re.compile(
            r'^vlan\s+(\d+)\s*\n((?:(?!^vlan\s|\binterface\s).*\n)*)',
            re.MULTILINE
        )

        for m in vlan_pattern.finditer(content):
            vlan_id = int(m.group(1))
            block = m.group(2)

            name = ''
            name_m = re.search(r'name\s+(.+)', block, re.IGNORECASE)
            if name_m:
                name = name_m.group(1).strip()

            vlans[vlan_id] = VLANInfo(
                vlan_id=vlan_id,
                name=name,
                device=device,
            )

        return vlans

    def _parse_cisco_vlan_defs(self, content: str, device: str) -> Dict[int, VLANInfo]:
        """Cisco IOS: 'vlan <id>' / 'name <name>'."""
        vlans: Dict[int, VLANInfo] = {}

        # vlan <id> блоки
        vlan_pattern = re.compile(
            r'^vlan\s+(\d+)\s*\n((?:(?!^vlan\s|\binterface\s).*\n)*)',
            re.MULTILINE
        )

        for m in vlan_pattern.finditer(content):
            vlan_id = int(m.group(1))
            block = m.group(2)

            name = ''
            name_m = re.search(r'^\s*name\s+(.+)', block, re.MULTILINE | re.IGNORECASE)
            if name_m:
                name = name_m.group(1).strip()

            vlans[vlan_id] = VLANInfo(
                vlan_id=vlan_id,
                name=name,
                device=device,
            )

        return vlans

    def _parse_huawei_vlan_defs(self, content: str, device: str) -> Dict[int, VLANInfo]:
        """Huawei VRP: 'vlan <id>' / 'description <name>'."""
        vlans: Dict[int, VLANInfo] = {}

        vlan_pattern = re.compile(
            r'^vlan\s+(\d+)\s*\n((?:(?!^vlan\s|\binterface\s|^#\s*$).*\n)*)',
            re.MULTILINE
        )

        for m in vlan_pattern.finditer(content):
            vlan_id = int(m.group(1))
            block = m.group(2)

            name = ''
            desc_m = re.search(r'description\s+(.+)', block, re.IGNORECASE)
            if desc_m:
                name = desc_m.group(1).strip()

            vlans[vlan_id] = VLANInfo(
                vlan_id=vlan_id,
                name=name,
                device=device,
            )

        return vlans

    def _parse_generic_vlan_defs(self, content: str, device: str) -> Dict[int, VLANInfo]:
        """Fallback: vlan <id> с опциональным name."""
        vlans: Dict[int, VLANInfo] = {}
        for m in re.finditer(r'^vlan\s+(\d+)\s*$', content, re.MULTILINE):
            vlan_id = int(m.group(1))
            if vlan_id not in vlans:
                vlans[vlan_id] = VLANInfo(vlan_id=vlan_id, name='', device=device)
        return vlans

    # ── VLAN port assignments ────────────────────────────────────────────

    def _parse_vlan_ports(
        self, content: str, vendor: str, device: str
    ) -> Dict[str, VLANPortInfo]:
        """
        Парсит порты с VLAN-настройками.

        Aruba CX:
            interface 1/1/1
                vlan access 10
            interface lag 1
                vlan trunk native 1
                vlan trunk allowed 10,20,30

        Cisco IOS:
            interface GigabitEthernet0/1
                switchport mode access
                switchport access vlan 10
            interface GigabitEthernet0/2
                switchport mode trunk
                switchport trunk native vlan 1
                switchport trunk allowed vlan 10,20,30

        Huawei VRP:
            interface GigabitEthernet0/0/1
                port link-type access
                port default vlan 10
            interface GigabitEthernet0/0/2
                port link-type trunk
                port trunk allow-pass vlan 10 20 30
        """
        if vendor in ('aruba_cx',):
            return self._parse_aruba_cx_vlan_ports(content, device)
        elif vendor == 'cisco_ios':
            return self._parse_cisco_vlan_ports(content, device)
        elif vendor == 'huawei':
            return self._parse_huawei_vlan_ports(content, device)
        elif vendor == 'hp_aruba':
            # ArubaOS (controller) — гибридный: trusted vlan + switchport + aruba-like
            return self._parse_hp_aruba_vlan_ports(content, device)
        else:
            return self._parse_generic_vlan_ports(content, device)

    def _parse_aruba_cx_vlan_ports(
        self, content: str, device: str
    ) -> Dict[str, VLANPortInfo]:
        """Aruba CX VLAN port assignments."""
        ports: Dict[str, VLANPortInfo] = {}

        # Интерфейсы: interface <name>
        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^interface\s).*\n)*)',
            content,
            re.MULTILINE
        ):
            name = m.group(1)
            block = m.group(2)

            # Пропускаем VLAN-интерфейсы, loopback, mgmt
            if name.lower().startswith(('vlan', 'loopback')):
                continue

            port_info = VLANPortInfo(port_name=name, device=device)

            # Status
            if 'no shutdown' in block.lower():
                port_info.status = 'up'
            elif 'shutdown' in block.lower():
                port_info.status = 'down'

            # Description
            desc_m = re.search(r'description\s+(.+)', block, re.IGNORECASE)
            if desc_m:
                port_info.description = desc_m.group(1).strip()

            # Access порт
            access_m = re.search(r'vlan\s+access\s+(\d+)', block, re.IGNORECASE)
            if access_m:
                port_info.port_type = 'access'
                port_info.access_vlan = int(access_m.group(1))
                ports[name] = port_info
                continue

            # Trunk порт
            trunk_native_m = re.search(r'vlan\s+trunk\s+native\s+(\d+)', block, re.IGNORECASE)
            trunk_allowed_m = re.search(r'vlan\s+trunk\s+allowed\s+(.+)', block, re.IGNORECASE)

            if trunk_native_m or trunk_allowed_m:
                port_info.port_type = 'trunk'
                if trunk_native_m:
                    port_info.trunk_native_vlan = int(trunk_native_m.group(1))
                if trunk_allowed_m:
                    allowed_str = trunk_allowed_m.group(1).strip()
                    port_info.trunk_allowed_vlans = self._parse_vlan_list(allowed_str)
                ports[name] = port_info
                continue

            # Voice VLAN (в Aruba CX обычно через LLDP-MED, но иногда явно)
            voice_m = re.search(r'voice\s+vlan\s+(\d+)', block, re.IGNORECASE)
            if voice_m:
                port_info.voice_vlan = int(voice_m.group(1))
                if port_info not in ports.values():
                    ports[name] = port_info

        return ports

    def _parse_cisco_vlan_ports(
        self, content: str, device: str
    ) -> Dict[str, VLANPortInfo]:
        """Cisco IOS VLAN port assignments."""
        ports: Dict[str, VLANPortInfo] = {}

        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^interface\s).*\n)*)',
            content,
            re.MULTILINE
        ):
            name = m.group(1)
            block = m.group(2)

            # Пропускаем VLAN/loopback/tunnel/bdi/port-channel
            if any(name.lower().startswith(p) for p in (
                'vlan', 'loopback', 'tunnel', 'bdi',
            )):
                continue

            port_info = VLANPortInfo(port_name=name, device=device)

            # Description
            desc_m = re.search(r'description\s+(.+)', block, re.IGNORECASE)
            if desc_m:
                port_info.description = desc_m.group(1).strip()

            # Mode + access / trunk
            mode_m = re.search(r'switchport\s+mode\s+(\S+)', block, re.IGNORECASE)
            access_m = re.search(r'switchport\s+access\s+vlan\s+(\d+)', block, re.IGNORECASE)
            trunk_native_m = re.search(
                r'switchport\s+trunk\s+native\s+vlan\s+(\d+)',
                block, re.IGNORECASE
            )
            trunk_allowed_m = re.search(
                r'switchport\s+trunk\s+allowed\s+vlan\s+(.+)',
                block, re.IGNORECASE
            )
            voice_m = re.search(r'switchport\s+voice\s+vlan\s+(\d+)', block, re.IGNORECASE)

            if access_m:
                port_info.port_type = 'access'
                port_info.access_vlan = int(access_m.group(1))
                ports[name] = port_info
            elif mode_m and mode_m.group(1).lower() == 'trunk':
                port_info.port_type = 'trunk'
                if trunk_native_m:
                    port_info.trunk_native_vlan = int(trunk_native_m.group(1))
                if trunk_allowed_m:
                    port_info.trunk_allowed_vlans = self._parse_vlan_list(
                        trunk_allowed_m.group(1)
                    )
                ports[name] = port_info
            elif trunk_allowed_m:
                port_info.port_type = 'trunk'
                if trunk_native_m:
                    port_info.trunk_native_vlan = int(trunk_native_m.group(1))
                port_info.trunk_allowed_vlans = self._parse_vlan_list(
                    trunk_allowed_m.group(1)
                )
                ports[name] = port_info
            elif access_m:
                # Резервный случай
                port_info.port_type = 'access'
                port_info.access_vlan = int(access_m.group(1))
                ports[name] = port_info
            elif voice_m:
                port_info.voice_vlan = int(voice_m.group(1))
                ports[name] = port_info

        return ports

    def _parse_huawei_vlan_ports(
        self, content: str, device: str
    ) -> Dict[str, VLANPortInfo]:
        """Huawei VRP VLAN port assignments."""
        ports: Dict[str, VLANPortInfo] = {}

        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^interface\s|^#\s*$).*\n)*)',
            content,
            re.DOTALL
        ):
            name = m.group(1)
            block = m.group(2)

            if name.lower().startswith(('vlanif', 'loopback', 'null')):
                continue

            port_info = VLANPortInfo(port_name=name, device=device)

            link_type_m = re.search(r'port\s+link-type\s+(\S+)', block, re.IGNORECASE)
            access_vlan_m = re.search(r'port\s+default\s+vlan\s+(\d+)', block, re.IGNORECASE)
            trunk_allow_m = re.search(
                r'port\s+trunk\s+allow-pass\s+vlan\s+(.+)',
                block, re.IGNORECASE
            )
            trunk_pvid_m = re.search(r'port\s+trunk\s+pvid\s+vlan\s+(\d+)', block, re.IGNORECASE)

            if link_type_m:
                port_info.port_type = link_type_m.group(1).lower()

            if access_vlan_m:
                port_info.access_vlan = int(access_vlan_m.group(1))
                if not link_type_m:
                    port_info.port_type = 'access'
                ports[name] = port_info

            if trunk_allow_m:
                port_info.trunk_allowed_vlans = self._parse_vlan_list(
                    trunk_allow_m.group(1)
                )
                if port_info.port_type == 'access':
                    port_info.port_type = 'trunk'
                ports[name] = port_info

            if trunk_pvid_m:
                port_info.trunk_native_vlan = int(trunk_pvid_m.group(1))
                if name not in ports:
                    ports[name] = port_info

        return ports

    def _parse_hp_aruba_vlan_ports(
        self, content: str, device: str
    ) -> Dict[str, VLANPortInfo]:
        """HP ArubaOS Controller — trusted vlan + switchport hybrid."""
        ports: Dict[str, VLANPortInfo] = {}

        for m in re.finditer(
            r'interface\s+(\S+\s+\S+)\s*\n((?:(?!^interface\s).*\n)*)',
            content,
            re.MULTILINE
        ):
            name = m.group(1).replace(' ', '/')
            block = m.group(2)

            # Пропускаем mgmt/loopback
            if any(name.lower().startswith(p) for p in ('mgmt', 'loopback')):
                continue

            port_info = VLANPortInfo(port_name=name, device=device)

            # Description
            desc_m = re.search(r'description\s+"(.+?)"', block)
            if desc_m:
                port_info.description = desc_m.group(1)

            # ArubaOS: "trusted vlan <id>"
            trusted_m = re.search(r'trusted\s+vlan\s+(\d+)', block, re.IGNORECASE)
            if trusted_m:
                port_info.port_type = 'access'
                port_info.access_vlan = int(trusted_m.group(1))
                ports[name] = port_info
                continue

            # Cisco-like switchport commands
            mode_m = re.search(r'switchport\s+mode\s+(\S+)', block, re.IGNORECASE)
            access_m = re.search(
                r'switchport\s+access\s+vlan\s+(\d+)', block, re.IGNORECASE
            )
            trunk_native_m = re.search(
                r'switchport\s+trunk\s+native\s+vlan\s+(\d+)',
                block, re.IGNORECASE
            )
            trunk_allowed_m = re.search(
                r'switchport\s+trunk\s+allowed\s+vlan\s+(.+)',
                block, re.IGNORECASE
            )
            voice_m = re.search(
                r'switchport\s+voice\s+vlan\s+(\d+)', block, re.IGNORECASE
            )

            if access_m:
                port_info.port_type = 'access'
                port_info.access_vlan = int(access_m.group(1))
                ports[name] = port_info
            elif mode_m and mode_m.group(1).lower() == 'trunk':
                port_info.port_type = 'trunk'
                if trunk_native_m:
                    port_info.trunk_native_vlan = int(trunk_native_m.group(1))
                if trunk_allowed_m:
                    port_info.trunk_allowed_vlans = self._parse_vlan_list(
                        trunk_allowed_m.group(1)
                    )
                ports[name] = port_info
            elif trunk_allowed_m:
                port_info.port_type = 'trunk'
                if trunk_native_m:
                    port_info.trunk_native_vlan = int(trunk_native_m.group(1))
                port_info.trunk_allowed_vlans = self._parse_vlan_list(
                    trunk_allowed_m.group(1)
                )
                ports[name] = port_info
            elif voice_m:
                port_info.voice_vlan = int(voice_m.group(1))
                ports[name] = port_info

        return ports

    def _parse_generic_vlan_ports(
        self, content: str, device: str
    ) -> Dict[str, VLANPortInfo]:
        """Fallback: пробуем aruba-like + cisco-like."""
        ports = self._parse_aruba_cx_vlan_ports(content, device)
        cisco = self._parse_cisco_vlan_ports(content, device)
        # Мержим (Cisco-специфичные порты добавляем)
        for name, pi in cisco.items():
            if name not in ports:
                ports[name] = pi
        return ports

    def _parse_vlan_list(self, vlan_str: str) -> List[int]:
        """
        Парсит список VLAN ID.
        Форматы:
            "10,20,30"
            "10-12,20,30-35"
            "add 10,20,30"  (Cisco IOS 'add' префикс)
        """
        # Убираем префикс 'add'
        vlan_str = re.sub(r'\badd\s+', '', vlan_str, flags=re.IGNORECASE).strip()
        result: List[int] = []

        for segment in re.split(r'[,;]\s*', vlan_str):
            segment = segment.strip()
            if not segment:
                continue
            if '-' in segment:
                # Range: 10-12
                parts = segment.split('-')
                try:
                    start, end = int(parts[0]), int(parts[-1])
                    result.extend(range(start, end + 1))
                except (ValueError, IndexError):
                    # Не числовой VLAN (алиас вроде phone4)
                    pass
            else:
                try:
                    result.append(int(segment))
                except ValueError:
                    # Не числовой VLAN (алиас)
                    pass

        return sorted(set(result))

    # ── Special VLAN classification ──────────────────────────────────────

    def _classify_special_vlans(
        self,
        vlans: Dict[int, VLANInfo],
        ports: Dict[str, VLANPortInfo],
        device: str,
    ) -> None:
        """
        Эвристическая классификация management / voice VLAN.
        """
        for vlan_id, vlan_info in vlans.items():
            name_lower = vlan_info.name.lower()

            # Management VLAN
            if vlan_id == 999 or 'mgmt' in name_lower or 'management' in name_lower:
                vlan_info.is_management = True

            # Voice VLAN
            if vlan_id == 666 or 'voice' in name_lower or 'phone' in name_lower \
               or 'voip' in name_lower or 'телефония' in name_lower:
                vlan_info.is_voice = True

        # Также проверяем порты на voice vlan
        for port_info in ports.values():
            if port_info.voice_vlan and port_info.voice_vlan in vlans:
                vlans[port_info.voice_vlan].is_voice = True


# ─── Builder ────────────────────────────────────────────────────────────────

class VLANTopologyBuilder:
    """
    Строитель VLAN топологии.

    Алгоритм:
    1. Парсинг конфигов → VLANDeviceInfo для каждого файла
    2. Агрегация всех VLAN по broadcast domain (VLAN ID)
    3. Классификация портов (access vs trunk)
    4. Построение графа: устройства + VLAN-узлы + связи (member/trunk)
    5. Экспорт nodes/edges для Vis.js

    Выходные данные готовы к визуализации в существующем GraphVisualizer.
    """

    # Палитра для VLAN (16 цветов, повторяются циклически)
    VLAN_COLORS = [
        '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8',
        '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B739', '#52B788',
        '#E74C3C', '#3498DB', '#2ECC71', '#F39C12', '#9B59B6',
        '#1ABC9C',
    ]

    def __init__(self):
        self.devices: Dict[str, VLANDeviceInfo] = {}
        self.parser = VLANConfigParser()

    def load_device(
        self,
        filepath: Path,
        vendor: Optional[str] = None,
        known_hostname: Optional[str] = None,
    ) -> VLANDeviceInfo:
        """Парсит один файл конфигурации и добавляет устройство."""
        info = self.parser.parse_device(
            filepath, vendor=vendor, known_hostname=known_hostname
        )
        self.devices[info.hostname] = info
        return info

    def load_devices_from_dir(
        self, dirpath, vendor: Optional[str] = None
    ) -> List[VLANDeviceInfo]:
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

    def discover_vlan_domains(self) -> Dict[int, VLANInfo]:
        """
        Строит broadcast domains: агрегирует VLAN по ID из всех устройств.
        Возвращает полный словарь {vlan_id: VLANInfo} с информацией о том,
        на каких устройствах присутствует каждый VLAN.
        """
        global_vlans: Dict[int, VLANInfo] = {}

        for device_info in self.devices.values():
            for vlan_id, vlan_info in device_info.vlans.items():
                if vlan_id not in global_vlans:
                    global_vlans[vlan_id] = VLANInfo(
                        vlan_id=vlan_id,
                        name=vlan_info.name,
                        device=vlan_info.device,
                        is_management=vlan_info.is_management,
                        is_voice=vlan_info.is_voice,
                    )
                else:
                    # Обновляем имя, если текущее пустое, а новое нет
                    if not global_vlans[vlan_id].name and vlan_info.name:
                        global_vlans[vlan_id].name = vlan_info.name

                global_vlans[vlan_id].devices_with_this_vlan.add(
                    device_info.hostname
                )

        return global_vlans

    def to_visjs(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Экспорт в формат Vis.js: (nodes, edges).

        Граф содержит:
        - Узлы VLAN (группировка по VLAN ID, свой цвет)
        - Узлы устройств (коммутаторы)
        - Рёбра access (устройство → VLAN)
        - Рёбра trunk (устройство → VLAN, с пометкой trunk)

        Совместим с существующим GraphVisualizer.
        """
        nodes: List[Dict] = []
        edges: List[Dict] = []

        # Агрегируем все VLAN
        global_vlans = self.discover_vlan_domains()

        # Сортируем VLAN: сначала специальные, потом по ID
        sorted_vlan_ids = sorted(
            global_vlans.keys(),
            key=lambda vid: (
                not global_vlans[vid].is_management,
                not global_vlans[vid].is_voice,
                vid,
            )
        )

        # ── VLAN узлы ───────────────────────────────────────────────────
        for idx, vlan_id in enumerate(sorted_vlan_ids):
            vlan = global_vlans[vlan_id]
            color = self.VLAN_COLORS[idx % len(self.VLAN_COLORS)]

            device_count = len(vlan.devices_with_this_vlan)
            subtitle_parts = [f'Устройств: {device_count}']

            # Special tags
            tags = []
            if vlan.is_management:
                tags.append('🔧 MGMT')
            if vlan.is_voice:
                tags.append('📞 VOICE')

            tag_str = ' | '.join(tags) if tags else ''

            nodes.append({
                'id': f'vlan_{vlan_id}',
                'label': f'VLAN {vlan_id}\n{vlan.name}',
                'group': 'vlan',
                'vlan_id': vlan_id,
                'color': color,
                'size': 30 + device_count * 3,
                'title': f'VLAN {vlan_id}: {vlan.name}\n'
                         f'{"; ".join(subtitle_parts)}\n'
                         f'{tag_str}',
                'borderWidth': 3 if vlan.is_management else 1,
                'borderWidthSelected': 4,
                'shapeProperties': {
                    'borderDashes': [5, 2] if vlan.is_management else [0, 0],
                },
            })

        # ── Узлы устройств ──────────────────────────────────────────────
        for device_name in sorted(self.devices.keys()):
            device_info = self.devices[device_name]
            vlan_count = len(device_info.vlans)
            access_count = sum(
                1 for p in device_info.ports.values() if p.port_type == 'access'
            )
            trunk_count = sum(
                1 for p in device_info.ports.values() if p.port_type == 'trunk'
            )

            nodes.append({
                'id': f'dev_{device_name}',
                'label': device_name,
                'group': 'device',
                'title': f'Устройство: {device_name}\n'
                         f'VLANs: {vlan_count}\n'
                         f'Access портов: {access_count}\n'
                         f'Trunk портов: {trunk_count}',
                'color': '#667eea',
                'size': 25,
                'shape': 'box',
            })

        # ── Рёбра access (device → vlan) ────────────────────────────────
        for device_info in self.devices.values():
            for port_name, port_info in device_info.ports.items():
                if port_info.port_type == 'access' and port_info.access_vlan:
                    vlan_id = port_info.access_vlan
                    # Показываем только если VLAN найден в global_vlans (или хотя бы числовой)
                    vlan_key = f'vlan_{vlan_id}'
                    dev_key = f'dev_{device_info.hostname}'

                    edges.append({
                        'from': dev_key,
                        'to': vlan_key,
                        'label': port_name,
                        'title': f'Access порт: {port_name}\n'
                                 f'VLAN: {vlan_id}\n'
                                 f'Описание: {port_info.description or "N/A"}',
                        'color': {'color': global_vlans.get(vlan_id) and
                                  self.VLAN_COLORS[sorted_vlan_ids.index(vlan_id) %
                                                    len(self.VLAN_COLORS)]
                                  if vlan_id in sorted_vlan_ids
                                  else '#999999'},
                        'width': 1,
                        'dashes': False,
                        'arrows': 'to',
                    })

        # ── Рёбра trunk (device → vlan для разрешённых VLAN) ────────────
        for device_info in self.devices.values():
            for port_name, port_info in device_info.ports.items():
                if port_info.port_type == 'trunk' and port_info.trunk_allowed_vlans:
                    dev_key = f'dev_{device_info.hostname}'
                    for vlan_id in port_info.trunk_allowed_vlans:
                        vlan_key = f'vlan_{vlan_id}'
                        edges.append({
                            'from': dev_key,
                            'to': vlan_key,
                            'label': f'trunk {port_name}',
                            'title': f'Trunk порт: {port_name}\n'
                                     f'Разрешён VLAN: {vlan_id}\n'
                                     f'Native VLAN: {port_info.trunk_native_vlan or "N/A"}\n'
                                     f'Описание: {port_info.description or "N/A"}',
                            'color': {'color': '#FF6600'},
                            'width': 3,
                            'dashes': True,
                            'arrows': 'to',
                        })

        return nodes, edges

    def get_vlan_matrix(self) -> Dict:
        """
        Возвращает матрицу устройство×VLAN:
        {devices: [...], vlans: {vid: name}, matrix: {device: {vid: info}}}
        """
        global_vlans = self.discover_vlan_domains()

        devices = sorted(self.devices.keys())
        vlan_ids = sorted(global_vlans.keys())

        matrix: Dict[str, Dict[int, Optional[Dict]]] = {}
        for device_name in devices:
            matrix[device_name] = {}
            device_info = self.devices[device_name]
            for vlan_id in vlan_ids:
                vlan = global_vlans[vlan_id]
                if device_name in vlan.devices_with_this_vlan:
                    # VLAN присутствует на устройстве
                    access_ports = [
                        p.port_name
                        for p in device_info.ports.values()
                        if p.port_type == 'access' and p.access_vlan == vlan_id
                    ]
                    trunk_ports = [
                        p.port_name
                        for p in device_info.ports.values()
                        if p.port_type == 'trunk'
                           and vlan_id in p.trunk_allowed_vlans
                    ]
                    matrix[device_name][vlan_id] = {
                        'name': vlan.name,
                        'access_ports': access_ports,
                        'trunk_ports': trunk_ports,
                        'is_management': vlan.is_management,
                        'is_voice': vlan.is_voice,
                    }
                else:
                    matrix[device_name][vlan_id] = None

        return {
            'devices': devices,
            'vlans': {vid: global_vlans[vid].name for vid in vlan_ids},
            'special_vlans': {
                'management': [vid for vid in vlan_ids if global_vlans[vid].is_management],
                'voice': [vid for vid in vlan_ids if global_vlans[vid].is_voice],
            },
            'matrix': matrix,
        }

    def summary(self) -> Dict:
        """Возвращает сводную статистику VLAN топологии."""
        global_vlans = self.discover_vlan_domains()

        total_access = 0
        total_trunk = 0
        for device_info in self.devices.values():
            for port_info in device_info.ports.values():
                if port_info.port_type == 'access':
                    total_access += 1
                elif port_info.port_type == 'trunk':
                    total_trunk += 1

        return {
            'devices': len(self.devices),
            'vlans_total': len(global_vlans),
            'management_vlans': [vid for vid, v in global_vlans.items() if v.is_management],
            'voice_vlans': [vid for vid, v in global_vlans.items() if v.is_voice],
            'access_ports': total_access,
            'trunk_ports': total_trunk,
            'orphan_vlans': [
                vid for vid, v in global_vlans.items()
                if len(v.devices_with_this_vlan) <= 1
            ],
            'broadcast_domains': {
                vid: {
                    'name': v.name,
                    'devices': sorted(v.devices_with_this_vlan),
                    'device_count': len(v.devices_with_this_vlan),
                }
                for vid, v in sorted(global_vlans.items())
            },
        }


# ─── CLI integration ───────────────────────────────────────────────────────

def build_vlan_topology(
    config_dir,
    vendor: Optional[str] = None,
):
    """
    Точка входа: парсит все конфиги в директории, строит VLAN топологию.

    Возвращает (nodes, edges) для Vis.js.

    Использование:
        from src.core.vlan_topology import build_vlan_topology
        nodes, edges = build_vlan_topology('configs/')
    """
    builder = VLANTopologyBuilder()
    path = Path(config_dir)
    builder.load_devices_from_dir(path, vendor=vendor)

    stats = builder.summary()
    print(f"[VLAN Topology] {stats['devices']} устройств, "
          f"{stats['vlans_total']} VLAN")
    print(f"  Access-портов: {stats['access_ports']}, "
          f"Trunk-портов: {stats['trunk_ports']}")
    if stats['management_vlans']:
        print(f"  Management VLAN: {stats['management_vlans']}")
    if stats['voice_vlans']:
        print(f"  Voice VLAN: {stats['voice_vlans']}")
    if stats['orphan_vlans']:
        print(f"  VLAN без соседей (на 1 устройстве): "
              f"{stats['orphan_vlans']}")

    # Показываем broadcast domains summary
    for vid, dom in stats['broadcast_domains'].items():
        dev_list = ', '.join(dom['devices'][:3])
        if len(dom['devices']) > 3:
            dev_list += f' +{len(dom["devices"]) - 3}'
        print(f"  VLAN {vid} ({dom['name'] or 'unnamed'}): {dev_list}")

    return builder.to_visjs()


# Экспорт
__all__ = [
    'VLANInfo',
    'VLANPortInfo',
    'VLANDeviceInfo',
    'VLANConfigParser',
    'VLANTopologyBuilder',
    'build_vlan_topology',
]
