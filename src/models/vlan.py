"""
Модель VLAN (Virtual Local Area Network).
"""
from dataclasses import dataclass, field
from typing import Optional, List, Set, Dict
from enum import Enum


class VlanMode(Enum):
    """Режим работы VLAN на интерфейсе."""
    ACCESS = "access"      # Доступный порт (один VLAN)
    TRUNK = "trunk"        # Транковый порт (несколько VLAN)
    HYBRID = "hybrid"      # Гибридный режим (Huawei)
    NATIVE = "native"      # Native VLAN (Cisco trunk)


@dataclass
class VLAN:
    """VLAN - виртуальная локальная сеть."""
    vlan_id: int                    # ID VLAN (1-4094)
    name: Optional[str] = None      # Имя VLAN
    description: Optional[str] = None  # Описание
    
    # Интерфейсы в этом VLAN
    access_interfaces: List[str] = field(default_factory=list)   # access ports
    trunk_interfaces: List[str] = field(default_factory=list)    # trunk ports
    
    # IP сеть ассоциированная с VLAN (SVI)
    network: Optional[str] = None   # Например "192.168.1.0/24"
    gateway: Optional[str] = None   # Gateway IP (SVI)
    
    # Дополнительные параметры
    is_native: bool = False         # Native VLAN для trunk
    is_management: bool = False   # Management VLAN
    
    def __hash__(self):
        return hash(self.vlan_id)
    
    def __eq__(self, other):
        if not isinstance(other, VLAN):
            return False
        return self.vlan_id == other.vlan_id
    
    def __repr__(self):
        return f"VLAN({self.vlan_id}, {self.name or 'unnamed'})"
    
    @property
    def interface_count(self) -> int:
        """Возвращает общее количество интерфейсов в VLAN."""
        return len(self.access_interfaces) + len(self.trunk_interfaces)


@dataclass
class VlanInterface:
    """Информация о VLAN на интерфейсе."""
    interface_name: str
    vlan_id: int
    mode: VlanMode
    is_native: bool = False         # Для trunk - native VLAN
    allowed_vlans: Set[int] = field(default_factory=set)  # Разрешённые VLAN (для trunk)
    
    def __repr__(self):
        mode_str = self.mode.value
        if self.mode == VlanMode.TRUNK:
            return f"VlanInterface({self.interface_name}, trunk, {len(self.allowed_vlans)} VLANs)"
        return f"VlanInterface({self.interface_name}, {mode_str}, VLAN {self.vlan_id})"


@dataclass
class VlanConfig:
    """Конфигурация VLAN на устройстве."""
    vlans: Dict[int, VLAN] = field(default_factory=dict)
    vlan_interfaces: List[VlanInterface] = field(default_factory=list)
    
    def add_vlan(self, vlan: VLAN):
        """Добавляет VLAN в конфигурацию."""
        self.vlans[vlan.vlan_id] = vlan
    
    def get_vlan(self, vlan_id: int) -> Optional[VLAN]:
        """Возвращает VLAN по ID."""
        return self.vlans.get(vlan_id)
    
    def get_vlans_for_interface(self, interface_name: str) -> List[VLAN]:
        """Возвращает список VLAN на интерфейсе."""
        result = []
        for vi in self.vlan_interfaces:
            if vi.interface_name == interface_name:
                if vi.mode == VlanMode.ACCESS:
                    vlan = self.get_vlan(vi.vlan_id)
                    if vlan:
                        result.append(vlan)
                elif vi.mode == VlanMode.TRUNK:
                    for vid in vi.allowed_vlans:
                        vlan = self.get_vlan(vid)
                        if vlan:
                            result.append(vlan)
        return result
