"""
VLAN Topology Builder
Строит топологию VLAN broadcast domains из конфигураций.
"""

import re
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class VLANNode:
    """Узел VLAN топологии."""
    vlan_id: int
    vlan_name: str
    device: str
    ports: List[str] = field(default_factory=list)
    is_trunk: bool = False
    trunk_to: List[str] = field(default_factory=list)  # связанные VLAN
    hosts: List[str] = field(default_factory=list)  # IP хосты в VLAN
    color: str = '#90EE90'


@dataclass
class VLANTrunk:
    """Trunk link между устройствами."""
    from_device: str
    from_port: str
    to_device: str
    to_port: str
    allowed_vlans: List[int]
    native_vlan: int


class VLANTopologyBuilder:
    """Строитель VLAN топологии."""
    
    VLAN_COLORS = [
        '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8',
        '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B739', '#52B788',
        '#E74C3C', '#3498DB', '#2ECC71', '#F39C12', '#9B59B6',
    ]
    
    def __init__(self):
        self.vlans: Dict[int, VLANNode] = {}
        self.trunks: List[VLANTrunk] = []
        self.device_vlans: Dict[str, Set[int]] = defaultdict(set)
        self.color_map: Dict[int, str] = {}
    
    def add_device_vlans(self, device: str, vlans: Dict[int, str], 
                         interfaces: Dict):
        """Добавляет VLAN устройства в топологию."""
        for vlan_id, vlan_name in vlans.items():
            if vlan_id not in self.vlans:
                self.vlans[vlan_id] = VLANNode(
                    vlan_id=vlan_id,
                    vlan_name=vlan_name,
                    device=device
                )
                self.color_map[vlan_id] = self.VLAN_COLORS[
                    len(self.color_map) % len(self.VLAN_COLORS)
                ]
            
            self.vlans[vlan_id].device = device
            self.device_vlans[device].add(vlan_id)
    
    def add_trunk(self, from_device: str, from_port: str,
                  to_device: str, to_port: str,
                  allowed_vlans: List[int], native_vlan: int = 1):
        """Добавляет trunk соединение."""
        self.trunks.append(VLANTrunk(
            from_device=from_device,
            from_port=from_port,
            to_device=to_device,
            to_port=to_port,
            allowed_vlans=allowed_vlans,
            native_vlan=native_vlan
        ))
    
    def get_vlan_graph(self) -> Tuple[List[Dict], List[Dict]]:
        """Возвращает nodes и edges для визуализации VLAN."""
        nodes = []
        edges = []
        
        # Группировка по VLAN
        vlan_devices = defaultdict(list)
        for vlan_id, vlan in self.vlans.items():
            vlan_devices[vlan_id].append(vlan.device)
        
        # Узлы VLAN
        for vlan_id in sorted(self.vlans.keys()):
            vlan = self.vlans[vlan_id]
            nodes.append({
                'id': f'vlan_{vlan_id}',
                'label': f'VLAN {vlan_id}\\n{vlan.vlan_name}',
                'group': 'vlan',
                'vlan_id': vlan_id,
                'color': self.color_map.get(vlan_id, '#90EE90'),
                'size': 30 + len(self.device_vlans.get(vlan.device, [])) * 5,
                'title': self._format_vlan_tooltip(vlan)
            })
        
        # Узлы устройств
        devices = set()
        for vlan in self.vlans.values():
            devices.add(vlan.device)
        
        for device in sorted(devices):
            device_vlans = self.device_vlans.get(device, set())
            nodes.append({
                'id': f'dev_{device}',
                'label': device,
                'group': 'device',
                'device': device,
                'color': '#667eea',
                'size': 25,
                'title': f'Устройство: {device}\\nVLANs: {sorted(device_vlans)}'
            })
        
        # Рёбра: устройство -> VLAN (access ports)
        for vlan_id, vlan in self.vlans.items():
            edges.append({
                'from': f'dev_{vlan.device}',
                'to': f'vlan_{vlan_id}',
                'label': 'member',
                'color': {'color': self.color_map.get(vlan_id, '#999')},
                'width': 2,
                'dashes': not vlan.is_trunk
            })
        
        # Рёбра: trunk соединения
        for trunk in self.trunks:
            for vlan_id in trunk.allowed_vlans:
                if vlan_id in self.vlans:
                    edges.append({
                        'from': f'dev_{trunk.from_device}',
                        'to': f'vlan_{vlan_id}',
                        'label': f'trunk {trunk.from_port}',
                        'color': {'color': '#FF6600'},
                        'width': 3,
                        'arrows': 'to'
                    })
        
        return nodes, edges
    
    def get_vlan_matrix(self) -> Dict:
        """Возвращает матрицу VLAN для всех устройств."""
        devices = sorted(self.device_vlans.keys())
        vlan_ids = sorted(self.vlans.keys())
        
        matrix = {}
        for device in devices:
            matrix[device] = {}
            for vlan_id in vlan_ids:
                vlan = self.vlans.get(vlan_id)
                if vlan and vlan.device == device:
                    matrix[device][vlan_id] = {
                        'name': vlan.vlan_name,
                        'ports': len(vlan.ports),
                        'is_trunk': vlan.is_trunk,
                        'color': self.color_map.get(vlan_id, '#999')
                    }
                else:
                    matrix[device][vlan_id] = None
        
        return {
            'devices': devices,
            'vlans': {vid: self.vlans[vid].vlan_name for vid in vlan_ids},
            'matrix': matrix
        }
    
    def _format_vlan_tooltip(self, vlan: VLANNode) -> str:
        """Форматирует tooltip для VLAN."""
        lines = [
            f'VLAN {vlan.vlan_id}: {vlan.vlan_name}',
            f'Устройство: {vlan.device}',
            f'Порты: {len(vlan.ports)}',
        ]
        if vlan.is_trunk:
            lines.append('Trunk: Да')
        if vlan.hosts:
            lines.append(f'Хосты: {len(vlan.hosts)}')
        return '\\n'.join(lines)


# Экспорт
__all__ = ['VLANTopologyBuilder', 'VLANNode', 'VLANTrunk']
