"""
Модель сетевого интерфейса.
"""
from dataclasses import dataclass, field
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from .vlan import VlanInterface


@dataclass
class Interface:
    """
    Представление сетевого интерфейса.

    Attributes:
        name: Имя интерфейса (например, "eth0", "GigabitEthernet1/0/1")
        ip_address: IP-адрес с маской в формате CIDR (например, "192.168.1.1/24")
        zone: Зона безопасности (если есть)
        acl_in: Имя/ID входящего ACL
        acl_out: Имя/ID исходящего ACL
        description: Описание интерфейса
        enabled: Состояние интерфейса (включён/выключен)
        vlan_interface: VLAN конфигурация интерфейса (access/trunk)
    """
    name: str
    ip_address: Optional[str] = None  # CIDR, например "192.168.1.1/24"
    zone: Optional[str] = None
    acl_in: Optional[str] = None
    acl_out: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True
    vlan_interface: Optional['VlanInterface'] = None  # type: ignore

    @property
    def ip_only(self) -> Optional[str]:
        """Возвращает только IP-адрес без маски."""
        if self.ip_address and '/' in self.ip_address:
            return self.ip_address.split('/')[0]
        return self.ip_address

    @property
    def network(self) -> Optional[str]:
        """Возвращает сеть в формате CIDR."""
        return self.ip_address

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if not isinstance(other, Interface):
            return False
        return self.name == other.name
