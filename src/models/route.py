"""
Модель статического маршрута.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class StaticRoute:
    """
    Представление статического маршрута.
    
    Attributes:
        destination: Целевой префикс в формате CIDR (например, "0.0.0.0/0" для default route)
        next_hop: IP-адрес next-hop или "interface <имя>"
        admin_distance: Административная дистанция (по умолчанию 1)
        metric: Метрика маршрута
        tag: Тег маршрута (опционально)
        name: Имя маршрута (опционально)
    """
    destination: str  # CIDR, например "192.168.0.0/16" или "0.0.0.0/0"
    next_hop: str  # IP или "interface <name>"
    admin_distance: int = 1
    metric: int = 0
    tag: Optional[int] = None
    name: Optional[str] = None
    
    @property
    def is_default(self) -> bool:
        """Проверяет, является ли маршрут маршрутом по умолчанию."""
        return self.destination == "0.0.0.0/0" or self.destination == "::/0"
    
    @property
    def is_via_interface(self) -> bool:
        """Проверяет, указывает ли next-hop на интерфейс."""
        return self.next_hop.startswith("interface ")
    
    @property
    def next_hop_ip(self) -> Optional[str]:
        """Возвращает IP next-hop (None, если next-hop - интерфейс)."""
        if self.is_via_interface:
            return None
        return self.next_hop
    
    @property
    def outgoing_interface(self) -> Optional[str]:
        """Возвращает имя исходящего интерфейса (если next-hop - интерфейс)."""
        if self.is_via_interface:
            return self.next_hop.replace("interface ", "").strip()
        return None
    
    def __hash__(self):
        return hash((self.destination, self.next_hop))
    
    def __eq__(self, other):
        if not isinstance(other, StaticRoute):
            return False
        return self.destination == other.destination and self.next_hop == other.next_hop
