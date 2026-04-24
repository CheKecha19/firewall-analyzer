"""
Модель сетевого сервиса.
"""
from dataclasses import dataclass, field
from typing import Optional, Set


@dataclass
class Service:
    """Сетевой сервис - протокол и порт/диапазон."""
    name: str
    protocol: str  # tcp, udp, icmp, ip, etc.
    ports: Set[str] = field(default_factory=set)  # "80", "443", "1000-2000"
    description: Optional[str] = None

    def __hash__(self):
        return hash((self.name, self.protocol, frozenset(self.ports) if self.ports else frozenset()))

    def __eq__(self, other):
        if not isinstance(other, Service):
            return False
        return (self.name == other.name and 
                self.protocol == other.protocol and 
                self.ports == other.ports)

    def __repr__(self):
        ports_str = ", ".join(sorted(self.ports)) if self.ports else "any"
        return f"Service({self.name}, {self.protocol}/{ports_str})"

    def port_range_str(self) -> str:
        """Возвращает строковое представление портов."""
        if not self.ports:
            return "any"
        return ", ".join(sorted(self.ports))
    
    def is_port_in_range(self, port: int) -> bool:
        """Проверяет, входит ли порт в диапазон сервиса."""
        if not self.ports or 'any' in self.ports:
            return True
        
        for port_str in self.ports:
            port_str = port_str.strip()
            if port_str == 'any':
                return True
            
            # Диапазон (1000-2000)
            if '-' in port_str:
                try:
                    start, end = port_str.split('-', 1)
                    if start.isdigit() and end.isdigit():
                        if int(start) <= port <= int(end):
                            return True
                except ValueError:
                    continue
            
            # Одиночный порт
            elif port_str.isdigit():
                if int(port_str) == port:
                    return True
        
        return False
    
    def get_port_numbers(self) -> Set[int]:
        """Возвращает множество всех портов как чисел."""
        result = set()
        
        if not self.ports or 'any' in self.ports:
            return result
        
        for port_str in self.ports:
            port_str = port_str.strip()
            
            if '-' in port_str:
                try:
                    start, end = port_str.split('-', 1)
                    result.update(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            elif port_str.isdigit():
                result.add(int(port_str))
        
        return result
    
    def has_wide_range(self, threshold: int = 100) -> bool:
        """Проверяет, содержит ли сервис широкий диапазон портов."""
        total_ports = len(self.get_port_numbers())
        return total_ports > threshold or 'any' in self.ports
