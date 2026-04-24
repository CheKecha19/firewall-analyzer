"""
Модель правила межсетевого экрана.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Set
from .endpoint import Endpoint
from .service import Service


@dataclass
class FirewallRule:
    """Правило межсетевого экрана - разрешающее."""
    name: str
    rule_id: Optional[str] = None
    sources: List[Endpoint] = field(default_factory=list)
    destinations: List[Endpoint] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    action: str = "accept"  # accept/permit/allow
    enabled: bool = True
    description: Optional[str] = None
    vendor: Optional[str] = None  # usergate, cisco, juniper

    def __hash__(self):
        return hash((self.name, self.rule_id, self.vendor))

    def __eq__(self, other):
        if not isinstance(other, FirewallRule):
            return False
        return (self.name == other.name and 
                self.rule_id == other.rule_id and 
                self.vendor == other.vendor)

    def __repr__(self):
        src_count = len(self.sources)
        dst_count = len(self.destinations)
        svc_count = len(self.services)
        return f"FirewallRule({self.name}, {src_count}src->{dst_count}dst, {svc_count}svc, {self.action})"

    def get_source_names(self) -> Set[str]:
        """Возвращает имена источников."""
        return {s.name for s in self.sources}

    def get_destination_names(self) -> Set[str]:
        """Возвращает имена назначений."""
        return {d.name for d in self.destinations}

    def get_service_names(self) -> Set[str]:
        """Возвращает имена сервисов."""
        return {s.name for s in self.services}

    def services_str(self) -> str:
        """Возвращает строковое представление сервисов."""
        if not self.services:
            return "any"
        return ", ".join(s.name for s in self.services)
