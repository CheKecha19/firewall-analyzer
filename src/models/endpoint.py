"""
Модель узла сети (Endpoint).
"""
from dataclasses import dataclass
from typing import Optional, Set


@dataclass
class Endpoint:
    """Узел сети - хост, подсеть, группа или зона."""
    name: str
    endpoint_type: str  # 'host', 'subnet', 'group', 'zone'
    cidrs: Set[str] = None
    zone: Optional[str] = None
    description: Optional[str] = None

    def __post_init__(self):
        if self.cidrs is None:
            self.cidrs = set()

    def __hash__(self):
        return hash((self.name, self.endpoint_type))

    def __eq__(self, other):
        if not isinstance(other, Endpoint):
            return False
        return self.name == other.name and self.endpoint_type == other.endpoint_type

    def __repr__(self):
        cidrs_str = ", ".join(sorted(self.cidrs)) if self.cidrs else "N/A"
        return f"Endpoint({self.name}, {self.endpoint_type}, {cidrs_str})"
