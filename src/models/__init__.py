"""
Модели данных для анализатора межсетевых экранов.
"""
from .endpoint import Endpoint
from .service import Service
from .rule import FirewallRule
from .interface import Interface
from .route import StaticRoute
from .device import NetworkDevice
from .vlan import VLAN, VlanInterface, VlanConfig

__all__ = [
    'Endpoint', 'Service', 'FirewallRule',
    'Interface', 'StaticRoute', 'NetworkDevice',
    'VLAN', 'VlanInterface', 'VlanConfig'
]
