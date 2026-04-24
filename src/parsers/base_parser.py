"""
Базовый класс для парсеров конфигураций.
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Tuple
from ..models.rule import FirewallRule
from ..models.interface import Interface
from ..models.route import StaticRoute


class BaseParser(ABC):
    """Абстрактный базовый класс для парсеров конфигураций."""
    
    VENDOR: str = "unknown"
    
    @abstractmethod
    def can_parse(self, file_path: Path, content: Optional[str] = None) -> bool:
        """
        Проверяет, может ли парсер обработать данный файл.
        
        Args:
            file_path: Путь к файлу
            content: Опционально - содержимое файла для анализа
            
        Returns:
            True если парсер может обработать файл
        """
        pass
    
    @abstractmethod
    def parse(self, file_path: Path) -> List[FirewallRule]:
        """
        Парсит файл конфигурации и возвращает список правил.
        
        Args:
            file_path: Путь к файлу конфигурации
            
        Returns:
            Список разобранных правил FirewallRule
        """
        pass
    
    def parse_topology(self, file_path: Path) -> Tuple[List[Interface], List[StaticRoute]]:
        """
        Парсит топологию сети (интерфейсы и маршруты).
        
        По умолчанию возвращает пустые списки.
        Конкретные парсеры должны переопределить этот метод.
        
        Args:
            file_path: Путь к файлу конфигурации
            
        Returns:
            Кортеж (список интерфейсов, список статических маршрутов)
        """
        return [], []
    
    def read_file(self, file_path: Path) -> str:
        """
        Читает содержимое файла.
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            Содержимое файла в виде строки
        """
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
