"""
Парсеры конфигураций межсетевых экранов.
"""
from .base_parser import BaseParser
from .json_parser import UserGateParser
from .acl_parser import ACLParser

__all__ = ['BaseParser', 'UserGateParser', 'ACLParser']

# Регистрация доступных парсеров
AVAILABLE_PARSERS = [
    UserGateParser,
    ACLParser,
]


def get_parser_for_file(file_path: Path, content: str = None):
    """
    Возвращает подходящий парсер для файла.
    
    Args:
        file_path: Путь к файлу
        content: Опционально - содержимое файла
        
    Returns:
        Экземпляр парсера или None
    """
    from pathlib import Path
    
    for parser_class in AVAILABLE_PARSERS:
        parser = parser_class()
        if parser.can_parse(file_path, content):
            return parser
    
    return None
