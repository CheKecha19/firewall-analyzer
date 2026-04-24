"""
Анализатор правил и построитель графа с оптимизациями производительности.
"""
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
import networkx as nx
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
from ..models.rule import FirewallRule
from ..models.endpoint import Endpoint
from ..models.service import Service
from ..models.device import NetworkDevice
from .topology_builder import TopologyBuilder


class FirewallAnalyzer:
    """Анализатор правил межсетевого экрана с кэшированием и параллельной обработкой."""
    
    def __init__(self):
        self.rules: List[FirewallRule] = []
        self.graph: nx.DiGraph = nx.DiGraph()
        self.endpoints: Dict[str, Endpoint] = {}
        self.services: Dict[str, Service] = {}
        
        # Топология сети
        self.topology_builder: Optional[TopologyBuilder] = None
        self.devices: Dict[str, NetworkDevice] = {}
        
        # Кэш разрешённых объектов
        self.resolved_objects_cache: Dict[str, List[Endpoint]] = {}
        
        # Статистика
        self.stats = {
            'files_processed': 0,
            'total_rules': 0,
            'allow_rules': 0,
            'unique_endpoints': 0,
            'unique_connections': 0,
            'devices_count': 0,
            'networks_count': 0,
        }
    
    def add_rules(self, rules: List[FirewallRule], source_file: str = ""):
        """Добавляет правила для анализа."""
        self.rules.extend(rules)
        self.stats['total_rules'] += len(rules)
        self.stats['allow_rules'] += len([r for r in rules if r.enabled])
        if rules:
            self.stats['files_processed'] += 1
        
        # Индексируем endpoints и services
        for rule in rules:
            for ep in rule.sources + rule.destinations:
                self.endpoints[ep.name] = ep
            for svc in rule.services:
                self.services[svc.name] = svc
    
    def add_rules_parallel(self, file_rules_pairs: List[Tuple[Path, List[FirewallRule]]]) -> List[Tuple[Path, str]]:
        """
        Параллельно добавляет правила из нескольких файлов.
        
        Args:
            file_rules_pairs: Список пар (путь_к_файлу, список_правил)
            
        Returns:
            Список ошибок (путь_к_файлу, описание_ошибки)
        """
        errors = []
        
        with ThreadPoolExecutor(max_workers=min(8, len(file_rules_pairs))) as executor:
            # Отправляем задачи на добавление правил
            futures = {}
            for file_path, rules in file_rules_pairs:
                future = executor.submit(self._process_rules_batch, rules, str(file_path))
                futures[future] = file_path
            
            # Собираем результаты
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    result = future.result()
                    if result:
                        errors.append((file_path, result))
                except Exception as e:
                    errors.append((file_path, str(e)))
        
        return errors
    
    def _process_rules_batch(self, rules: List[FirewallRule], source_file: str) -> Optional[str]:
        """Обрабатывает партию правил (для ThreadPoolExecutor)."""
        try:
            self.add_rules(rules, source_file)
            return None
        except Exception as e:
            return str(e)
    
    def build_graph(self, aggregate_subnets: bool = False, aggregate_threshold: int = 24) -> nx.DiGraph:
        """
        Строит направленный граф с опциональной агрегацией.
        
        Args:
            aggregate_subnets: Свернуть /32 хосты до /24 подсетей
            aggregate_threshold: Минимальный размер подсети для сворачивания
        """
        self.graph = nx.DiGraph()
        
        # Агрегация endpoint'ов если требуется
        if aggregate_subnets:
            self._aggregate_endpoints(threshold=aggregate_threshold)
        
        # Собираем зоны из правил
        zones_from_rules: Set[str] = set()
        
        # Собираем рёбра с агрегацией по (src, dst, service)
        edge_groups: Dict[Tuple[str, str], Dict] = defaultdict(lambda: {
            'rules': [],
            'services': set(),
            'rule_count': 0
        })
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Создаём узлы
            for src in rule.sources:
                self._add_node_if_not_exists(src)
                if src.zone:
                    zones_from_rules.add(src.zone)
            for dst in rule.destinations:
                self._add_node_if_not_exists(dst)
                if dst.zone:
                    zones_from_rules.add(dst.zone)
            
            # Группируем рёбра
            for src in rule.sources:
                for dst in rule.destinations:
                    edge_key = (src.name, dst.name)
                    
                    edge_groups[edge_key]['rules'].append(rule.name)
                    edge_groups[edge_key]['services'].update(
                        svc.name for svc in rule.services
                    )
                    edge_groups[edge_key]['rule_count'] += 1
        
        # Если зон нет в данных, создаём дефолтные
        if not zones_from_rules:
            zones_from_rules = {'Source', 'Destination', 'Network'}
        
        # Создаём рёбра из групп
        for (src_name, dst_name), data in edge_groups.items():
            self.graph.add_edge(
                src_name,
                dst_name,
                rules=data['rules'],
                services=list(data['services']),
                rule_count=data['rule_count']
            )
        
        self.stats['unique_endpoints'] = self.graph.number_of_nodes()
        self.stats['unique_connections'] = self.graph.number_of_edges()
        
        return self.graph
    
    def _add_node_if_not_exists(self, endpoint: Endpoint):
        """Добавляет узел в граф если его ещё нет."""
        if not self.graph.has_node(endpoint.name):
            self.graph.add_node(
                endpoint.name,
                endpoint_type=endpoint.endpoint_type,
                cidrs=list(endpoint.cidrs),
                zone=endpoint.zone,
                description=endpoint.description
            )
    
    def _aggregate_endpoints(self, threshold: int = 24):
        """Агрегирует /32 хосты до /24 подсетей."""
        # Собираем хосты по /24 сетям
        hosts_by_subnet: Dict[str, List[Endpoint]] = defaultdict(list)
        
        for rule in self.rules:
            for ep_list in [rule.sources, rule.destinations]:
                for i, ep in enumerate(ep_list):
                    if ep.endpoint_type == 'host' and ep.cidrs:
                        for cidr in ep.cidrs:
                            try:
                                if '/' in cidr:
                                    # Получаем /24 сеть
                                    network = ipaddress.ip_network(cidr, strict=False)
                                    if network.prefixlen >= threshold:
                                        aggregated = network.supernet(new_prefix=threshold)
                                        subnet_key = str(aggregated)
                                        hosts_by_subnet[subnet_key].append(ep)
                            except (ValueError, TypeError):
                                pass
        
        # Заменяем хосты на агрегированные
        for rule in self.rules:
            rule.sources = self._aggregate_endpoint_list(rule.sources, threshold)
            rule.destinations = self._aggregate_endpoint_list(rule.destinations, threshold)
    
    def _aggregate_endpoint_list(self, endpoints: List[Endpoint], threshold: int) -> List[Endpoint]:
        """Агрегирует список endpoint'ов."""
        if not endpoints:
            return endpoints
        
        # Группируем по /24
        subnet_groups: Dict[str, List[Endpoint]] = defaultdict(list)
        other_endpoints: List[Endpoint] = []
        
        for ep in endpoints:
            if ep.endpoint_type == 'host' and ep.cidrs:
                cidr = list(ep.cidrs)[0] if ep.cidrs else None
                if cidr:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        if network.prefixlen >= threshold:
                            aggregated = network.supernet(new_prefix=threshold)
                            subnet_groups[str(aggregated)].append(ep)
                            continue
                    except (ValueError, TypeError):
                        pass
            other_endpoints.append(ep)
        
        # Создаём агрегированные endpoints
        result = other_endpoints.copy()
        for subnet, hosts in subnet_groups.items():
            if len(hosts) >= 2:  # Агрегируем только если 2+ хоста
                aggregated_ep = Endpoint(
                    name=f"{subnet}_aggregated",
                    endpoint_type='subnet',
                    cidrs={subnet},
                    description=f"Aggregated from {len(hosts)} hosts"
                )
                result.append(aggregated_ep)
            else:
                result.extend(hosts)
        
        return result
    
    def get_cached_endpoints(self, obj_id: str, resolver_func) -> List[Endpoint]:
        """Возвращает закэшированные endpoints или вычисляет их."""
        if obj_id in self.resolved_objects_cache:
            return self.resolved_objects_cache[obj_id]
        
        result = resolver_func(obj_id)
        self.resolved_objects_cache[obj_id] = result
        return result
    
    def get_statistics(self) -> dict:
        """Возвращает статистику анализа."""
        return {
            **self.stats,
            'cache_size': len(self.resolved_objects_cache),
        }
    
    def print_statistics(self):
        """Выводит статистику в консоль."""
        stats = self.get_statistics()
        print("\n" + "="*60)
        print("ANALYSIS STATISTICS")
        print("="*60)
        print(f"Files processed:        {stats['files_processed']}")
        print(f"Total rules:              {stats['total_rules']}")
        print(f"Active allow rules:       {stats['allow_rules']}")
        print(f"Unique endpoints:         {stats['unique_endpoints']}")
        print(f"Unique connections:       {stats['unique_connections']}")
        if stats.get('cache_size'):
            print(f"Resolved objects cached:  {stats['cache_size']}")
        print("="*60 + "\n")
    
    def find_paths(self, source: str, target: str) -> List[List[str]]:
        """Находит все пути между двумя узлами."""
        try:
            return list(nx.all_simple_paths(self.graph, source, target, cutoff=5))
        except nx.NetworkXNoPath:
            return []
    
    def get_connected_components(self) -> List[Set[str]]:
        """Возвращает компоненты связности графа."""
        if self.graph.is_directed():
            return list(nx.weakly_connected_components(self.graph))
        return list(nx.connected_components(self.graph))
    
    def get_high_degree_nodes(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """Возвращает узлы с наибольшей степенью."""
        degrees = sorted(self.graph.degree(), key=lambda x: x[1], reverse=True)
        return degrees[:top_n]
    
    def export_to_dot(self, output_path: Path) -> Path:
        """Экспортирует граф в формат DOT."""
        try:
            nx.nx_agraph.write_dot(self.graph, str(output_path))
            return output_path
        except Exception:
            # Fallback: ручная генерация DOT
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("digraph FirewallMap {\n")
                f.write('    rankdir=LR;\n')
                f.write('    node [shape=box];\n\n')
                
                # Узлы с цветами
                for node, data in self.graph.nodes(data=True):
                    endpoint_type = data.get('endpoint_type', 'unknown')
                    color = self._get_node_color(endpoint_type)
                    
                    safe_node = node.replace('"', '\\"')
                    f.write(f'    "{safe_node}" [label="{safe_node}", fillcolor={color}, style=filled];\n')
                
                f.write('\n')
                
                # Рёбра
                for src, dst, data in self.graph.edges(data=True):
                    safe_src = src.replace('"', '\\"')
                    safe_dst = dst.replace('"', '\\"')
                    services = ', '.join(data.get('services', ['any']))
                    f.write(f'    "{safe_src}" -> "{safe_dst}" [label="{services}"];\n')
                
                f.write("}\n")
            
            return output_path
    
    def _get_node_color(self, endpoint_type: str) -> str:
        """Возвращает цвет узла по типу."""
        colors = {
            'zone': 'lightgreen',
            'subnet': 'lightyellow',
            'host': 'pink',
            'group': 'lightblue',
            'unknown': 'lightgray'
        }
        return colors.get(endpoint_type, 'lightgray')
    
    # ===== Методы для работы с топологией =====
    
    def add_device_topology(
        self,
        device_id: str,
        vendor: str,
        hostname: Optional[str],
        interfaces: List,
        routes: List,
        mgmt_ip: Optional[str] = None
    ):
        """
        Добавляет топологию устройства.
        
        Args:
            device_id: Уникальный ID устройства
            vendor: Вендор (cisco, juniper, huawei, usergate)
            hostname: Имя хоста
            interfaces: Список Interface объектов
            routes: Список StaticRoute объектов
            mgmt_ip: IP для управления
        """
        if self.topology_builder is None:
            self.topology_builder = TopologyBuilder()
        
        self.topology_builder.add_device_from_parsed(
            device_id=device_id,
            vendor=vendor,
            hostname=hostname,
            interfaces=interfaces,
            routes=routes,
            mgmt_ip=mgmt_ip
        )
        
        # Обновляем статистику
        self.stats['devices_count'] = len(self.topology_builder.devices)
        self.stats['networks_count'] = len(self.topology_builder.networks)
    
    def build_topology(self) -> Optional[nx.Graph]:
        """Строит и возвращает граф топологии."""
        if self.topology_builder is None:
            return None
        return self.topology_builder.build_topology_graph()
    
    def get_topology_data(self) -> Optional[Tuple[List[Dict], List[Dict]]]:
        """Возвращает данные топологии для визуализации Vis.js."""
        if self.topology_builder is None:
            return None
        return self.topology_builder.export_to_visjs_data()
    
    def has_topology(self) -> bool:
        """Проверяет, есть ли построенная топология."""
        return self.topology_builder is not None and len(self.topology_builder.devices) > 0
    
    def get_topology_summary(self) -> Dict:
        """Возвращает сводку по топологии."""
        if not self.has_topology():
            return {'has_topology': False}
        
        return {
            'has_topology': True,
            'devices_count': len(self.topology_builder.devices),
            'networks_count': len(self.topology_builder.networks),
            'device_list': [
                {
                    'id': d.id,
                    'hostname': d.hostname,
                    'vendor': d.vendor,
                    'interface_count': len(d.interfaces),
                    'route_count': len(d.static_routes),
                }
                for d in self.topology_builder.devices.values()
            ]
        }
    
    # ===== Методы для проверки достижимости =====
    
    def check_reachability(
        self,
        source_ip: str,
        dest_ip: str,
        dest_port: int = 80,
        protocol: str = "tcp"
    ) -> Optional[Dict]:
        """
        Проверяет достижимость между IP-адресами с учётом ACL.
        
        Args:
            source_ip: IP-адрес источника
            dest_ip: IP-адрес назначения
            dest_port: Порт назначения
            protocol: Протокол (tcp, udp, icmp)
            
        Returns:
            Dict с результатом проверки или None если нет топологии
        """
        if not self.has_topology():
            return None
        
        from .reachability_checker import ReachabilityChecker
        
        checker = ReachabilityChecker(self.topology_builder, self.rules)
        result = checker.check_reachability(source_ip, dest_ip, dest_port, protocol)
        
        return {
            'source': result.source_ip,
            'destination': result.dest_ip,
            'port': result.dest_port,
            'protocol': result.protocol,
            'reachable': result.is_reachable,
            'status': result.status.value,
            'message': result.message,
            'blocking_device': result.blocking_device,
            'path': [
                {
                    'device': hop.device_id,
                    'ingress': hop.ingress_iface,
                    'egress': hop.egress_iface,
                    'action': hop.action,
                    'rule': hop.matched_rule,
                    'message': hop.message
                }
                for hop in result.path
            ]
        }
    
    def get_path_devices(self, source_ip: str, dest_ip: str) -> List[str]:
        """Возвращает список устройств на пути между IP."""
        if not self.has_topology():
            return []
        
        from .reachability_checker import ReachabilityChecker
        
        checker = ReachabilityChecker(self.topology_builder, self.rules)
        return checker.get_shortest_path_devices(source_ip, dest_ip)
