# Техническое задание: Модуль визуализации топологий Firewall Analyzer v3.0

**Версия:** 1.0
**Дата:** 2026-04-24
**Автор:** Firewall Analyzer Team

---

## 1. Общее описание

Разработать профессиональный модуль визуализации сетевой инфраструктуры, поддерживающий 6 видов топологий и 10+ режимов просмотра. Модуль работает с данными, извлечёнными из конфигураций сетевого оборудования (HP/Aruba, Cisco, Huawei, Juniper), и предоставляет интерактивный HTML-интерфейс.

---

## 2. Виды топологий

### 2.1 Access Graph (Граф доступа) — РЕАЛИЗОВАНО

**Описание:** Направленный граф правил firewall. Узел = IP/подсеть/хост/any. Ребро = разрешённое соединение.

**Данные:**
- Источник (source): IP, subnet, range, any
- Назначение (destination): IP, subnet, range, any
- Сервис: протокол + порт(ы)
- Действие: accept/deny
- Устройство: hostname
- Риск: 0-10

**Визуализация:**
- Узлы: dot/box по типу (host/subnet/zone/any)
- Цвета узлов: zone=#90EE90, subnet=#FFFACD, host=#FFB6C1, any=#FF0000
- Цвета рёбер: риск-based (red/orange/green)
- Толщина рёбер: количество правил

**Фильтры:**
- По зоне (zone filter)
- По подсети (subnet filter)
- По риску (show high risk only)
- По сервису (service filter)

---

### 2.2 Physical Topology (Физическая топология)

**Описание:** Граф физических соединений между устройствами. Узел = коммутатор/роутер/файрвол. Ребро = физический линк (порт-в-порт).

**Данные (парсинг):**
- Interface name (GigabitEthernet0/1)
- Port status (up/down)
- Port speed (1G/10G/100G)
- LAG/Port-channel membership
- LLDP/CDP neighbors (if available)
- Cable type (copper/fiber)

**Визуализация:**
- Узлы: иконки по типу устройства (switch icon, router icon)
- Рёбра: сплошная линия (up), пунктир (down), толщина = bandwidth
- Подписи рёбер: interface names (e.g., "Gi0/1 → Gi0/2")
- Цвет рёбер: зелёный (up), красный (down), жёлтый (errors)

**Фильтры:**
- По типу устройства
- По VLAN
- По скорости порта
- Показать только down линки

---

### 2.3 Logical L3 Topology (L3 логическая топология)

**Описание:** Граф IP-маршрутизации. Узел = IP-сеть (subnet) или next-hop роутер. Ребро = маршрут.

**Данные (парсинг):**
- Static routes: `ip route 10.0.0.0/24 192.168.1.1`
- Connected networks: интерфейсы с IP
- OSPF/BGP neighbors (если есть)
- Next-hop для каждой сети
- AD (Administrative Distance), metric

**Визуализация:**
- Узлы: IP-сети (прямоугольники) + роутеры (круги)
- Рёбра: направленные, подписаны next-hop IP
- Цвет рёбер: static (синий), connected (зелёный), dynamic (оранжевый)
- Двойной клик на сеть = показать все маршруты к ней

**Фильтры:**
- По типу маршрута (static/dynamic/connected)
- По VRF (если есть)
- По метрике

---

### 2.4 VLAN Topology (VLAN топология)

**Описание:** Граф VLAN broadcast domains. Узел = VLAN ID или устройство. Ребро = принадлежность к VLAN (access/trunk).

**Данные (парсинг):**
- VLAN IDs и names
- Access ports: `switchport access vlan 10`
- Trunk ports: `switchport trunk allowed vlan 10,20,30`
- Native VLAN
- Voice VLAN
- Management VLAN

**Визуализация:**
- Группировка по VLAN ID (цвета VLAN)
- Узлы устройств внутри группы VLAN
- Рёбра trunk: показать как соединения между VLAN
- Access порт: точка входа в VLAN
- Цвета: каждый VLAN = свой цвет

**Фильтры:**
- По VLAN ID
- Показать только trunk-линки
- Показать неиспользуемые VLAN

---

### 2.5 Security Zone Topology (Топология зон безопасности)

**Описание:** Граф межзонового доступа. Узел = security zone (Inside, Outside, DMZ, Mgmt). Ребро = разрешённый трафик между зонами.

**Данные (парсинг + ручное задание):**
- Zone assignments (interface → zone)
- Inter-zone policies (Cisco ASA security-level, Juniper zones)
- Default inter-zone action (permit/deny)
- Intra-zone action

**Визуализация:**
- Узлы: крупные области ( Inside 🔒, DMZ 🌐, Outside ⚠️ )
- Рёбра: направленные со стрелками + подписью сервисов
- Цвета рёбер: зелёный (разрешено), красный (запрещено), оранжевый (ограничено)
- Толщина = количество правил

**Фильтры:**
- По зоне
- По направлению (inbound/outbound)
- Показать только рискованные (Outside → Inside)

---

### 2.6 Application/Service Topology (Сервисная топология)

**Описание:** Граф зависимостей приложений/сервисов. Узел = сервис (DB, Web, API). Ребро = сетевое взаимодействие.

**Данные (выводится из правил + ручное маппинг):**
- Service name → IP:port mapping
- Dependencies: Web-tier → App-tier → DB-tier
- Protocol: HTTP, HTTPS, SQL, LDAP, etc.
- Direction: client → server

**Визуализация:**
- Узлы: иконки приложений (🗄️ DB, 🌐 Web, 🔌 API)
- Рёбра: с номерами портов
- Цвета по слоям (presentation/blue, app/green, data/orange)
- Многоуровневая раскладка

**Фильтры:**
- По слою (presentation/app/data)
- По протоколу
- Показать только критичные (DB tier)

---

## 3. Режимы просмотра

| Режим | Описание | Применение |
|-------|----------|------------|
| **Standard** | ForceAtlas2 physics | Общий обзор |
| **Hierarchical** | Уровни по зонам/подсетям | Иерархия сети |
| **Circular** | Радиальная раскладка | Презентации |
| **Risk Heatmap** | Фон окрашен по риску | Аудит |
| **Compliance View** | Подсветка PCI/CIS/NIST violations | Соответствие стандартам |
| **Path Trace** | Trace от Source до Destination | Troubleshooting |
| **Diff Mode** | До/После изменений | Change management |
| **Service Filter** | Только выбранный сервис | Анализ сервиса |
| **Temporal** | Изменения за период | Trend analysis |
| **Collapsed/Expanded** | Агрегация подсетей | Детализация |

---

## 4. Функциональные требования

### 4.1 Интерактивность
- [ ] Zoom (колёсико мыши)
- [ ] Pan (перетаскивание)
- [ ] Hover tooltip (IP, зона, риск)
- [ ] Click node = panel с деталями
- [ ] Click edge = список правил
- [ ] Multi-select (Ctrl+click)
- [ ] Context menu (right-click)

### 4.2 Фильтрация
- [ ] Real-time filter (без перезагрузки)
- [ ] Комбинированные фильтры (zone + risk)
- [ ] Search с autocomplete
- [ ] URL params для сохранения состояния фильтров

### 4.3 Экспорт
- [ ] PNG (текущий viewport)
- [ ] SVG (вектор)
- [ ] PDF (отчёт)
- [ ] JSON (данные графа)
- [ ] CSV (список правил)

### 4.4 Аналитика
- [ ] Path finding (BFS/DFS)
- [ ] Risk scoring per path
- [ ] Compliance check overlay
- [ ] Statistics panel (nodes count, edges count, avg risk)

---

## 5. Технические требования

**Фронтенд:**
- Vis.js Network (текущий)
- D3.js (для сложных custom визуализаций)
- HTML5 Canvas (для heatmap)

**Бэкенд:**
- Python 3.9+
- NetworkX для графов
- Graphviz для PNG
- Jinja2 для шаблонов

**Производительность:**
- До 1000 узлов без лагов
- Lazy loading для больших графов
- Web Worker для path finding
- Кэширование JSON

**Совместимость:**
- Chrome 90+, Firefox 88+, Edge 90+
- Мобильная адаптация (responsive)
- Touch events (pinch zoom)

---

## 6. Архитектура данных

```
Config File → Parser → Models → Analyzer → Graph → Visualizer → HTML
                    ↓           ↓          ↓
              Topology    Security   Reachability
               Builder     Auditor     Checker
```

**Unified Data Model:**
```python
class TopologyNode:
    id: str           # IP или hostname
    type: str         # host/subnet/zone/device/vlan
    label: str
    group: str        # zone/subnet/vlan_id
    level: int        # для hierarchical layout
    risk_score: float
    metadata: dict    # vendor-specific data

class TopologyEdge:
    from: str
    to: str
    type: str         # access/physical/logical/vlan
    label: str
    color: str
    width: int
    rules: List[str]  # связанные правила
    risk_score: float
    metadata: dict
```

---

## 7. Этапы разработки

### Этап 1: Fix & Polish (1-2 дня)
- [ ] Исправить все JS ошибки
- [ ] Полная русификация
- [ ] Risk Heatmap overlay
- [ ] Performance: lazy loading

### Этап 2: Physical + L3 Topology (3-5 дней)
- [ ] Парсер interface configuration (Cisco/HP)
- [ ] LLDP/CDP neighbor discovery
- [ ] Static route extraction
- [ ] Switch between views (Access/Physical/L3)

### Этап 3: VLAN + Zones (3-5 дней)
- [ ] VLAN parser
- [ ] Zone matrix view
- [ ] Security zone topology
- [ ] Compliance overlay

### Этап 4: Advanced Analytics (5-7 дней)
- [ ] Path Tracer с ACL evaluation
- [ ] What-If анализ
- [ ] Diff mode (до/после)
- [ ] Temporal view (timeline)

### Этап 5: Integrations (опционально)
- [ ] SNMP live discovery
- [ ] SIEM correlation
- [ ] API для внешних систем

---

## 8. Приоритеты (MoSCoW)

**Must have:**
- Access Graph (done)
- L3 Topology
- VLAN Topology
- Risk Heatmap
- Path Tracer

**Should have:**
- Physical Topology
- Security Zone Topology
- Compliance View
- Service Topology

**Could have:**
- Temporal view
- Diff mode
- API
- SNMP discovery

**Won't have (v3.0):**
- Real-time monitoring
- Configuration push
- Multi-tenant

---

## 9. Метрики успеха

- Время загрузки HTML < 3 сек (до 500 узлов)
- FPS > 30 при pan/zoom
- Path finding < 1 сек
- 100% покрытие парсером HP/Aruba/Cisco
- 0 критических JS ошибок

