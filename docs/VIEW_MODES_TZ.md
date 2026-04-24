# Техническое задание: Режимы просмотра Firewall Analyzer v3.0

**Версия:** 1.0
**Дата:** 2026-04-24
**Автор:** Firewall Analyzer Team

---

## 1. Общее описание

Настоящее ТЗ описывает все режимы просмотра (View Modes) интерактивного HTML-визуализатора. Каждый режим — это отдельная проекция одного и того же графа данных, оптимизированная под конкретную задачу пользователя (аудит, troubleshooting, презентация).

**Основной принцип:** один граф данных — множество представлений. Переключение режима не требует перезагрузки данных.

---

## 2. Режимы просмотра

### 2.1 Standard (Стандартный)

**Цель:** Общий обзор сетевой карты с естественным расположением узлов.

**Описание:**
Режим по умолчанию при открытии карты. Использует force-directed layout (ForceAtlas2) для автоматического размещения узлов на основе связей и физики.

**Данные:**
- Все узлы графа (hosts, subnets, zones, devices)
- Все рёбра (access rules, routes, links)
- Risk score для рёбер

**Визуализация:**
- Layout: `physics: { solver: 'forceAtlas2Based' }`
- Nodes: shape='dot', size=25, font=14px
- Edges: curvedCW, width=1-3
- Цвета: зона/тип узла (см. легенду)
- Анимация: плавная при загрузке ( stabilization )

**Элементы управления:**
- Zoom: колёсико мыши / pinch
- Pan: drag & drop
- Physics toggle: вкл/выкл физику (после ручного позиционирования)
- Stabilization progress bar

**Фильтры:**
- Все фильтры доступны
- Сохраняют позицию узлов при переключении

**Экспорт:**
- PNG: текущий viewport
- JSON: позиции всех узлов для восстановления вида

**Зависимости:**
- Базовый режим, не требует дополнительных данных

**Производительность:**
- До 500 узлов: мгновенная стабилизация
- 500-1000: progress bar, ~2 сек
- >1000: lazy loading (только видимые узлы)

---

### 2.2 Hierarchical (Иерархический)

**Цель:** Показать иерархию сети по уровням (ядро → агрегация → доступ).

**Описание:**
Узлы располагаются по уровням (levels) в зависимости от их типа, зоны или IP-октетов. Иерархия может быть:
- Вертикальная (Top-Down, Bottom-Up)
- Горизонтальная (Left-Right)

**Данные:**
- `node.level` — уровень в иерархии (0 = корень, 1, 2, ...)
- `node.parent` — ID родительского узла (для nested)
- `node.group` — зона/тип (для авто-уровней)

**Алгоритм уровней:**
```
Level 0: Интернет / Outside
Level 1: DMZ / Perimeter
Level 2: Core / Distribution
Level 3: Access / Inside
Level 4: Endpoints / Hosts
```

**Визуализация:**
- Layout: `hierarchical: { direction: 'UD', sortMethod: 'directed' }`
- Nodes: shape='box' для групп, 'dot' для хостов
- Level separation: 150px (настраиваемо)
- Node spacing: 200px
- Physics: отключена (фиксированная позиция)

**Элементы управления:**
- Direction selector: UD / DU / LR / RL
- Level spacing slider
- Expand/Collapse групп
- Show/hide intermediate nodes

**Фильтры:**
- Show levels 0-2 only (скрыть endpoints)
- Filter by parent group
- Search within level

**Экспорт:**
- PNG с иерархическим layout
- SVG для печати

**Зависимости:**
- Требуется определение levels для узлов
- Поддержка групп (nested nodes)

**Кастомизация:**
- Пользователь может задать `level` через конфиг-файл
- Авто-определение: subnet > host > any

---

### 2.3 Circular (Круговой)

**Цель:** Презентационный вид для демонстрации связности.

**Описание:**
Узлы располагаются по окружности. Рёбра пересекают центр круга. Хорошо показывает полносвязность или изоляцию.

**Данные:**
- Все узлы
- Все рёбра
- Может применяться как overlay на любой topology type

**Визуализация:**
- Layout: custom positioning (x = r*cos(θ), y = r*sin(θ))
- Radius: зависит от количества узлов
- Центр: можно разместить gateway / core switch
- Nodes: равномерно по кругу
- Edges: прямые линии через центр
- Physics: отключена

**Элементы управления:**
- Rotate: кнопка поворота на 90°
- Radius scale: +/-
- Center node selector: выбор центрального узла
- Show/hide edge crossings

**Фильтры:**
- Радиус: показать только узлы в N hops от центра
- Hide orphaned nodes

**Экспорт:**
- PNG: круговой layout
- PDF: презентационный слайд

**Зависимости:**
- Custom layout algorithm (не встроен в Vis.js)
- Требует расчёта координат перед рендерингом

**Кастомизация:**
- Секторы: группировка узлов по зонам в секторы круга
- Concentric circles: узлы разных типов на разных радиусах

---

### 2.4 Risk Heatmap (Тепловая карта рисков)

**Цель:** Быстро найти критичные соединения и узлы.

**Описание:**
Overlay режим, который окрашивает узлы и фон в зависимости от риск-скора. Пользователь видит "горячие точки" инфраструктуры.

**Данные:**
- `node.risk_score` — агрегированный риск узла (max риск всех рёбер)
- `edge.risk_score` — риск конкретного соединения
- `node.critical_ports` — список критичных портов на узле

**Алгоритм окраски:**
```
Риск узла = max(risk всех входящих/исходящих рёбер)
Если node.risk >= 8:    background = красный (#FF0000), glow эффект
Если node.risk >= 5:    background = оранжевый (#FF8C00)
Если node.risk >= 3:    background = жёлтый (#FFD700)
Иначе:                   background = зелёный (#00FF00)
```

**Визуализация:**
- Nodes: background color = risk heat
- Edges: width = risk, color = risk gradient
- Background: Canvas heatmap overlay (Gaussian blur по узлам)
- Legend: градиентная шкала 0-10
- Pulse animation: пульсация для critical (8+) узлов

**Элементы управления:**
- Heatmap intensity: slider 0-100%
- Show only risk > N: checkbox
- Toggle node heat / edge heat / background heat
- Risk metric selector: max / avg / sum
- Time decay: fade старых рисков (если temporal data)

**Фильтры:**
- Show only critical (risk >= 8)
- Show only changed risks (diff)
- Filter by risk category (PCI, CIS, custom)

**Экспорт:**
- PNG: с heatmap overlay
- CSV: список узлов по убыванию риска
- PDF: executive summary (топ-10 рисков)

**Зависимости:**
- Требует risk scoring engine (уже есть)
- Canvas rendering для background heatmap

**Производительность:**
- Heatmap overlay: canvas, WebGL если доступен
- Gaussian blur: pre-calculated, кэшируется

---

### 2.5 Compliance View (Вид соответствия)

**Цель:** Показать соответствие/несоответствие требованиям PCI DSS, CIS, NIST, ISO 27001, SOX.

**Описание:**
Подсветка узлов и рёбер в зависимости от нарушения стандартов. Создаётся compliance overlay на базовом графе.

**Данные:**
- Результаты compliance audit (уже реализовано)
- `node.violations: List[{ standard, control, severity, description }]`
- `edge.violations: List[{ standard, control, severity, description }]`

**Стандарты и цвета:**
| Стандарт | Цвет нарушения | Цвет соответствия |
|----------|---------------|-------------------|
| PCI DSS  | 🔴 Красный | 🟢 Зелёный |
| CIS      | 🟠 Оранжевый | 🟢 Зелёный |
| NIST     | 🟡 Жёлтый | 🟢 Зелёный |
| ISO 27001| 🔵 Синий | 🟢 Зелёный |
| SOX      | 🟣 Фиолетовый | 🟢 Зелёный |

**Визуализация:**
- Nodes: border color = primary violation
- Nodes: badge/overlay = количество нарушений
- Edges: dashed line = нарушение, solid = OK
- Panel: список всех violations при клике
- Filter bar: checkbox per standard

**Элементы управления:**
- Standard selector: PCI / CIS / NIST / ISO / SOX / All
- Severity filter: Critical / High / Medium / Low
- Show compliant nodes: yes/no (обычно скрыть чтобы focus на проблемах)
- Violation detail popup
- Export compliance report

**Фильтры:**
- По стандарту
- По severity
- По control ID (например, PCI 1.1)
- Показать только non-compliant

**Экспорт:**
- HTML compliance report (уже есть)
- PNG: карта с подсветкой violations
- CSV: список violations (node, standard, control, severity, fix)

**Зависимости:**
- Compliance auditor module (уже есть)
- Mapping: правило → standard control

**Кастомизация:**
- Добавление custom standards через JSON config
- Severity weights (настраиваемые)

---

### 2.6 Path Trace (Трассировка пути)

**Цель:** Ответить на вопрос "Может ли хост A достучаться до хоста B?"

**Описание:**
Пользователь выбирает Source и Destination. Система находит все пути (BFS/DFS) и визуализирует их с учётом ACL (accept/deny).

**Данные:**
- Граф доступа (directed)
- ACL rules с action (accept/deny)
- Device per rule (какое устройство блокирует/разрешает)

**Алгоритм:**
```
1. BFS от Source до Destination
2. Для каждого ребра на пути:
   a. Найти правила между этими узлами
   b. Если есть DENY → путь BLOCKED
   c. Если есть ACCEPT → путь ALLOWED
   d. Если нет правил → IMPLICIT DENY
3. Показать все возможные пути с цветами
```

**Визуализация:**
- Path: подсвечен зелёным (allowed) / красным (blocked) / серым (no rule)
- Nodes on path: крупнее, с glow эффектом
- Blocked node: красная пульсация
- Info panel: пошаговая трассировка (hop-by-hop)
- Multiple paths: показать все альтернативы

**Элементы управления:**
- Source input: autocomplete из списка узлов
- Destination input: autocomplete
- Find Path button
- Next/Prev path: если несколько путей
- Show ACL details per hop: выпадающий список правил
- Direction: forward / reverse / bidirectional
- Max hops: slider (2-10)

**Фильтры:**
- Show only allowed paths
- Show only blocked paths (чтобы найти причину)
- Filter by service: только SSH, только HTTP, etc.

**Экспорт:**
- PNG: путь на карте
- Text report: пошаговая трассировка
- JSON: структура путей для автоматизации

**Зависимости:**
- Path finding engine (BFS реализовано)
- ACL resolution per hop

**Производительность:**
- BFS: O(V+E), <1 сек для графа <1000 узлов
- Кэширование: сохранять найденные пути в sessionStorage

---

### 2.7 Diff Mode (Режим сравнения)

**Цель:** Показать изменения между двумя версиями конфигурации.

**Описание:**
Загружаются два графа: "До" и "После". Показываются добавленные, удалённые, изменённые узлы и рёбра.

**Данные:**
- Graph A (old): nodes_A, edges_A
- Graph B (new): nodes_B, edges_B
- Diff result: added, removed, modified

**Визуализация:**
- Added: 🟢 Зелёный узел/ребро, анимация fade-in
- Removed: 🔴 Красный узел/ребро, полупрозрачный, strikethrough
- Modified: 🟡 Жёлтый, badge "changed"
- Unchanged: серый/приглушённый
- Side-by-side view: две карты рядом

**Элементы управления:**
- Left/Right panel: выбор версии (A/B)
- Sync pan: две карты двигаются синхронно
- Show only changes: скрыть unchanged
- Change list: список изменений (click → focus)
- Timeline slider: если >2 версий

**Фильтры:**
- Show only added
- Show only removed
- Show only modified
- Filter by node type
- Filter by change severity

**Экспорт:**
- PNG: side-by-side или overlay
- HTML diff report (уже реализовано)
- JSON: machine-readable diff
- PDF: change summary для менеджмента

**Зависимости:**
- Diff engine (уже есть в main.py)
- Возможность загрузить два графа одновременно

**Кастомизация:**
- 3-way diff: common ancestor + A + B
- Diff rules: ignore whitespace, ignore comments, etc.

---

### 2.8 Service Filter (Фильтр по сервису)

**Цель:** Показать только соединения для конкретного сервиса (например, только SSH или только HTTPS).

**Описание:**
Оверлей на базовый граф. Скрывает все рёбра, не связанные с выбранным сервисом. Показывает зависимости сервиса.

**Данные:**
- `edge.services: List[str]` — список сервисов на ребре (ssh, http, https, sql...)
- `node.services: List[str]` — сервисы, доступные на узле

**Визуализация:**
- Edges: показаны только для выбранного сервиса
- Nodes: окрашены в цвет сервиса (SSH=зелёный, HTTP=синий, DB=оранжевый)
- Isolated nodes: скрыты или серые
- Service icon: иконка на ребре (🔒, 🌐, 🗄️)
- Service legend: цветовая шкала сервисов

**Элементы управления:**
- Service selector: dropdown / chips / multiselect
- Multiselect: показать SSH + HTTPS одновременно
- Show related services: "также показать зависимости"
- Service dependency graph: Web → App → DB
- Port range filter: custom port range

**Фильтры:**
- По протоколу: TCP / UDP / ICMP
- По порту: exact / range
- По direction: inbound / outbound / bidirectional
- By service risk: только критичные сервисы

**Экспорт:**
- PNG: карта сервиса
- CSV: список узлов с этим сервисом
- JSON: service dependency map

**Зависимости:**
- Service extraction from rules (уже есть)
- Service-to-color mapping

**Кастомизация:**
- Custom service definitions (название, порт, цвет)
- Service groups (Web = HTTP+HTTPS, DB = SQL+NoSQL)

---

### 2.9 Temporal (Временная шкала)

**Цель:** Показать, как менялась сеть во времени. Аналитика трендов.

**Описание:**
Граф строится из серии снапшотов (snapshot) конфигураций. Пользователь двигается по времени и видит появление/исчезновение узлов и рёбер.

**Данные:**
- Snapshots: List[{ timestamp, graph }]
- Diff per snapshot: что изменилось
- Time range: from/to

**Визуализация:**
- Timeline slider: внизу экрана
- Play/Pause: анимация изменений
- Speed: 1x, 2x, 5x
- Current date: label над картой
- Fade in/out: анимация появления/исчезновения
- Sparkline: мини-график количества правил за период

**Элементы управления:**
- Date picker: from / to
- Timeline scrubber
- Play / Pause / Step forward / Step backward
- Bookmark: сохранить интересный момент
- Compare with baseline: checkbox
- Time unit: hour / day / week / month

**Фильтры:**
- Show only changes (hide stable)
- Filter by change type (added/removed/modified)
- Filter by author (если есть git blame)
- Filter by device (только изменения на device X)

**Экспорт:**
- Video/GIF: анимация изменений
- PNG series: кадры на каждую дату
- JSON: time series data
- Report: "что изменилось с [date] до [date]"

**Зависимости:**
- Хранение истории конфигураций (git / versioning)
- Diff engine per snapshot

**Кастомизация:**
- Custom events: маркеры (deployment, incident, change)
- Anomaly detection: авто-метка подозрительных изменений

---

### 2.10 Collapsed / Expanded (Свернуто/Развернуто)

**Цель:** Управлять детализацией отображения (агрегация/детализация).

**Описание:**
Не отдельный режим, а поведение внутри других режимов. Позволяет свернуть подсеть в один узел или развернуть его до хостов.

**Данные:**
- Subnet groups: /24, /16, /8
- Hosts inside subnet
- Aggregation rules: when to collapse (threshold)

**Визуализация:**
- Collapsed subnet: один узел, label="192.168.1.0/24 (42 hosts)", size=40
- Expanded: все 42 хоста + subnet node
- Double-click: toggle collapse/expand
- Indicators: "+42" badge на свёрнутом узле
- Nested: возможность сворачивать вложенно

**Элементы управления:**
- Collapse all subnets: button
- Expand all: button
- Auto-collapse: threshold (если >N хостов — свернуть)
- Expand on search: если найденный хост внутри свёрнутой подсети — развернуть
- Remember state: сохранять expanded/collapsed в URL

**Фильтры:**
- Collapse by size: свернуть если > N узлов
- Collapse by zone
- Collapse by VLAN

**Экспорт:**
- PNG: текущее состояние (collapsed или expanded)
- JSON: с агрегированными данными

**Зависимости:**
- Subnet detection (уже есть)
- Hierarchical IP grouping (уже есть)

**Кастомизация:**
- Custom groups: не только подсети, но и по имени, по зоне
- Aggregation functions: count, sum, avg risk

---

## 3. Общие требования

### 3.1 Переключение режимов
- **Без перезагрузки:** переключение < 500ms
- **Сохранение состояния:** позиции узлов, фильтры, zoom/pan
- **URL params:** `?mode=hierarchical&filter=risk&8`
- **Keyboard shortcuts:**
  - `1` — Standard
  - `2` — Hierarchical
  - `3` — Circular
  - `R` — Risk Heatmap
  - `C` — Compliance
  - `P` — Path Trace
  - `D` — Diff
  - `T` — Temporal

### 3.2 UX/UI
- **Mode selector:** dropdown / tabs / toolbar icons
- **Loading indicator:** для тяжёлых режимов (Diff, Temporal)
- **Tutorial:** first-time overlay с подсказками
- **Responsive:** mobile — только Standard + Service Filter
- **Accessibility:** ARIA labels, keyboard navigation, high contrast

### 3.3 Производительность
| Режим | Макс узлов | Время переключения | Требования |
|-------|-----------|-------------------|------------|
| Standard | 2000 | <100ms | — |
| Hierarchical | 1000 | <200ms | Pre-calc levels |
| Circular | 500 | <200ms | Pre-calc coords |
| Risk Heatmap | 1000 | <300ms | Canvas overlay |
| Compliance | 1000 | <200ms | — |
| Path Trace | 1000 | <1s | BFS on demand |
| Diff Mode | 500x2 | <2s | Два графа |
| Service Filter | 2000 | <100ms | — |
| Temporal | 500/series | <500ms | Pre-load diffs |
| Collapsed | 5000 | <100ms | Агрегация |

### 3.4 Состояния и переходы
```
[Initial Load] → Standard (default)
                    ↓
    ┌───────────────┼───────────────┐
    ↓               ↓               ↓
Hierarchical   Risk Heatmap    Path Trace
    ↓               ↓               ↓
Circular      Compliance       Diff Mode
    ↓               ↓               ↓
Service Filter  Temporal      Collapsed
```

### 3.5 API Backend (требования к серверу)
- `POST /api/graph` — получить граф для даты/снапшота
- `POST /api/path` — path trace (BFS на сервере)
- `POST /api/diff` — diff двух снапшотов
- `POST /api/compliance` — compliance check
- `GET /api/timeline` — список доступных дат
- `GET /api/services` — список сервисов

### 3.6 Конфигурация режимов (JSON)
```json
{
  "default_mode": "standard",
  "enabled_modes": ["standard", "hierarchical", "risk", "path", "service"],
  "mode_configs": {
    "hierarchical": {
      "direction": "UD",
      "level_separation": 150,
      "node_spacing": 200
    },
    "risk_heatmap": {
      "intensity": 80,
      "show_background": true,
      "pulse_critical": true
    },
    "path_trace": {
      "max_hops": 10,
      "direction": "forward"
    }
  }
}
```

---

## 4. Приоритеты (MoSCoW)

### Must Have
- Standard (✅ done)
- Hierarchical (✅ done)
- Risk Heatmap
- Path Trace (✅ базовый BFS)
- Service Filter
- Collapsed/Expanded (✅ базовый IP grouping)

### Should Have
- Compliance View (✅ backend ready)
- Diff Mode (✅ backend ready)

### Could Have
- Circular
- Temporal

### Won't Have (v3.0)
- 3D view
- VR/AR
- Real-time animation

---

## 5. Метрики успеха

- Переключение режима < 500ms (95th percentile)
- Path finding < 1s для графа <1000 узлов
- Risk Heatmap render < 300ms
- Zero JS errors при переключении режимов
- 100% keyboard accessibility

---
