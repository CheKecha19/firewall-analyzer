# Task: Firewall Analyzer v4.0

Type: project
Started: 2026-05-16
LastActivity: 2026-05-16
Updated: 2026-05-16
Status: in_progress
StaleAfterDays: 7

## Overview

16 фич в 5 блоках: визуализация (3), security analytics (3), dashboard (1), топологии (7), аналитика/оптимизация (2).

Принципы (Karpathy Guidelines):
- Минимум кода для решения задачи. Никаких спекулятивных абстракций.
- Хирургические правки — только то что нужно, не трогать соседний код.
- Каждый шаг → verify. Пишем тест → заставляем работать.
- Стек: Python 3.9+, NetworkX, Vis.js/Three.js, FastAPI, Jinja2

---

# БЛОК V: Визуализация

## V1 — 3D-граф (Three.js / force-graph-3d)

### V1.1 — Исследование и выбор библиотеки
- Сравнить 3d-force-graph vs ngraph.three vs raw Three.js
- Проверить совместимость с форматом данных NetworkX → JSON
- Проверить размер бандла и производительность на 1000+ узлах
- **Verify:** выбранная библиотека рендерит тестовый граф из 100 узлов без ошибок, бандл < 500KB gzipped

### V1.2 — Базовый 3D-рендерер
- Интеграция библиотеки в HTML-шаблон (CDN или локальный бандл)
- Конвертация текущего nodes/edges JSON в формат 3D-графа
- Базовые настройки: камера (PerspectiveCamera), освещение (ambient + directional)
- OrbitControls для вращения/зума
- **Verify:** `python main.py configs --web` → кнопка "3D" переключает на 3D-вид, граф отображается

### V1.3 — Risk-aware Z-ось
- Z-позиция узла = нормализованный risk_score (0 → z=0, 10 → z=50)
- Цвета узлов: градиент от зелёного (risk=0) до красного (risk=10)
- Размер узла: 3 + risk_score * 2
- **Verify:** критические узлы "всплывают" выше, цвет красный

### V1.4 — Визуальные эффекты
- Glow/свечение на критических рёбрах (risk >= 8)
- Частицы на проблемных соединениях
- Плавные переходы при переключении 2D↔3D
- **Verify:** визуально отличимы критические соединения, нет артефактов

### V1.5 — Интерактивность в 3D
- Hover tooltip: IP, зона, риск (raycasting)
- Click node → панель деталей (как в 2D)
- Подсветка пути при Path Trace в 3D
- **Verify:** клик по узлу в 3D показывает ту же инфо-панель что и в 2D

---

## V2 — Миникарта + анимированный Path Trace

### V2.1 — Minimap-компонент
- Маленькая карта (200×150px) в правом нижнем углу
- Отображает весь граф в уменьшенном масштабе
- Прямоугольник viewport'а — что видно на основном графе
- Drag по minimap двигает основной граф
- **Verify:** minimap отображается, прямоугольник двигается при pan, клик по minimap двигает основной граф

### V2.2 — Анимированный Path Trace
- При клике "Find Path" частица (пульсирующий круг) бежит по найденному пути
- Скорость анимации: ~300ms на hop
- Цвет частицы: зелёный (allowed) / красный (blocked)
- Остановка на blocking node с подсветкой
- **Verify:** визуально видно движение частицы от source до dest, понятно где blocked

### V2.3 — Path Trace Info Panel
- Пошаговый список hop'ов с инфой о каждом
- Для каждого hop: устройство, интерфейс, matched rule, action
- Подсветка текущего hop'а синхронно с анимацией
- **Verify:** панель синхронизирована с анимацией частицы

---

## V3 — Dark/Light Theme Switch + Custom Branding

### V3.1 — Theme System (CSS Variables)
- Вынести все цвета в CSS custom properties (:root)
- Два набора переменных: dark (текущий) и light
- CSS-класс на body для переключения: `<body class="theme-dark">`
- Плавный transition при переключении (0.3s)
- **Verify:** переключение класса body меняет тему без перезагрузки, нет "моргания"

### V3.2 — Theme Toggle Button
- Кнопка в хедере: ☀️/🌙
- Сохранение выбора в localStorage
- Авто-определение при загрузке: localStorage → system preference → dark
- **Verify:** выбор темы сохраняется после F5

### V3.3 — Custom Branding
- JSON-конфиг `branding.json` с цветами, логотипом, заголовком
- Поддержка: primary color, accent, logo URL, title, favicon
- Загрузка через API endpoint `/api/branding`
- **Verify:** изменение branding.json → обновление в UI без правок HTML

---

# БЛОК S: Security Analytics

## S1 — MITRE ATT&CK Mapping

### S1.1 — MITRE ATT&CK Data Model
- JSON/YAML словарь: security finding type → MITRE technique ID
- Пример маппинга: "any-any rule" → T1190, "telnet allowed" → T1021.004, "RDP exposed" → T1021.001
- Загрузка данных из локального файла `data/mitre_mapping.json`
- **Verify:** файл маппинга загружается, парсится без ошибок

### S1.2 — Backend: Match Findings to MITRE
- Новая функция в SecurityAuditor: `map_to_mitre() -> List[MitreMatch]`
- Проходит по всем findings, ищет соответствие в маппинге
- Возвращает: finding + technique_id + technique_name + tactic
- **Verify:** `python main.py configs --mitre` — выводит список матчей

### S1.3 — REST API: MITRE Endpoint
- `GET /api/mitre` — возвращает все матчи
- `GET /api/mitre?technique=T1190` — фильтр по технике
- `GET /api/mitre/matrix` — данные для визуализации матрицы
- **Verify:** curl запросы возвращают валидный JSON

### S1.4 — MITRE ATT&CK Matrix Visualization
- HTML-таблица: строки = тактики (Initial Access, Execution, ...), столбцы = severity count
- Подсвеченные ячейки = есть findings по этой технике
- Клик по ячейке → фильтр findings
- Отдельная вкладка "MITRE" в панели
- **Verify:** матрица отображается в UI, клик по ячейке показывает findings

---

## S2 — Attack Graph / Attack Path Simulation

### S2.1 — Attack Source Detection
- Найти все external-facing узлы (зона Internet/External/Untrusted)
- Для каждого: какие сервисы exposed
- **Verify:** корректно определяется периметр

### S2.2 — Critical Asset Detection
- Найти узлы в зонах Management/Critical/Trusted
- Узлы с критическими портами (DB, DC, Admin)
- **Verify:** критические активы идентифицированы

### S2.3 — Attack Path BFS
- BFS от каждого external узла до всех critical assets
- Учёт ACL (только разрешённые рёбра)
- Ограничение глубины: max 5 hops
- **Verify:** находятся все достижимые извне критические активы

### S2.4 — Attack Graph Visualization
- Новый режим просмотра: "Attack Graph"
- Узлы: external (красный), промежуточные (жёлтый), critical (золотой)
- Рёбра: направленные, подписаны протоколом/портом
- Толщина рёбер = количество эксплуатируемых уязвимостей
- **Verify:** видно пути атаки, понятно какие активы под угрозой

### S2.5 — Dashboard: Attack Path Summary
- На вкладке Dashboard: карточка "Attack Surface"
- Количество: external nodes, exposed services, reachable critical assets
- Максимальная глубина проникновения
- **Verify:** карточка обновляется при переключении на Attack Graph

---

## S3 — Rule Shadowing / Conflict Detection

### S3.1 — Shadowing Detection Algorithm
- Для каждой пары правил на одном устройстве проверить перекрытие по:
  - Source (subset/superset)
  - Destination (subset/superset)
  - Service (subset/superset)
- Если правило A полностью перекрывает правило B и A выше → B shadowed
- **Verify:** алгоритм находит shadowed правила на тестовых данных

### S3.2 — Conflict Detection
- Правила с одинаковым scope (src+dst+svc) но разным action → конфликт
- Правила на разных устройствах с противоречивым action → конфликт
- **Verify:** конфликты детектятся

### S3.3 — Redundancy Detection
- Идентичные правила на разных устройствах → redundancy
- Правило которое полностью перекрыто комбинацией других → redundant
- **Verify:** избыточные правила найдены

### S3.4 — REST API + UI
- `GET /api/rules/shadowed` — shadowed правила
- `GET /api/rules/conflicts` — конфликты
- `GET /api/rules/redundant` — избыточные
- UI: вкладка "Качество" в панели, список проблем сгруппирован по типу
- Оверлей на графе: подсветка проблемных рёбер
- **Verify:** UI показывает проблемы, клик → фокус на графе

---

# БЛОК D: Dashboard

## D1 — Dashboard / Landing Page

### D1.1 — KPI Card Component
- Карточки в верхней части: Security Score (0-100), Rules Health %, Open Risks, Compliance %
- Каждая с трендом (стрелка вверх/вниз + % изменения)
- Цветовая индикация: зелёный (>80), жёлтый (50-80), красный (<50)
- **Verify:** карточки отображаются с реальными данными

### D1.2 — Trend Charts
- График Security Score за последние 30 дней (если есть temporal data)
- Pie chart: распределение правил по action (allow/deny)
- Bar chart: findings по severity
- **Библиотека:** Chart.js (уже используется в некоторых режимах)
- **Verify:** графики отображаются без ошибок JS

### D1.3 — Top-10 Widgets
- Топ-10 рисков (самые опасные правила/узлы)
- Топ изменений за неделю (из diff_temporal)
- Быстрые действия: кнопки "Найти все any-any", "Показать exposed RDP", "Экспорт отчёта"
- **Verify:** виджеты кликабельны, ведут к фильтрации/навигации

### D1.4 — Dashboard как Default View
- При открытии `/` — сначала дашборд
- Кнопка "Открыть граф" → переход к визуализации
- URL-роутинг: `/` = dashboard, `/graph` = граф
- **Verify:** при открытии страницы виден дашборд

---

# БЛОК T: Новые топологии

## T1 — Data Flow Topology

### T1.1 — Flow Classification Engine
- Классификация потоков по портам/протоколам: DB (1433/3306/5432), Web (80/443), File (445/139), Mail (25/587), Auth (389/636)
- Категории данных: PII, финансовые, аутентификационные, публичные, внутренние
- Авто-теггинг рёбер
- **Verify:** рёбра получают корректные теги data_category

### T1.2 — Flow Graph Builder
- Новый класс `DataFlowBuilder` в `src/core/data_flow_topology.py`
- Строит граф: source → processor → storage → consumer
- Определение слоёв: presentation (web), application (app/api), data (db/storage)
- **Verify:** граф строится, слои определены

### T1.3 — Vis.js Visualization
- Новый HTML-шаблон для Data Flow
- Узлы с иконками слоёв (🌐 🖥️ 🗄️)
- Цвета по категории данных
- Легенда с категориями
- **Verify:** вкладка "Data Flow" в режимах отображения

---

## T2 — Trust Boundary Topology

### T2.1 — Trust Boundary Detection
- Определение границ между зонами безопасности
- Классификация рёбер: intra-zone, inter-zone, external
- Определение направления: inbound, outbound, cross-zone
- **Verify:** все рёбра классифицированы

### T2.2 — Perimeter Hole Detection
- Все outside→inside соединения → candidate perimeter holes
- Фильтр: исключить легитимные (известные сервисы)
- Ранжирование по риску
- **Verify:** дыры в периметре найдены и ранжированы

### T2.3 — Trust Boundary Graph
- Новый класс `TrustBoundaryBuilder` в `src/core/trust_boundary_topology.py`
- Узлы = зоны (укрупнённо)
- Рёбра = межзоновые потоки с агрегацией
- **Verify:** граф строится и визуализируется

### T2.4 — UI Integration
- Режим "Trust Boundaries" в тулбаре
- Подсветка perimeter holes красным
- Панель: список дыр с деталями
- **Verify:** переключение режима работает без ошибок

---

## T3 — Redundancy / Resilience Topology

### T3.1 — SPOF Detection
- Для каждого узла и ребра: если удалить → какие сервисы теряют связность?
- Узлы с degree=1 → потенциальный SPOF
- Критические пути без альтернатив → SPOF edge
- **Verify:** SPOF найдены

### T3.2 — Redundancy Scoring
- Для каждой пары (src, dst): количество независимых путей
- R_score = количество путей / критичность соединения
- Шкала: 0 (SPOF) → 10 (N+2 redundancy)
- **Verify:** скор рассчитывается корректно

### T3.3 — Resilience Simulator
- What-If расширение: "что если упадёт узел X?"
- Показать affected services, альтернативные пути
- Визуализация: красный = отвалилось, зелёный = работает
- **Verify:** симуляция показывает affected nodes/edges

### T3.4 — UI
- Новый режим "Resilience"
- Цвет узлов по R_score: красный (SPOF) → зелёный (redundant)
- Панель: топ-10 SPOF с рекомендациями
- **Verify:** режим работает, SPOF видны

---

## T4 — Protocol / Encryption Topology

### T4.1 — Protocol Classifier
- Маппинг порт → протокол → encryption level
- TLS 1.3 (443 с HSTS), TLS 1.2, TLS 1.0/1.1, plaintext (80/21/23/110), неизвестно
- Определение версии: если есть данные из сканера или ручной конфиг
- **Verify:** классификатор выдаёт корректный encryption_level

### T4.2 — Encryption Coverage Scoring
- Процент зашифрованных соединений
- По зонам: отдельно внутри, межзоновые, внешние
- График: покрытие шифрованием
- **Verify:** метрики считаются

### T4.3 — Encryption Topology Graph
- Новый класс `EncryptionTopologyBuilder` в `src/core/encryption_topology.py`
- Рёбра окрашены по encryption level
- Легенда: TLS 1.3 (зелёный), TLS 1.0 (жёлтый), plaintext (красный)
- **Verify:** граф строится, рёбра цветные

---

## T5 — Lateral Movement Topology

### T5.1 — East-West Path Detection
- Фильтр: только рёбра внутри одной зоны (internal → internal)
- Для каждого хоста: все достижимые хосты в пределах зоны
- Протоколы lateral movement: SMB (445), RDP (3389), SSH (22), WMI (135), WinRM (5985/5986)
- **Verify:** east-west пути найдены

### T5.2 — Blast Radius Calculation
- От выбранного хоста: все достижимые в N hops (default: 3)
- Группировка по типу: workstations, servers, DC
- Радиус поражения = количество достижимых критичных хостов
- **Verify:** радиус считается для тестового хоста

### T5.3 — MITRE Lateral Movement Mapping
- Интеграция с S1: матчинг найденных путей на техники MITRE
- T1021.001 (RDP), T1021.002 (SMB), T1021.004 (SSH)
- **Verify:** техники MITRE матчатся на пути

### T5.4 — Lateral Movement Graph
- Новый класс `LateralMovementBuilder` в `src/core/lateral_movement_topology.py`
- Режим "Lateral Movement" в тулбаре
- Визуализация: радиус поражения, критические цели
- **Verify:** режим работает, видно опасные east-west пути

---

## T6 — Micro-segmentation Topology (Zero Trust-ready)

### T6.1 — Intra-zone Connection Analysis
- Внутри каждой зоны: все межхостовые соединения
- Подсчёт: сколько соединений ничем не ограничены
- Группировка по подсетям внутри зоны
- **Verify:** анализ внутризоновых соединений работает

### T6.2 — Micro-segmentation Readiness Score
- Формула: 100 - (незащищённые east-west соединения / общее east-west) * 100
- На зону: отдельный скор для Internal, DMZ, Management
- Рекомендации: «для достижения 80% нужно добавить N deny-правил»
- **Verify:** скор рассчитывается

### T6.3 — Micro-segmentation Policy Generator
- Генерация deny-правил по умолчанию между хостами в зоне
- Правило: разрешить только необходимые сервисы (allowlist)
- Экспорт в формат целевого firewall
- **Verify:** генерируются валидные deny-правила

### T6.4 — UI
- Новый режим "Micro-segmentation"
- Тепловая карта: цвет зоны = readiness score
- Zoom in → появляются микро-правила
- Панель: рекомендации по сегментации
- **Verify:** зум внутрь зоны показывает межхостовые соединения

---

## T7 — Multi-tenancy / VRF Topology

### T7.1 — VRF Detection & Parsing
- Парсинг VRF из конфигов: `ip vrf`, `vrf definition`, `vrf member`
- Парсинг route-target (RT) для import/export
- Определение границ VRF: интерфейсы, привязанные к VRF
- **Verify:** VRF извлекаются из тестовых конфигов

### T7.2 — VRF Leak Detection
- Анализ route-target import/export пересечений
- VRF-A экспортирует RT 100:1, VRF-B импортирует RT 100:1 → controlled leak
- Неожиданные пересечения: разные тенанты имеют общий RT → potential leak
- **Verify:** leaks найдены

### T7.3 — Multi-tenant Isolation Scoring
- На тенанта: Isolation Score = 100 - (leaked routes / total routes) * 100
- Межтенантные соединения → нарушение изоляции
- **Verify:** скор изоляции считается

### T7.4 — VRF Topology Graph
- Новый класс `VRFTopologyBuilder` в `src/core/vrf_topology.py`
- Узлы: VRF-инстансы, сгруппированные по тенантам
- Рёбра: route leaking (RT import/export)
- Цвета: зелёный (изолирован), жёлтый (controlled leak), красный (unexpected leak)
- **Verify:** граф строится, видны утечки

---

# БЛОК A: Аналитика & Оптимизация

## A1 — Rule Optimization Engine

### A1.1 — Rule Grouping Algorithm
- Группировка правил по: source subnet, destination, service
- Поиск правил которые можно объединить (одинаковый action, смежные IP)
- Алгоритм IP-агрегации: смежные подсети → одна более крупная
- **Verify:** алгоритм находит candidates для консолидации

### A1.2 — Optimization Score Calculation
- До: количество правил, complexity score
- После: симулированное количество, complexity score
- Экономия: абсолютная и в процентах
- **Verify:** метрики до/после считаются

### A1.3 — Optimization Preview
- REST API: `POST /api/optimize/preview` → список предлагаемых изменений
- Ответ: original_rule → consolidated_rule, savings
- UI: панель "Оптимизация" с preview до/после
- Кнопка "Экспорт оптимизированных правил"
- **Verify:** preview показывает что изменится, без применения

---

## A2 — Impact Analysis

### A2.1 — Dependency Graph
- Построение обратного графа зависимостей: кто зависит от узла/правила
- Сервис → зависимые хосты, зоны
- Правило → affected flows
- **Verify:** зависимости вычисляются

### A2.2 — Cascading Impact Simulation
- Выбрать узел/правило для удаления/изменения → симуляция
- Затронутые: сервисы, хосты, зоны, бизнес-процессы (если есть mapping)
- Severity: critical (ядро сети), high (критичные сервисы), medium, low
- **Verify:** симуляция показывает каскадные эффекты

### A2.3 — Impact Visualization
- Оверлей на графе: affected nodes подсвечены
- Радиус поражения: градиент от красного (прямое) до жёлтого (каскадное)
- Панель: список affected с группировкой по severity
- **Verify:** визуализация понятно показывает последствия

### A2.4 — Impact Report Export
- Текстовый отчёт: "Impact Analysis Report"
- Секции: Summary, Direct Impact, Cascading Impact, Recommendations
- Экспорт в PDF/Markdown
- **Verify:** отчёт генерируется и содержит все секции

---

# Финальный этап

## F1 — Интеграционное тестирование
- Прогнать все 16 фич на тестовых данных (71 конфиг)
- Проверить что старый функционал не сломан
- Исправить баги
- **Verify:** `python main.py configs --web` запускается без ошибок, все режимы переключаются

## F2 — Git Push
- Commit всех изменений
- Push в https://github.com/CheKecha19/firewall-analyzer
- Тег v4.0.0
- **Verify:** код в репозитории, `git clone` → `pip install -r requirements.txt` → работает

---

## Progress

| # | Step | Status |
|---|------|--------|
| V1.1 | Research 3D library | pending |
| V1.2 | Basic 3D renderer | pending |
| V1.3 | Risk Z-axis | pending |
| V1.4 | Visual effects | pending |
| V1.5 | 3D interactivity | pending |
| V2.1 | Minimap component | pending |
| V2.2 | Animated Path Trace | pending |
| V2.3 | Path Trace Info Panel | pending |
| V3.1 | Theme CSS Variables | pending |
| V3.2 | Theme Toggle Button | pending |
| V3.3 | Custom Branding | pending |
| S1.1 | MITRE Data Model | pending |
| S1.2 | MITRE Matching Backend | pending |
| S1.3 | MITRE REST API | pending |
| S1.4 | MITRE Matrix UI | pending |
| S2.1 | Attack Source Detection | pending |
| S2.2 | Critical Asset Detection | pending |
| S2.3 | Attack Path BFS | pending |
| S2.4 | Attack Graph Viz | pending |
| S2.5 | Attack Dashboard Card | pending |
| S3.1 | Shadowing Detection | pending |
| S3.2 | Conflict Detection | pending |
| S3.3 | Redundancy Detection | pending |
| S3.4 | REST API + UI | pending |
| D1.1 | KPI Cards | pending |
| D1.2 | Trend Charts | pending |
| D1.3 | Top-10 Widgets | pending |
| D1.4 | Dashboard Default View | pending |
| T1.1 | Flow Classification | pending |
| T1.2 | Flow Graph Builder | pending |
| T1.3 | Data Flow Vis.js | pending |
| T2.1 | Trust Boundary Detection | pending |
| T2.2 | Perimeter Hole Detection | pending |
| T2.3 | Trust Boundary Graph | pending |
| T2.4 | Trust Boundary UI | pending |
| T3.1 | SPOF Detection | pending |
| T3.2 | Redundancy Scoring | pending |
| T3.3 | Resilience Simulator | pending |
| T3.4 | Resilience UI | pending |
| T4.1 | Protocol Classifier | pending |
| T4.2 | Encryption Coverage | pending |
| T4.3 | Encryption Topology Graph | pending |
| T5.1 | East-West Path Detection | pending |
| T5.2 | Blast Radius Calc | pending |
| T5.3 | MITRE Lateral Mapping | pending |
| T5.4 | Lateral Movement Graph | pending |
| T6.1 | Intra-zone Analysis | pending |
| T6.2 | Readiness Score | pending |
| T6.3 | Policy Generator | pending |
| T6.4 | Micro-segmentation UI | pending |
| T7.1 | VRF Detection | pending |
| T7.2 | VRF Leak Detection | pending |
| T7.3 | Isolation Scoring | pending |
| T7.4 | VRF Topology Graph | pending |
| A1.1 | Rule Grouping | pending |
| A1.2 | Optimization Score | pending |
| A1.3 | Optimization Preview | pending |
| A2.1 | Dependency Graph | pending |
| A2.2 | Cascading Impact | pending |
| A2.3 | Impact Visualization | pending |
| A2.4 | Impact Report Export | pending |
| F1 | Integration Testing | pending |
| F2 | Git Push | pending |

## Resume Context
- Проект: Firewall Analyzer v4.0 — масштабное обновление
- Стек: Python 3.9+, NetworkX, Vis.js, Three.js/force-graph-3d, Chart.js, FastAPI, Jinja2
- Папка: `firewall-analyzer/`
- 16 фич, 62 подзадачи
- Принципы: Karpathy Guidelines (simplicity first, surgical changes, verify every step)
- Репозиторий: https://github.com/CheKecha19/firewall-analyzer
