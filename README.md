# Firewall Analyzer v4.3

Анализатор конфигураций межсетевых экранов. Парсит правила, строит граф связности, находит дыры в безопасности, визуализирует топологию.

**Поддерживаемые вендоры:** UserGate NGFW, Cisco IOS/ASA/ACL, Juniper JunOS/SRX, Huawei VRP, Aruba Wireless Controller, HP ProCurve.

---

## Быстрый старт

```bash
git clone https://github.com/CheKecha19/firewall-analyzer.git
cd firewall-analyzer
pip install -r requirements.txt

# Базовый запуск — HTML-отчёт
python main.py configs/ --html

# Аудит безопасности
python main.py configs/ --audit --risk-report -v

# Веб-интерфейс (интерактивный анализ)
python main.py configs/ --web --web-open
```

Результаты в `output/`.

---

## Возможности

### 🔍 Парсинг конфигураций

| Вендор | Формат | Статус |
|--------|--------|--------|
| UserGate | JSON-экспорт | ✅ |
| Cisco IOS/ASA | `show running-config` | ✅ |
| Juniper JunOS/SRX | Security policies | ✅ |
| Huawei VRP | `display acl` | ✅ |
| Aruba Wireless | `ip access-list session` | ✅ |
| HP ProCurve | `ip authorized-managers` | ✅ |

### 🛡️ Security Audit (12 проверок)

any-any rules, any-source, any-destination, critical ports to Internet, shadowed rules, insecure protocols, zone violations, wide port ranges, overly permissive, bidirectional rules, redundant rules, logging disabled.

Risk score 1-10 по каждой проблеме, рекомендации по исправлению.

### 📋 Compliance Audit

PCI DSS (4 контроля), CIS Benchmarks (3), NIST CSF (2). ISO 27001 и SOX в процессе.

### 🗺️ Визуализация

**Единый современный интерфейс** (статический HTML = веб-режим):

- **Интерактивный граф связности** — узлы, рёбра, цвета по зонам и рискам
- **Режимы раскладки**: Standard (физика), Hierarchy, Circle, Risk, Attack Graph
- **3D-граф** — Three.js/force-graph-3d, risk-aware Z-ось, OrbitControls, hover/click
- **8 топологий**: Logical, Physical, Zone, Service, Data Flow, Trust Boundaries, Resilience, Encryption, Lateral Movement, Micro-segmentation, VRF
- **Minimap** — навигация по графу с drag
- **Анимированный Path Trace** — accept (зелёный) / deny (красный) / blocked
- **Drill-down по зонам** — double-click → фокус на зону
- **Dark/Light темы** — сохранение в localStorage
- **Кастомный брендинг** — `branding.json`
- **Фильтры**: по зонам, подсетям, рискам
- **Поиск узлов** с debounce
- **Экспорт в JSON**

### 🛡️ Security Analytics

- **MITRE ATT&CK Mapping** — матчинг findings на техники MITRE, интерактивная матрица
- **Attack Graph** — BFS от external узлов до critical assets, визуализация путей атаки
- **Rule Quality** — shadowing, conflicts, redundancy detection, unused rules

### 📊 Dashboard

- **KPI Cards** — Security Score, Rules Health, Open Risks, Compliance, Attack Surface
- **6 графиков** — Score breakdown, Allow/Deny pie, Rules Health bar, Findings by Severity bar, Risk trend, Risk Donut
- **Top-10 рисков**, **быстрые действия**

### 🔧 Оптимизация и аналитика

- **Rule Optimizer** — группировка, консолидация, preview экономии
- **What-If** — симуляция добавления/удаления правил
- **Impact Analysis** — анализ последствий изменений

### 🧪 Диагностические инструменты (CLI)

| Инструмент | Команда |
|------------|---------|
| Path Tracer | `--path-trace --path-source IP --path-dest IP --path-port PORT` |
| What-If | `--what-if --what-if-add "src,dst,port,action"` |
| Config Diff | `--diff-old old.txt --diff-new new.txt` |
| Reachability | `--reachability-check --reachability-source IP --reachability-dest IP` |

---

## Все параметры CLI

```
python main.py <путь> [опции]

ОСНОВНЫЕ:
  -o, --output NAME         Имя выходных файлов
  --output-dir DIR          Папка результатов (output)
  --parallel                Параллельный парсинг
  -v, --verbose             Подробный вывод

БЕЗОПАСНОСТЬ:
  --audit                   Аудит безопасности
  --risk-report             JSON risk report
  --compliance STD          pci_dss | cis | nist | iso27001 | sox | all

ВИЗУАЛИЗАЦИЯ:
  --html                    Интерактивный HTML (современный UI)
  --png                     Статичный PNG (Graphviz)
  --dot                     DOT-файл
  --web                     Веб-интерфейс (FastAPI)
  --web-open                Открыть браузер

ТОПОЛОГИЯ:
  --topology                Physical/L3
  --vlan-view               VLAN
  --zone-view               Зоны безопасности
  --zone-matrix             Матрица зон

ДИАГНОСТИКА:
  --path-trace / --path-source / --path-dest / --path-port
  --what-if / --what-if-add
  --diff-old / --diff-new
  --temporal-view / --temporal-days

ПРОЧЕЕ:
  -s, --source TYPE         usergate | cisco_acl | juniper_acl | huawei_acl
  --version
```

---

## Архитектура

```
firewall-analyzer/
├── main.py                   # Точка входа
├── branding.json             # Брендирование
├── requirements.txt
├── _task.md                  # Roadmap
├── configs/                  # Конфиги для анализа
├── data/                     # Справочные данные (MITRE mapping)
├── output/                   # Результаты
├── research/                 # Исследования (выбор библиотек)
├── src/
│   ├── cli.py                # CLI
│   ├── core/
│   │   ├── analyzer.py       # Ядро: граф (NetworkX)
│   │   ├── resolver.py       # Резолюция объектов UserGate
│   │   ├── security_auditor.py    # 12 проверок безопасности
│   │   ├── compliance_auditor.py  # PCI DSS, CIS, NIST
│   │   ├── rule_optimizer.py      # Оптимизация правил
│   │   ├── rule_quality.py        # Shadowing/conflicts/redundancy
│   │   ├── attack_graph.py        # Attack Graph + BFS
│   │   ├── mitre_mapper.py        # MITRE ATT&CK mapping
│   │   ├── impact_analysis.py     # Impact analysis
│   │   ├── what_if.py             # What-If симуляция
│   │   ├── dashboard.py           # Dashboard data
│   │   ├── path_tracer.py         # Трассировка маршрутов
│   │   ├── config_diff.py         # Сравнение конфигов
│   │   ├── diff_temporal.py       # Временная шкала
│   │   ├── topology_builder.py    # Physical/L3
│   │   ├── vlan_topology.py       # VLAN
│   │   ├── zone_topology.py       # Зоны
│   │   ├── service_topology.py    # Сервисы
│   │   ├── data_flow_topology.py      # Data Flow
│   │   ├── trust_boundary_topology.py # Trust Boundaries
│   │   ├── resilience_topology.py     # Resilience/SPOF
│   │   ├── encryption_topology.py     # Encryption
│   │   ├── lateral_movement_topology.py # Lateral Movement
│   │   ├── microseg_topology.py       # Micro-segmentation
│   │   └── vrf_topology.py            # VRF/Multi-tenancy
│   ├── parsers/
│   │   ├── base_parser.py
│   │   ├── json_parser.py      # UserGate JSON
│   │   ├── acl_parser.py       # Cisco/Juniper/Huawei/Aruba/HP
│   │   └── topology_parser.py
│   ├── graph/
│   │   └── visualizer.py       # HTML-визуализация
│   ├── models/                 # Модели данных
│   ├── api/
│   │   ├── web_ui.py           # FastAPI (33 эндпоинта)
│   │   ├── ui_template.html    # Единый UI-шаблон
│   │   └── rest_api.py         # REST API (альтернативный)
│   └── integrations/           # SIEM (отключено)
└── tests/                      # Тестовые конфиги
```

---

## Статус разработки

| Блок | Описание | Статус |
|------|----------|--------|
| **Core** | Парсинг, граф, аудит, compliance | ✅ v4.3 |
| **V** | 3D-граф, minimap, path trace, темы, брендинг | ✅ v4.3 |
| **S1** | MITRE ATT&CK mapping | ✅ v4.3 |
| **S2** | Attack Graph + BFS | ✅ v4.3 |
| **S3** | Rule Quality (shadowing/conflicts/redundancy) | ✅ v4.3 |
| **D** | Dashboard (KPI, 6 графиков, виджеты) | ✅ v4.3 |
| **T1-T7** | 7 топологий | ✅ v4.3 |
| **A1-A2** | Оптимизатор + Impact/What-If | ✅ v4.3 |
| **Stage 5** | Интеграции (SIEM) | ❌ Отключено |

---

## Требования

- Python 3.10+
- `networkx`, `pandas`, `Pillow`
- Для PNG: [Graphviz](https://graphviz.org/download/) в PATH

```bash
pip install -r requirements.txt
```

---

## Лицензия

MIT
