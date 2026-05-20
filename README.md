# Firewall Analyzer v2.0

Анализатор конфигураций межсетевых экранов. Парсит правила, строит граф связности, находит дыры в безопасности, визуализирует топологию.

**Поддерживаемые вендоры:** UserGate NGFW, Cisco IOS/ASA/ACL, Juniper JunOS/SRX, Huawei VRP, Aruba Wireless Controller (ip access-list session).

---

## Быстрый старт

```bash
# 1. Установка
git clone https://github.com/CheKecha19/firewall-analyzer.git
cd firewall-analyzer
pip install -r requirements.txt

# 2. Кидаешь конфиги в configs/

# 3. Базовый запуск — карта правил
python main.py configs/ --html

# 4. Аудит безопасности
python main.py configs/ --audit --risk-report -v

# 5. Полный прогон — всё сразу
python main.py configs/ --parallel --audit --risk-report --html --png --topology --vlan-view --zone-view --zone-matrix -v -o full_report

# 6. Веб-интерфейс для интерактивного анализа
python main.py configs/ --web --web-open
```

Результаты в папке `output/`.

---

## Возможности: что программа умеет проверять

### 🔍 Парсинг конфигураций

| Вендор | Формат | Что парсим | Статус |
|--------|--------|-----------|--------|
| **UserGate** | JSON-экспорт | Правила МЭ, зоны, группы, сервисы | ✅ |
| **Cisco IOS/ASA** | `show running-config` | ACL, object-group, интерфейсы, маршруты | ✅ |
| **Juniper JunOS** | Конфигурация security | Security policies, zones, address-book | ✅ |
| **Huawei VRP** | `display acl` | ACL numbered/named, интерфейсы, маршруты | ✅ |
| **Aruba Wireless Controller** | `show running-config` | `ip access-list session`, netservice, netdestination, user-role | ✅ |
| **HP ProCurve** | `show running-config` | `ip authorized-managers` | ✅ |

### 🛡️ Security Audit — Аудит безопасности (12 проверок)

| # | Проверка | Severity | Что ищет |
|---|----------|----------|----------|
| 1 | **any-any rules** | 🔴 Critical | Правила `any → any` — открыто вообще всё (risk=10) |
| 2 | **any-source rules** | 🟠 High | Источник `any` — пускаем любого |
| 3 | **any-destination rules** | 🟠 High | Назначение `any` — доступ ко всем хостам |
| 4 | **critical ports to Internet** | 🔴 Critical | SSH(22), RDP(3389), SNMP(161), SMB(445), БД открыты извне (risk=9) |
| 5 | **shadowed rules** | 🟡 Medium | Правило перекрыто более широким правилом выше |
| 6 | **insecure protocols** | 🟡 Medium | Telnet, FTP, HTTP, POP3, IMAP, SNMP — передача открытым текстом (risk=5) |
| 7 | **zone violations** | 🟠 High | Доступ между несовместимыми зонами (Internet → Trusted, DMZ → Management) (risk=8) |
| 8 | **wide port ranges** | 🟠 High | Диапазон портов >1000 — слишком широко (risk=7) |
| 9 | **overly permissive** | 🟡 Medium | >10 источников и >10 назначений в одном правиле (risk=5) |
| 10 | **bidirectional rules** | 🟡 Medium | Source и Destination пересекаются — риск lateral movement (risk=5) |
| 11 | **redundant rules** | 🔵 Low | Полные дубликаты — мусор в конфиге (risk=2) |
| 12 | **logging disabled** | 🔵 Low | Нет логирования на правиле — не видно кто ходит (risk=3) |

По каждой проверке: описание проблемы, affected rules, risk score (1-10), рекомендации по исправлению.

### 📋 Compliance Audit — Комплаенс-аудит

| Стандарт | Контролей | Что проверяет |
|----------|-----------|---------------|
| **PCI DSS** | 4 контроля | PCI-DSS-1.1 (Default Deny), 1.2 (Inbound Restriction), 1.3 (Mgmt from Internet), 1.4 (DB Exposure) |
| **CIS Benchmarks** | 3 контроля | CIS-3.1 (Unused Rules), 3.2 (Logging), 3.3 (Mgmt Network) |
| **NIST CSF** | 2 контроля | PR.AC-3 (Remote Access), PR.AC-5 (Network Integrity) |
| **ISO 27001** | ⏸ в процессе | |
| **SOX** | ⏸ в процессе | |

Форматы отчётов: text, json, html. Для каждого стандарта — compliance score (0-100%).

### 🗺️ Визуализация (HTML-интерфейс)

- **Интерактивный граф связности** — 357 узлов, 780 рёбер на wifi-конфиге
- **Два режима**: «Граф доступа» (правила) ↔ «Топология» (устройства/интерфейсы)
- **Раскладки**: стандартная (физика), иерархическая, круговая
- **Фильтры**: по зонам, подсетям, severity
- **Цвета по риску**: градиент зелёный→красный (risk_score 0→10)
- **Поиск пути** (Path Trace): выбираешь source/dest → подсвечивается маршрут
- **Клик по правилу** → подсветка связанных рёбер + панель деталей
- **Экспорт в PNG** одной кнопкой
- **Русский интерфейс**

### 🧪 Диагностические инструменты

| Инструмент | Что делает | Команда |
|------------|-----------|---------|
| **Path Tracer** | Трассировка пакета через все фаерволы с проверкой ACL | `--path-trace --path-source 10.0.0.1 --path-dest 10.0.1.1 --path-port 443` |
| **What-If** | Симуляция: «а что если добавить/удалить правило?» | `--what-if --what-if-add "src,dst,port,action"` |
| **Config Diff** | Сравнение конфигов до/после изменения | `--diff-old old.txt --diff-new new.txt` |
| **Temporal View** | Временная шкала изменений (требует снапшотов) | `--temporal-view --temporal-days 90` |
| **Reachability Check** | Проверка связности между двумя IP | `--reachability-check --reachability-source IP --reachability-dest IP --reachability-port N` |

### 📊 Дополнительные топологии

| Топология | Что показывает | Команда |
|-----------|----------------|---------|
| **Physical/L3** | Устройства, интерфейсы, маршруты | `--topology` |
| **VLAN** | VLAN'ы, trunk/access-порты, native VLAN | `--vlan-view` |
| **Security Zones** | Зоны безопасности, межзоновые политики | `--zone-view` |
| **Zone Matrix** | Матрица «кто-кому-что разрешено» между зонами | `--zone-matrix` |
| **Services** | Сервисная топология (кто какой сервис потребляет) | `--svc-view` |

---

## Типовые сценарии

### 🔍 Хочу понять, что происходит в сети

```bash
python main.py configs/ --html --topology
```

### 🛡️ Ищу уязвимости и готовлю отчёт для руководства

```bash
python main.py configs/ --audit --risk-report --compliance --compliance-format html -v
```

Получаешь:
- Список проблем с баллами риска
- JSON risk report для автоматизации
- Комплаенс-отчёт в HTML

### 📋 Готовлюсь к аудиту/аттестации PCI DSS

```bash
python main.py configs/ --compliance pci_dss --compliance-format html -o pci_audit
```

### 🔄 Менял конфиг, хочу сравнить до/после

```bash
python main.py configs/ --diff-old config_before.txt --diff-new config_after.txt --diff-format html
```

### 🔗 Не работает доступ — проверяю достижимость

```bash
python main.py configs/ --path-trace --path-source 192.168.1.100 --path-dest 10.0.0.50 --path-port 443
```

### 🧪 What-If: а что будет если добавлю правило?

```bash
python main.py configs/ --what-if --what-if-add "192.168.1.0/24,10.0.0.0/24,443,permit"
```

### 🖥️ Интерактивный анализ через веб

```bash
python main.py configs/ --web --web-open
```

---

## Все параметры CLI

```
python main.py <путь> [опции]

ОСНОВНЫЕ:
  -o, --output NAME         Имя выходных файлов (firewall_map)
  --output-dir DIR          Папка результатов (output)
  --parallel                Параллельный парсинг
  --aggregate-subnets       Схлопнуть /32 в /24
  -v, --verbose             Подробный вывод

БЕЗОПАСНОСТЬ:
  --audit                   Аудит безопасности (12 проверок)
  --risk-report             JSON risk report
  --compliance STD          pci_dss | cis | nist | iso27001 | sox | all
  --compliance-format FMT   text | json | html

ТОПОЛОГИЯ:
  --topology                Physical/L3 топология
  --vlan-view               VLAN топология
  --zone-view               Зоны безопасности
  --zone-matrix             Матрица межзоновых политик
  --svc-view                Сервисная топология

СРАВНЕНИЕ И ДИАГНОСТИКА:
  --diff-old/--diff-new     Сравнение конфигов
  --diff-format FMT         text | json | html
  --path-trace              Трассировка маршрута
  --path-source/--path-dest/--path-port
  --what-if                 What-If анализ
  --what-if-add RULE        "src,dst,port,action"
  --temporal-view           Временная шкала изменений
  --temporal-days N         Глубина истории (30)

ВИЗУАЛИЗАЦИЯ:
  --html                    Интерактивный HTML (Vis.js)
  --png                     Статичный PNG (Graphviz)
  --dot                     DOT-файл для Graphviz
  --pdf                     PDF с графом
  --web                     Запустить веб-интерфейс
  --web-open                Открыть браузер автоматически

ПРОЧЕЕ:
  -s, --source TYPE         auto | usergate | cisco_acl | juniper_acl | huawei_acl
  --no-recursive            Не обходить подпапки
  --version                 Версия
```

---

## Архитектура проекта

```
firewall-analyzer/
├── main.py                     # Точка входа
├── branding.json               # Брендирование (лого, цвета)
├── requirements.txt
├── README.md
├── _task.md                    # Roadmap и бэклог
├── configs/                    # ← Конфиги для анализа
├── data/                       # ← Справочные данные (MITRE mapping и т.д.)
├── output/                     # ← Результаты
├── src/
│   ├── cli.py                  # CLI-аргументы
│   ├── core/
│   │   ├── analyzer.py         # Ядро: парсинг + построение графа (NetworkX)
│   │   ├── security_auditor.py # Security audit (12 проверок)
│   │   ├── compliance_auditor.py  # PCI DSS / CIS / NIST compliance
│   │   ├── config_diff.py      # Сравнение конфигов
│   │   ├── reachability_checker.py
│   │   ├── topology_builder.py # Physical/L3 топология
│   │   ├── path_tracer.py      # Трассировка маршрутов
│   │   ├── what_if.py          # Симуляция изменений
│   │   ├── diff_temporal.py    # Временная шкала
│   │   ├── vlan_topology.py    # VLAN топология
│   │   ├── zone_topology.py    # Зональная топология
│   │   └── service_topology.py # Сервисная топология
│   ├── parsers/
│   │   ├── base_parser.py      # Абстрактный базовый класс
│   │   ├── json_parser.py      # UserGate JSON
│   │   ├── acl_parser.py       # Cisco / Juniper / Huawei / Aruba / HP
│   │   └── topology_parser.py  # Парсинг интерфейсов и маршрутов
│   ├── graph/
│   │   ├── visualizer.py       # HTML/PNG визуализация (pyvis + graphviz)
│   │   └── templates/          # HTML-шаблоны
│   ├── models/                 # FirewallRule, Endpoint, Service, Interface, Route, VLAN...
│   ├── api/                    # ⏸ REST API (FastAPI)
│   └── integrations/           # ⏸ CI/CD, SIEM-экспорт
├── tests/                      # Тесты
└── docs/                       # Документация
```

---

## Статус этапов

| Этап | Статус | Описание |
|------|--------|----------|
| **Stage 1** | ✅ | Базовая визуализация, парсинг, русская локализация |
| **Stage 2** | ✅ | Physical/L3 топология, интерфейсы, маршруты |
| **Stage 3** | ✅ | VLAN, зоны безопасности, зональная матрица, сервисная топология |
| **Stage 4** | ✅ | Path Tracer, What-If, Temporal View (диагностика + симуляция) |
| **Stage 5** | ⏸ | Интеграции: REST API, CI/CD, SIEM — отключено |
| **Блок V** | 📋 Roadmap | 3D-граф (Three.js), миникарта, анимированный Path Trace, тёмная/светлая тема |
| **Блок S** | 📋 Roadmap | MITRE ATT&CK mapping, Attack Graph, Rule Conflict Detection |
| **Блок D** | 📋 Roadmap | Dashboard с KPI, трендами, топ-10 рисков |
| **Блок T** | 📋 Roadmap | 7 новых топологий: Data Flow, Trust Boundaries, Resilience, Encryption, Lateral Movement, Micro-segmentation, VRF |
| **Блок A** | 📋 Roadmap | Rule Optimization Engine, AI-Powered Recommendations |

---

## Пример вывода security audit

```
============================================================
SECURITY AUDIT REPORT
============================================================
Rules analyzed:     1578
Issues found:       6442
  Critical:         147
  High:             993
  Medium:           2787
  Low:              2515
Avg risk score:     3.3/10
============================================================

TOP ISSUES:
[!!] any_any_rule: FreshCafe-Users-2_r32
    Rule allows traffic from any to any
    Risk: 10/10
[!!] any_any_rule: cu-mm-computers_r0
    Rule allows traffic from any to any
    Risk: 10/10
[!] any_source_rule: Quarantine_r1
    Rule allows traffic from any source
    Risk: 7/10
[*] insecure_protocol: legacy_r45
    Rule allows insecure protocols: telnet, ftp
    Risk: 5/10
```

---

## Требования

- Python 3.10+
- `networkx`, `pandas`, `pyvis`, `Pillow`
- Для PNG: [Graphviz](https://graphviz.org/download/) в PATH

```bash
pip install -r requirements.txt
```

---

## Лицензия

MIT
