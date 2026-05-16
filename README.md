# Firewall Analyzer v4.0 — Netopia Pro Edition

Анализатор конфигураций межсетевых экранов. Парсит правила, строит граф связности, находит дыры в безопасности, визуализирует топологию.

**Поддерживает:** UserGate NGFW, Cisco IOS/ASA/ACL, Juniper JunOS/SRX, Huawei VRP.

---

## Как пользоваться — 5 минут

### 1. Установка

```bash
git clone https://github.com/CheKecha19/firewall-analyzer.git
cd firewall-analyzer
pip install -r requirements.txt
```

### 2. Кидаешь конфиги в папку `configs/`

Программа сама определит вендора по содержимому. Поддерживаются:

- UserGate — JSON-экспорт правил
- Cisco — `show running-config`, `show access-list`
- Juniper — конфигурация security policies
- Huawei — VRP ACL

### 3. Базовый запуск — просто карта правил

```bash
python main.py configs/ --html
```

Открываешь `output/firewall_map.html` в браузере — видишь интерактивный граф: кто с кем и по каким портам общается.

### 4. Аудит безопасности — найти проблемы

```bash
python main.py configs/ --audit --risk-report -v
```

В консоли увидишь:

```
[!] any-any правило: правило #7 разрешает 0.0.0.0/0 -> 0.0.0.0/0 (tcp/any)
[!] Критический порт в Internet: SSH (22) открыт для 0.0.0.0/0 из зоны Outside
[!] Скрытое правило: правило #12 никогда не сработает (перекрыто правилом #3)
[!] Небезопасный протокол: Telnet (23) в правиле #15
```

В папке `output/` появится `firewall_map_risk_report.json` с детальным разбором и баллами риска.

### 5. Полный прогон — всё сразу

```bash
python main.py configs/ --parallel --audit --risk-report --html --png --topology --vlan-view --zone-view --zone-matrix -v -o full_report
```

Что получишь:

- `full_report.html` — интерактивный граф правил + топологии
- `full_report.png` — статичная картинка для отчётов
- `full_report_risk_report.json` — JSON с аудитом безопасности
- `full_report_topology.html` — граф физической и L3-топологии
- `full_report_vlan.html` — VLAN-топология
- `full_report_zones.html` — карта зон безопасности
- `full_report_zone_matrix.txt` — матрица межзоновых политик

---

## Типовые сценарии

### 🔍 Я админ, хочу понять что происходит в сети

```bash
python main.py configs/ --html --topology
```

Открой HTML, переключи режим «Граф доступа» → «Топология». Видишь устройства, интерфейсы, связи.

### 🛡️ Я безопасник, ищу уязвимости

```bash
python main.py configs/ --audit --risk-report --compliance --compliance-format html -v
```

Получаешь:
- Список проблемных правил (any-any, Telnet, открытый RDP)
- Баллы риска на каждое соединение
- Комплаенс-отчёт (PCI DSS, CIS, NIST, ISO 27001)

### 📋 Я готовлюсь к аудиту/аттестации

```bash
python main.py configs/ --compliance --compliance-format html -o pci_audit
```

Отчёт `pci_audit_compliance.html` с разбивкой по стандартам. Каждый пункт: пройден/провален с пояснением.

### 🔄 Я менял конфиг, хочу сравнить до/после

```bash
python main.py configs/ --diff-old config_before.txt --diff-new config_after.txt --diff-format html -o diff_report
```

Покажет добавленные, удалённые и изменённые правила.

### 🔗 Не работает доступ — хочу проверить достижимость

```bash
python main.py configs/ --reachability-check --reachability-source 192.168.1.100 --reachability-dest 10.0.50.25 --reachability-port 443
```

Ответит: «Достижим через правило #8» или «Недостижим — нет разрешающего правила».

### 🧪 What-If: а что будет если добавлю правило?

```bash
python main.py configs/ --what-if --what-if-add "192.168.1.0/24,10.0.0.0/24,443,permit"
```

Покажет как изменится граф связности после добавления правила.

### 🗺️ Трассировка маршрута между IP

```bash
python main.py configs/ --path-trace --path-source 192.168.1.100 --path-dest 10.0.0.50 --path-port 443
```

Пошагово покажет путь пакета через фаерволы, зоны и маршруты.

---

## Что умеет HTML-визуализация

Открываешь `.html` в браузере и получаешь:

- **Масштабирование и панорама** — колёсиком и перетаскиванием
- **Два режима**: «Граф доступа» (правила фаервола) ↔ «Топология» (устройства и связи)
- **Раскладки**: стандартная, иерархическая, круговая
- **Фильтр по зонам** — оставить только Inside, DMZ или Outside
- **Фильтр по подсетям** — показать конкретный сегмент
- **Цвета по риску** — красные рёбра = опасные соединения
- **Поиск пути** — выбираешь источник и назначение → подсвечивается маршрут
- **Клик по правилу** — подсвечиваются связанные рёбра
- **Тёмная тема** — глаза не выжигает
- **Экспорт в PNG** — кнопка для скриншота
- **Русский интерфейс** — все надписи на русском

---

## Все параметры командной строки

```
python main.py <путь к конфигам> [опции]

ОСНОВНЫЕ:
  -o, --output NAME       Имя выходных файлов (по умолчанию: firewall_map)
  --output-dir DIR        Папка для результатов (по умолчанию: output)
  --parallel              Параллельный парсинг (быстрее на больших объёмах)
  --aggregate-subnets     Схлопнуть /32 хосты в /24 подсети
  -v, --verbose           Подробный лог в консоль

БЕЗОПАСНОСТЬ:
  --audit                 Аудит безопасности правил
  --risk-report           JSON-отчёт с баллами риска
  --compliance            Комплаенс-аудит (PCI DSS, CIS, NIST, ISO 27001)
  --compliance-format FMT text | json | html

ТОПОЛОГИЯ:
  --topology              Физическая и L3 топология
  --vlan-view             VLAN-топология
  --zone-view             Карта зон безопасности
  --zone-matrix           Матрица межзоновых политик

СРАВНЕНИЕ:
  --diff-old FILE         Старая версия конфига
  --diff-new FILE         Новая версия конфига
  --diff-format FMT       text | json | html

ДИАГНОСТИКА:
  --reachability-check    Проверить связность между IP
  --reachability-source IP
  --reachability-dest IP
  --reachability-port N
  --reachability-proto P  tcp | udp | icmp
  --path-trace            Трассировка маршрута
  --path-source IP
  --path-dest IP
  --path-port N
  --what-if               What-If анализ
  --what-if-add RULE      "src,dst,port,action"

ВИЗУАЛИЗАЦИЯ:
  --html                  Интерактивный HTML
  --png                   Статичный PNG
  --dot                   DOT-файл для Graphviz

ПРОЧЕЕ:
  -s, --source TYPE       auto | usergate | cisco_acl | juniper_acl
  --no-recursive          Не ходить в подпапки
  --version               Версия программы
```

---

## Что проверяет аудит безопасности

| Проверка | Серьёзность | Что значит |
|----------|-------------|------------|
| `any_any_rule` | 🔴 Критическая | Правило any→any — открыто вообще всё |
| `any_source_rule` | 🟠 Высокая | Источник any — пускаем кого угодно |
| `any_destination_rule` | 🟠 Высокая | Назначение any — доступ ко всем хостам |
| `critical_to_internet` | 🟠 Высокая | SSH/RDP/SNMP открыты в 0.0.0.0/0 |
| `zone_violation` | 🟠 Высокая | Доступ между несовместимыми зонами (outside→inside) |
| `shadowed_rule` | 🟡 Средняя | Правило никогда не сработает — перекрыто выше |
| `insecure_protocol` | 🟡 Средняя | Telnet, FTP, HTTP — передача в открытом виде |
| `wide_port_range` | 🟡 Средняя | Диапазон портов >1000 — слишком широко |
| `disabled_logging` | 🔵 Низкая | Логирование выключено — не видно кто ходит |

---

## Архитектура проекта

```
firewall-analyzer/
├── main.py                    # Точка входа
├── src/
│   ├── cli.py                 # CLI-аргументы
│   ├── core/
│   │   ├── analyzer.py        # Ядро: парсинг + построение графа
│   │   ├── security_auditor.py
│   │   ├── compliance_auditor.py
│   │   ├── config_diff.py
│   │   ├── reachability_checker.py
│   │   ├── topology_builder.py
│   │   ├── path_tracer.py
│   │   ├── what_if.py
│   │   └── temporal_view.py
│   ├── parsers/
│   │   ├── base_parser.py
│   │   ├── json_parser.py     # UserGate JSON
│   │   ├── acl_parser.py      # Cisco/Huawei ACL
│   │   └── topology_parser.py
│   ├── graph/
│   │   └── visualizer.py      # HTML/PNG визуализация
│   ├── models/                # Модели: rule, endpoint, device, vlan, route...
│   └── integrations/          # REST API, CI/CD, SIEM (⏸ отключено)
├── configs/                   # ← Кидай конфиги сюда
└── output/                    # ← Здесь результаты
```

---

## Статус этапов

| Этап | Статус | Что сделано |
|------|--------|-------------|
| 1 | ✅ | Базовая визуализация, русская локализация, JS-фиксы |
| 2 | ✅ | Физическая и L3-топология, интерфейсы, маршруты |
| 3 | ✅ | VLAN-топология, зоны безопасности, матрица зон |
| 4 | ✅ | Path Tracer, What-If анализ, временная шкала |
| 5 | ⏸ | Интеграции (REST API, CI/CD, SIEM) — отключено |

---

## Требования

- Python 3.10+
- `networkx`, `pandas`, `pyvis`, `Pillow`

```bash
pip install -r requirements.txt
```

---

## Лицензия

MIT — делай что хочешь.
