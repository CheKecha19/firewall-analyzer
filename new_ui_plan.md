# План: статический HTML на базе ui_template.html

## Проблема

`main.py --html` генерирует простой HTML через `visualizer._generate_full_html()` — минимальный шаблон с vis-network, без сайдбара, дашбордов, топологий.

Веб-интерфейс (`main.py --web` → `ui_template.html`) — красивый современный UI с:
- Сайдбаром (вкладки: Rules, Audit, Dashboard, Impact, Attack Graph, MITRE, Quality, Optimizer)
- Специализированными топологиями (Data Flow, Trust Boundary, Resilience, Encryption, Lateral Movement, Micro-seg, VRF)
- Тёмной/светлой темой
- Дашбордом с KPI, трендами
- MITRE ATT&CK маппингом
- Impact analysis
- Rule optimizer
- 3D-графом (Three.js)
- Контекстным меню, drill-down по зонам

Нужно: `main.py --html` должен генерировать **тот же** красивый HTML что и веб-интерфейс, но статически (данные вшиты, без API-сервера).

---

## Что нужно сделать

### 1. Собрать полные данные (backend, `visualizer.py`)

Метод `generate_html()` сейчас собирает: nodes, edges, rules, sankey, zone_matrix, services, risk_severity, hilbert.

Нужно добавить сбор:
- ✅ nodes/edges — уже есть
- ✅ rules — уже есть (только 100, нужно все)
- ✅ sankey — уже есть
- ✅ zone_matrix — уже есть
- ✅ services — уже есть
- ✅ risk_severity — уже есть
- ✅ hilbert — уже есть
- ❌ audit_issues — через `SecurityAuditor`
- ❌ attack_graph — через `AttackGraphBuilder`
- ❌ dashboard — через `get_dashboard_json()` (KPI, тренды)
- ❌ mitre_matrix — через `MitreMapper`
- ❌ rule_quality — через `RuleQualityAnalyzer`
- ❌ topology_data_flow — через `analyze_data_flow()`
- ❌ topology_trust_boundary — через `analyze_trust_boundary()`
- ❌ topology_resilience — через `analyze_resilience()`
- ❌ topology_encryption — через `analyze_encryption()`
- ❌ topology_lateral_movement — через `analyze_lateral_movement()`
- ❌ topology_microseg — через `analyze_microseg()`
- ❌ topology_vrf — через `analyze_vrf()`
- ❌ optimizer_preview — через `RuleOptimizer`
- ❌ branding — из `branding.json`

### 2. Заменить API-запросы на вшитые данные (frontend)

В `ui_template.html` есть 16 `fetch()` вызовов к `/api/*`. Все их нужно превратить во вшитые JSON-переменные:

```
/api/dashboard      → embeddedDashboard = {...}
/api/sankey         → embeddedSankey = {...}
/api/zone-matrix    → embeddedZoneMatrix = {...}
/api/services       → embeddedServices = [...]
/api/risk-severity  → embeddedRiskSeverity = [...]
/api/hilbert        → embeddedHilbert = {...}
/api/mitre/matrix   → embeddedMitreMatrix = {...}
/api/rules/quality  → embeddedRulesQuality = {...}
/api/attack-graph   → embeddedAttackGraph = {...}
/api/impact/*       → убрать (нужен работающий сервер для pathfinding)
/api/optimize/*     → убрать или заменить на статический preview
/api/siem/export    → убрать (нужен работающий сервер)
```

Варианты реализации замены:
- **Вариант A (простой):** создать метод `_generate_ui_html()` который читает `ui_template.html`, вставляет `<script>` с embedded-данными перед закрывающим `</body>`, и модифицирует все fetch-функции чтобы сначала проверять embedded-данные.
- **Вариант B (грязный):** string-замена fetch-вызовов прямо в HTML.
- **Вариант C (чистый):** создать копию `ui_template.html` → `static_template.html` где все fetch заменены на embedded data.

**Рекомендую Вариант A** — минимальные изменения ui_template.html.

### 3. Модифицировать `main.py`

Заменить вызов `visualizer.generate_html()` на `visualizer.generate_ui_html()` с передачей всех данных.

### 4. Обработать неработающие фичи

Некоторые фичи **не могут** работать статически без сервера:
- **Impact Analysis** — требует вычисления путей на сервере. Можно заменить на BFS в JS (уже есть `findPath()` в текущем статическом HTML).
- **Rule Optimizer** — требует серверной логики. Можно заменить на статический preview (показать потенциальную экономию без реального выполнения).
- **SIEM Export** — требует сервер. Просто скрыть кнопку.

### 5. Итоговый список файлов для изменения

| Файл | Изменение |
|------|-----------|
| `src/graph/visualizer.py` | Добавить `generate_ui_html()` — сбор всех данных + вставка в шаблон |
| `src/api/ui_template.html` | (опционально) добавить поддержку embedded data через `if (!embedded) fetch()` |
| `main.py` | Вызывать `visualizer.generate_ui_html()` вместо `generate_html()` при `--html` |

---

## Приоритеты

1. **P0 (критично):** Базовые данные — graph, rules, audit, zones, sankey, matrix, services, risks, hilbert
2. **P1 (важно):** Dashboard, MITRE, Quality, Attack Graph
3. **P2 (желательно):** Топологии (Data Flow, Trust Boundary, etc.)
4. **P3 (опционально):** Optimizer preview, брендинг

---

## Оценка

- P0: ~2 часа
- P0+P1: ~4 часа
- Полный набор: ~6-8 часов
