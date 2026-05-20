# ТЗ v4.4 — Исправление багов и доработка UI

Составлено: 2026-05-20 | Статус: план

---

## Корневая проблема

Статический HTML генерируется из `ui_template.html` (единый шаблон), но шаблон содержит **19 вызовов `fetch()`** к API-эндпоинтам. В статическом режиме сервера нет → все данные должны инжектироваться на этапе генерации.

**Решение:** `visualizer.py` должен инжектить ВСЕ данные в HTML на этапе генерации, а JS должен уметь работать с предзагруженными данными БЕЗ `fetch()`. Добавить флаг `window.STATIC_MODE = true` и обернуть все `fetch()`-вызовы в проверку этого флага.

---

## Баги и план устранения

### 1. «Курсор залипает» после клика на карту

**Причина:** `physics` в vis-network не отключается после ручного перемещения узла. Нода «приклеивается» к курсору.

**План:**
- Добавить `interaction: { dragNodes: true }` и обработчик `dragEnd` → перезапуск стабилизации на 1 сек
- Добавить настройку «Физика» с переключателем on/off
- При выключенной физике — узлы не двигаются при клике

**Файлы:** `ui_template.html` → `initNetwork()`

**Сложность:** низкая | **Время:** ~30 мин

---

### 2. Кнопка настроек (вместо только физики)

**Причина:** Нужна отдельная панель настроек для управления визуализацией.

**План:**
- Добавить кнопку ⚙️ в тулбар
- Панель настроек (popup/sidebar):
  - **Физика:** on/off + сила гравитации (слайдер)
  - **Тема:** dark/light переключатель
  - **Размер узлов:** множитель (слайдер 0.5x–3x)
  - **Показывать метки:** всегда / при наведении / никогда
  - **Сброс к дефолту**

**Файлы:** `ui_template.html` → новый блок CSS + JS

**Сложность:** средняя | **Время:** ~1 час

---

### 3. Переключение режимов Standard/Hierarchy/Circle/Risk/Attack

**Причина:** `setMode()` вызывает `network.setOptions()` с новыми physics/layout, но vis-network может игнорировать изменения без пересоздания сети.

**План:**
- Проверить `setMode()` — убедиться что `network.setOptions()` действительно применяется
- Для hierarchy: `layout.hierarchical.enabled = true`, `physics.solver = 'hierarchicalRepulsion'`
- Для circle: использовать `network.stabilize()` после смены физики
- Убедиться что кнопки имеют `data-mode` атрибуты и `setMode()` корректно их переключает
- Добавить `network.redraw()` после `setOptions()`

**Файлы:** `ui_template.html` → `setMode()`

**Сложность:** низкая | **Время:** ~30 мин

---

### 4. Переключение 2D ↔ 3D

**Причина:** `toggle3D()` скрывает vis-network canvas и показывает `#graph3d`, но при возврате в 2D canvas мог быть разрушен или vis-network теряет контекст.

**План:**
- В `toggle3D()` при возврате в 2D:
  - Показать vis-network canvas: `canvasEl.style.display = 'block'`
  - `nd.style.pointerEvents = 'auto'`
  - `network.redraw()` + `renderMinimap()`
  - Очистить 3D-контейнер полностью
- По умолчанию сделать 2D (убрать is3D=true по дефолту)
- Добавить проверку что `ForceGraph3D` загружен до вызова

**Файлы:** `ui_template.html` → `toggle3D()`, `init3DGraph()`

**Сложность:** средняя | **Время:** ~45 мин

---

### 5. Экспорт PNG и удаление SIEM

**Экспорт PNG не работает:**
**Причина:** Старый экспорт использовал `network.canvas.toDataURL()`, но vis-network может не иметь canvas напрямую.

**План:**
- Использовать `html2canvas` (CDN) для скриншота всего `#mynetwork`
- ИЛИ использовать vis-network встроенный метод (если есть)
- Код:
```javascript
function exportPNG() {
  html2canvas(document.getElementById('mynetwork')).then(function(canvas) {
    var link = document.createElement('a');
    link.download = 'firewall_map.png';
    link.href = canvas.toDataURL();
    link.click();
  });
}
```
- CDN: `<script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"></script>`

**Удаление SIEM:**
- Убрать кнопку SIEM-экспорта из UI
- Убрать `siemExport()` функцию из JS
- Убрать `/api/siem/export` из `web_ui.py` (или оставить как есть, только UI убрать)
- Удалить файлы в `output/archive/`

**Файлы:** `ui_template.html`, `web_ui.py`

**Сложность:** низкая | **Время:** ~30 мин

---

### 6. Топологии не работают (Data Flow, Trust, Resilience, Encryption, Lateral, MicroSeg, VRF)

**Причина:** Все топологии вызывают `fetch(url)` к API, которого нет в статическом HTML. В веб-режиме тоже может не работать, если модули возвращают пустые данные для тестовых конфигов.

**План:**
- Шаг 1: Проверить каждый модуль топологии, запустив его отдельно:
  ```python
  from src.core.analyzer import FirewallAnalyzer
  a = FirewallAnalyzer(['tests/'])
  a.analyze()
  from src.core.data_flow_topology import DataFlowBuilder
  df = DataFlowBuilder(a.graph, a.rules)
  print(df.analyze_data_flow())
  ```
- Шаг 2: Если модуль работает → проверить эндпоинт `/api/topology/*` в веб-режиме
- Шаг 3: Для статического режима — инжектить топологии как JSON в HTML и обойти fetch()
- Шаг 4: Починить конкретные баги в каждом модуле (пустые данные, ошибки импорта)

**Файлы:** `src/core/*_topology.py`, `web_ui.py`, `visualizer.py`, `ui_template.html`

**Сложность:** высокая (7 модулей) | **Время:** ~3-4 часа

---

### 7. Счётчик nodes/edges/rules/issues

**Причина:** `updateStats()` не вызывается после загрузки данных, или данные не доходят до счётчиков.

**План:**
- `updateStats()` должен читать `allNodes.length`, `allEdges.length`, `allRules.length`, `allAudit.length`
- Проверить что элемент `#stats-bar` существует в HTML
- Вызывать `updateStats()` после загрузки данных (в `DOMContentLoaded`)
- Формат: `Nodes: N | Edges: N | Rules: N | Issues: N`

**Файлы:** `ui_template.html` → `updateStats()`

**Сложность:** низкая | **Время:** ~15 мин

---

### 8. Дашборд — «TypeError: Failed to fetch»

**Причина:** `loadDashboard()` вызывает `fetch('/api/dashboard')`. В статическом HTML сервера нет.

**План:**
- В статическом режиме: `visualizer.py` должен инжектить `__DASHBOARD_JSON__` (как другие данные)
- `loadDashboard()` проверяет `window.STATIC_MODE`:
  - Если true → `renderDashboard(window.__DASHBOARD_DATA__)`
  - Если false → `fetch('/api/dashboard')`
- Dashboard данные генерировать в `visualizer.py` через `src/core/dashboard.py`

**Файлы:** `visualizer.py`, `ui_template.html`, `web_ui.py`

**Сложность:** средняя | **Время:** ~1 час

---

### 9. Risk Severity — пустой

**Причина:** `loadRiskDonut()` вызывает `fetch('/api/risk-severity')`. В статике сервера нет.

**План:**
- `visualizer.py` инжектит `__RISK_SEVERITY_JSON__`
- `loadRiskDonut()` проверяет `STATIC_MODE`

**Файлы:** `visualizer.py`, `ui_template.html`

**Сложность:** низкая | **Время:** ~20 мин

---

### 10. Top Services — пустой

**Причина:** Аналогично #9 — `fetch('/api/services')`.

**План:** Аналогично #9 — инжектить `__SERVICES_JSON__`.

**Файлы:** `visualizer.py`, `ui_template.html`

**Сложность:** низкая | **Время:** ~20 мин

---

### 11. Поисковая строка в подменю «Правила»

**Причина:** В таблице правил нет поля поиска.

**План:**
- Добавить `<input type="text" id="rules-search" placeholder="Поиск по правилам...">` над таблицей
- JS: фильтровать `allRules` по всем полям (name, source, destination, service, action)
- Debounce 300ms
- Подсвечивать совпадения

**Файлы:** `ui_template.html` → `renderRules()`

**Сложность:** низкая | **Время:** ~20 мин

---

### 12. Подменю «Аудит» пустое

**Причина:** `renderAudit()` вызывает `allAudit` — проверяем, что данные инжектятся. Аудит работает (42 findings), но данные могут не доходить до JS.

**План:**
- Проверить что `__AUDIT_JSON__` заменяется корректно в `visualizer.py`
- Проверить формат данных — `renderAudit()` ожидает определённую структуру
- Если данные есть но не отображаются → поправить рендеринг
- Добавить группировку по severity, сортировку

**Файлы:** `visualizer.py`, `ui_template.html` → `renderAudit()`

**Сложность:** низкая | **Время:** ~30 мин

---

### 13. Связанные правила в подменю «Инфо»

**Причина:** `showNodeInfo()` показывает только базовую инфу об узле, но не связанные с ним правила.

**План:**
- В `showNodeInfo(nodeId)`:
  - Найти все рёбра где `from === nodeId` или `to === nodeId`
  - Извлечь `rules` из каждого ребра
  - Показать список правил под информацией об узле
  - Каждое правило кликабельно → `focusNode()` для source/destination

**Файлы:** `ui_template.html` → `showNodeInfo()`

**Сложность:** низкая | **Время:** ~25 мин

---

### 14. MITRE — пустое подменю

**Причина:** `renderMitre()` вызывает `fetch('/api/mitre/matrix')`. В статике сервера нет. В веб-режиме — данные могут не матчиться с тестовыми конфигами.

**План:**
- Шаг 1: Проверить `mitre_mapper.py` на тестовых данных — находит ли матчи
- Шаг 2: В статическом режиме — инжектить `__MITRE_JSON__`
- Шаг 3: `renderMitre()` проверяет `STATIC_MODE`
- Шаг 4: Если матчей нет — показать сообщение «Нет совпадений с MITRE ATT&CK» вместо пустой матрицы
- Шаг 5: Улучшить словарь `mitre_mapping.json` для тестовых конфигов

**Файлы:** `mitre_mapper.py`, `visualizer.py`, `ui_template.html`

**Сложность:** средняя | **Время:** ~1 час

---

## План выполнения

### Этап 1: Статический режим — инжектить все данные (корень проблем 8, 9, 10, 14)

| # | Задача | Время |
|---|--------|-------|
| 1.1 | Добавить `__STATIC_MODE__` флаг + `__DASHBOARD_JSON__` + `__RISK_SEVERITY_JSON__` + `__SERVICES_JSON__` + `__MITRE_JSON__` + `__TOPOLOGY_JSON__` в `visualizer.py` | 1.5ч |
| 1.2 | Обернуть все `fetch()` в `if (!window.STATIC_MODE)` + использовать предзагруженные данные | 1ч |

### Этап 2: Базовые фиксы

| # | Задача |
|---|--------|
| 2.1 | Счётчик nodes/edges/rules/issues (#7) |
| 2.2 | Поиск в правилах (#11) |
| 2.3 | Связанные правила в инфо-панели (#13) |
| 2.4 | Аудит — проверить рендеринг (#12) |

### Этап 3: Карта и переключения

| # | Задача |
|---|--------|
| 3.1 | Залипание курсора + кнопка физики (#1) |
| 3.2 | Режимы Standard/Hierarchy/Circle/Risk (#3) |
| 3.3 | 2D ↔ 3D переключение (#4) |
| 3.4 | Панель настроек ⚙️ (#2) |

### Этап 4: Экспорт и SIEM

| # | Задача |
|---|--------|
| 4.1 | Починить PNG-экспорт (#5) |
| 4.2 | Удалить SIEM из UI (#5) |

### Этап 5: Топологии (#6)

| # | Задача |
|---|--------|
| 5.1 | Проверить и починить каждый модуль топологии (7 шт.) |
| 5.2 | Статический режим: инжектить топологии в HTML |

### Этап 6: Финальные проверки

| # | Задача |
|---|--------|
| 6.1 | Сквозной прогон: `--audit --html` |
| 6.2 | Веб-режим: `--web` |
| 6.3 | Коммит + обновить `_task.md` |
