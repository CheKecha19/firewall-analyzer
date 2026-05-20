# 3D Library Selection for Firewall Analyzer

## Date: 2026-05-20
## Task: V1.1 — Исследование и выбор 3D-библиотеки для визуализации графов

---

## Кандидаты

### 1. 3d-force-graph (vasturiano)

- **GitHub:** https://github.com/vasturiano/3d-force-graph
- **npm:** `3d-force-graph` (v1.80.0, MIT)
- **Основа:** Three.js/WebGL + d3-force-3d (или ngraph) для физики
- **CDN:** `https://cdn.jsdelivr.net/npm/3d-force-graph` (ESM + UMD)
- **Размер:** ~120-150KB gzipped (без Three.js; Three.js добавляет ~125KB gzipped)
  - Итого через CDN: ~275KB gzipped (Three.js included as dependency)
- **Звёзды GitHub:** ~4.8k
- **Активность:** Активно поддерживается (последний релиз — май 2026)

### 2. force-graph-3d

- **Упрощённый вариант / синоним:** Это то же самое, что `3d-force-graph`. Отдельного пакета `force-graph-3d` не существует как независимого продукта. В экосистеме vasturiano есть:
  - `force-graph` — 2D Canvas версия
  - `3d-force-graph` — 3D версия
  - `3d-force-graph-vr` — VR версия
  - `3d-force-graph-ar` — AR версия
- **Вывод:** Кандидат совпадает с #1, отдельного сравнения не требует.

### 3. Raw Three.js + собственный рендеринг

- **CDN:** `https://cdn.jsdelivr.net/npm/three@0.170.0/build/three.min.js`
- **Размер:** ~125KB gzipped (core only); ~600KB+ gzipped с OrbitControls и дополнениями
- **Плюсы:** Полный контроль, никаких абстракций, минимальный оверхед
- **Минусы:** 
  - Нужно писать force-directed layout с нуля (или подключать d3-force-3d отдельно)
  - Ручное управление геометрией сфер, линий, материалов
  - Ручной raycasting для hover/click на узлах
  - Ручная реализация OrbitControls (есть как плагин, ~15KB extra)
  - Оценка времени разработки: 3-5 дней только на базовый функционал

---

## Сравнительная таблица

| Критерий | 3d-force-graph | Raw Three.js |
|---|---|---|
| **Размер бандла (gzip)** | ~275KB (с Three.js) | ~140KB (core + OrbitControls) |
| **Формат nodes[{id, label, group, risk_score}]** | ✅ Идеально: `nodeId`, `nodeLabel`, `nodeAutoColorBy`, `nodeVal` | ⚠️ Ручной mapping |
| **Формат edges[{from, to, riskScore}]** | ✅ `linkSource`, `linkTarget`, `linkColor(fn)`, `linkWidth(fn)` | ⚠️ Ручной mapping |
| **Производительность 1000+ узлов** | ✅ Демо с 4000+ элементами, WebGL | ✅ WebGL native |
| **Интеграция в HTML (CDN)** | ✅ `<script src="cdn.jsdelivr.net/npm/3d-force-graph">` | ✅ `<script src="cdn.jsdelivr.net/npm/three">` |
| **OrbitControls** | ✅ Встроено: `{ controlType: 'orbit' }` | ⚠️ Нужен отдельный импорт |
| **Кастомизация цветов/размеров** | ✅ `nodeColor(fn)`, `nodeVal(fn)`, `linkColor(fn)`, `linkWidth(fn)` | ⚠️ Всё вручную |
| **Force-directed layout** | ✅ Встроено (d3-force-3d) | ❌ Нужно писать/подключать |
| **Лейблы узлов** | ✅ Sprite-based, HTML | ❌ Нужно писать |
| **Drag & drop узлов** | ✅ Встроено | ❌ Нужно писать |
| **Hover/tooltip** | ✅ Встроено (`nodeLabel` HTML) | ❌ Нужно писать |
| **Click events** | ✅ `onNodeClick`, `onLinkClick` | ⚠️ Ручной raycasting |
| **Стабилизация графа** | ✅ Автоматическая | ❌ Нужно реализовывать |
| **Время на интеграцию** | ~2-4 часа | ~3-5 дней |

---

## Решение

**Выбран: 3d-force-graph (vasturiano)**

### Обоснование

1. **Минимальное время интеграции.** Библиотека "из коробки" даёт всё, что нужно:
   - Force-directed 3D layout
   - OrbitControls (вращение, зум, панорамирование)
   - Кастомизацию размера/цвета узлов через accessor functions
   - Лейблы, hover, click, drag & drop
   - Стабилизацию графа

2. **Совместимость с форматом данных.** API библиотеки напрямую матчится с существующей структурой:
   ```js
   .nodeId('id')
   .nodeLabel('label')        // label из nodes_data
   .nodeAutoColorBy('group')  // group/zone из nodes_data
   .nodeVal('risk_score')     // риск из nodes_data
   .linkSource('from')        // from из edges_data
   .linkTarget('to')          // to из edges_data
   .linkColor(e => riskColor(e.riskScore))  // кастомный цвет по риску
   ```

3. **Размер бандла в рамках.** ~275KB gzipped — ниже порога в 500KB.

4. **Готовый CDN.** `<script src="//cdn.jsdelivr.net/npm/3d-force-graph"></script>` — одна строка, никакого npm/webpack.

5. **Производительность.** WebGL-рендеринг + d3-force-3d (оптимизирован для тысяч узлов). Демо с 4000+ элементами работает плавно.

6. **Зрелость.** 4.8k звёзд, активная поддержка, MIT лицензия, 43+ проекта используют.

7. **Документация.** Полный API reference с примерами для каждого метода. Десятки живых демо.

### Что теряем по сравнению с Raw Three.js

- **Кастомизация геометрии узлов** — но нам нужны сферы с цветом и размером, это стандарт
- **Специфические пост-эффекты** (bloom, custom shaders) — не критично для анализатора firewall
- **~135KB лишнего веса** — приемлемая цена за готовый функционал

### Миграция с Vis.js

Существующий код на Vis.js (vis-network) использует:
- `vis.DataSet` для nodes/edges → `graphData({ nodes, links })`
- `vis.Network` constructor → `new ForceGraph3D(container)`
- `network.setOptions()` → chained method calls

API 3d-force-graph следует тому же chainable паттерну, что упрощает миграцию.

---

## План интеграции (V1.2)

1. Добавить в `visualizer_v3.py` метод `generate_3d_html()`
2. Создать `src/graph/visualizer_3d.py` с 3D-специфичной логикой
3. Поддержать все существующие view modes в 3D (standard, risk, поиск, фильтр по зонам)
4. Добавить переключатель 2D/3D в UI

---

## Тестовый файл

Создан `tests/3d_test.html` — самодостаточный HTML с CDN-загрузкой 3d-force-graph:
- 100 случайных узлов с группами и risk_score
- Цвета по группам, размеры по risk_score
- OrbitControls
- Легенда рисков
- Панель статистики

Открыть: двойной клик по `tests/3d_test.html` в проводнике.
