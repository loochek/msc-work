# План: генератор тестового набора образов

Для экспериментальной оценки эффективности сканеров нужен параметризуемый генератор образов, моделирующий реальный профиль нагрузки на container registry

## Модель нагрузки

### Базовые образы

- `ubuntu:22.04` — для dpkg пакетов
- `alpine:3.18` — для apk пакетов
- `fedora:39` — для rpm пакетов
- `python:3.11-slim` — для dpkg + pip пакетов
- `node:20-slim` —  для dpkg + npm пакетов
- `golang:1.21` — для сборки go образов

### Шаблоны производных образов

Каждый базовый образ порождает заданное число производных. Типы производных:

1. **OS deps only** (для всех образов) — `apt-get install` / `apk add` / `dnf install` нескольких пакетов
2. **OS + pip** (для базового образа python) — pip install набора пакетов
3. **OS + npm** (для базового образа node) — npm install набора пакетов
4. **Scratch + Go binary** — `go build` простого приложения с зависимостями (go.mod) при помощи образа golang + создание distroless образа с готовым приложением

### Версии образов

Для каждого производного образа генерируем несколько "версий" - на одинаковые производные образы с окружением накатываем разные файлы (меняющийся "исходный код"). Это позволяет моделировать нагрузку от CI/CD

### manifest.json

Для каждого образа сохраняем:
- image ref (registry/name:tag)
- базовый образ
- тип (os-deps / pip / npm / scratch)
- список слоёв (digests)
- размер
- какие слои общие с другими образами

Эта информация используется для анализа результатов бенчмарка

### Go-образы

Для Go:
- генерируем минимальный main.go + go.mod с реальными зависимостями
- Multi-stage - первая стадия с `go build`, вторая - scratch образ с бинарником. Это даёт реалистичный Go binary с embedded module info (которую Trivy сканирует через `go version -m`)

## Запуск бенчмарка

### Сканеры

| Сканер | Indexing | Matching | Кеш слоёв |
|--------|---------|----------|-----------|
| **Trivy** | Встроенный (fanal) | Встроенный | Да (BoltDB) |
| **Grype** | Syft (отдельный процесс) | Grype по готовому SBOM | Нет |
| **Clair** | HTTP API (POST index_report) | HTTP API (GET vulnerability_report) | Да (PostgreSQL) |

Grype запускается в два этапа: `syft <image>` (indexing) → `grype sbom:<file>` (matching). Это даёт раздельное время indexing/matching, аналогично Clair

### Метрики

Для каждого образа и каждого сканера — единая структура `ScanResult`:

| Поле | Описание | Trivy | Grype | Clair |
|------|----------|-------|-------|-------|
| `wall_time_s` | Полное время | Да | index + match | index + match |
| `index_time_s` | Время indexing | — | syft | POST index_report |
| `match_time_s` | Время matching | — | grype sbom: | GET vulnerability_report |
| `vulns` | `{critical, high, medium, low, other}` | Да | Да | Да |
| `layers_fetched` | Список digest слоёв, скачанных из registry | Из debug stderr | Из SBOM (всегда все) | Из логов indexer |
| `layers_scanned` | Список digest слоёв, реально проанализированных | = fetched | = fetched | Из логов indexer |
| `layers_cached` | Список digest слоёв, взятых из кеша | all - fetched | `[]` (нет кеша) | Из логов indexer |

### Нормализация severity

Сканеры используют разные шкалы. Приводим к единой:

| Unified    | Trivy      | Grype            | Clair                |
|------------|------------|------------------|----------------------|
| critical   | CRITICAL   | Critical         | Critical, Defcon1    |
| high       | HIGH       | High             | High                 |
| medium     | MEDIUM     | Medium           | Medium               |
| low        | LOW        | Low, Negligible  | Low, Negligible      |
| other      | UNKNOWN    | Unknown          | Unknown              |

### Обнаружение cache hit

**Trivy** — из `--debug` stderr:
- `Missing diff ID in cache: sha256:XXX` — cache miss, слой будет скачан и проанализирован
- Слои, отсутствующие в этих строках, но присутствующие в `Diff IDs: [...]` — cache hit
- Перед cold scan: `trivy clean --scan-cache`

**Grype (Syft)** — кеша слоёв нет, каждый запуск cold

**Clair** — из `docker logs <indexer-container> --since <timestamp>`:
- `layer fetch start ... layer=sha256:XXX` — скачивание слоя (cache miss)
- `scan start ... layer=sha256:XXX` — анализ слоя (cache miss)
- `layer already scanned ... layer=sha256:XXX` — cache hit
- Перед cold scan: очистить БД indexer (или развернуть заново)

### Сценарии

1. **Cold scan** — кеш очищен, все образы сканируются с нуля
2. **Warm scan** — повторное сканирование тех же образов (кеш заполнен)

Порядок сканирования контролируемый: образы сортируются так, чтобы производные от одного base шли подряд. Это позволяет наблюдать эффект кеширования base layer

### Установка инструментов

```bash
# Trivy
brew install trivy
# или: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Grype + Syft (оба нужны — Syft для indexing, Grype для matching)
brew install grype syft
# или:
# curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
# curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# pip
pip install requests

# Pre-download vulnerability databases before benchmarking
trivy image --download-db-only
grype db update
```

Clair — уже развёрнут, нужен только endpoint

### Запуск

```bash
# Trivy + Grype (по умолчанию), cold scan
python benchmark/run_benchmark.py \
  --manifest manifest.json \
  --cold --insecure \
  --output results-cold.json

# Warm scan (повторный запуск без --cold)
python benchmark/run_benchmark.py \
  --manifest manifest.json \
  --insecure \
  --output results-warm.json

# Все три сканера включая Clair
python benchmark/run_benchmark.py \
  --manifest manifest.json \
  --scanners trivy grype clair \
  --clair-url http://<clair-host>:6060 \
  --clair-indexer-container clair-indexer \
  --insecure \
  --output results.json
```
