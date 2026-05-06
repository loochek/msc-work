# Фреймворк тестирования

## Модель нагрузки

Рассматриваемый профиль нагрузки нагрузки - managed container registry, автоматическая сборка и загрузка образов средствами CI/CD. Такой сценарий обеспечивает следующую закономерность в анатомии образа:
- Базовые слои с Linux окружением - обновляются редко
- Слои с зависимостями приложения (пакетные менеджеры дистрибутивов/языковые зависимости) - обновляются чаще
- Слой с самим приложением  - обновляется постоянно, на каждый коммит

# Генератор тестового набора образов

Скрипт `generate_images.py` генерирует набор образов, моделирующий реальный профиль нагрузки на container registry

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
4. **Scratch + Go binary** — `go build` простого приложения с зависимостями (go.mod) при помощи образа golang + создание scratch образа с готовым приложением

### Версии образов

Для каждого производного образа генерируем несколько "версий" - на одинаковые производные образы с окружением накатываем разные файлы (меняющийся "исходный код"). Это позволяет моделировать нагрузку от CI/CD

### Go-образы

Для Go:
- генерируем минимальный main.go + go.mod с реальными зависимостями
- Multi-stage - первая стадия с `go build`, вторая - scratch образ с бинарником. Это даёт реалистичный Go binary с embedded module info (которую Trivy сканирует через `go version -m`)

## Результат работы

Скрипт:
- собирает образы
- пушит их в registry (опционально)
- записывает метаинформациб о сгенерированных образах в файл `manifest.json`

## Запуск

```bash
python3 ./generate_images.py --registry 51.250.33.162.nip.io:8443 --push
```

# Benchmark runner

## Сканеры

- Trivy - запускается как есть
- Syft + Grype - сначала генерируется SBOM при помощи Syft, затем на нем запускается Grype
- Clair - последовательно вызываются ручки для indexing и matching

## Метрики

| Поле | Описание | Trivy | Syft + Grype | Clair |
|------|----------|-------|-------|-------|
| `wall_time` | Полное время | + | Суммарное время Syft + Grype | Суммарное время indexing + matching |
| `index_time` | Время indexing | - | Время работы Syft | Время работы POST index_report |
| `match_time` | Время matching | - | Время работы Grype | Время работы GET vulnerability_report |
| `vulns` | Уязвимости по severity | + | + | + |
| `layers_fetched` | Список digest слоёв, скачанных из registry и проанализированных | + | + (всегда все) | + |
| `layers_cached` | Список digest слоёв, взятых из кеша | + | - (нет кеша) | + |

## Запуск

```bash
# Сlair должен быть поднят на localhost:6060
trivy image --download-db-only
grype db update

python3 ./run_benchmark.py --manifest manifest.json --scanners trivy --cold --output results-trivy.json
python3 ./run_benchmark.py --manifest manifest.json --scanners grype --output results-grype.json
python3 ./run_benchmark.py --manifest manifest.json --scanners clair --clair-psk c2VjcmV0 --clair-url 'http://localhost:6060' --cold --output results-clair.json
```
