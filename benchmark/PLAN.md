# План: генератор тестового набора образов

## Контекст

Для экспериментальной оценки эффективности сканеров (Trivy, Clair) нужен параметризуемый генератор образов, моделирующий реальный профиль нагрузки на container registry. Генератор должен собирать и пушить образы через Docker.

## Структура

Один файл: `benchmark/generate_images.py`

## Модель нагрузки

### Base images (реальные, не собираем)
- `ubuntu:22.04` — dpkg
- `alpine:3.18` — apk
- `fedora:39` — rpm
- `python:3.11-slim` — dpkg + pip
- `node:20-slim` — dpkg + npm
- `golang:1.21` — dpkg + Go modules

### Шаблоны производных образов

Каждый base image порождает N производных. Типы производных:

1. **OS deps only** — `apt-get install` / `apk add` / `dnf install` нескольких пакетов
2. **OS + pip** (для python base) — pip install набора пакетов
3. **OS + npm** (для node base) — npm install набора пакетов
4. **OS + Go binary** (для golang base) — `go build` простого приложения с зависимостями (go.mod)
5. **App layer** — COPY синтетического файла контролируемого размера (имитация app binary)

### Имитация CI/CD (версии одного образа)

Для части образов генерируем 2-5 "версий": одинаковые base + deps слои, разный app layer. Это моделирует типичный CI/CD, где меняется только код приложения.

### Параметры CLI

```
python generate_images.py \
  --registry localhost:5000 \
  --derivatives-per-base 5 \      # сколько производных на каждый base image
  --versions-per-derivative 3 \   # сколько "версий" (только app layer меняется)
  --app-layer-size 10 \           # МБ, размер синтетического app layer
  --push                          # пушить в registry (без флага — только build)
  --output-manifest manifest.json # список собранных образов с метаданными
```

Итого образов при дефолтных параметрах: 6 bases × 5 derivatives × 3 versions = 90

### manifest.json

Для каждого образа сохраняем:
- image ref (registry/name:tag)
- base image
- тип (os-deps / pip / npm / go / app-only)
- список слоёв (digests)
- размер
- какие слои общие с другими образами

Это нужно для фазы бенчмарка: знать, какие образы делят слои, чтобы измерять cache hit.

## Реализация

### Зависимости
- Python 3.10+, только stdlib (subprocess для docker CLI, json, argparse, pathlib, tempfile, random)
- Docker CLI доступен

### Алгоритм

1. Парсим аргументы
2. Определяем матрицу: для каждого base image выбираем шаблоны производных (рандомно или по конфигу)
3. Для каждого производного:
   a. Генерируем Dockerfile во временной директории
   b. Генерируем контекст (requirements.txt / package.json / go.mod / синтетический бинарник)
   c. `docker build -t {registry}/{name}:{tag} .`
   d. Для "версий": пересоздаём только app layer (другой COPY), rebuild (Docker cache переиспользует предыдущие слои)
   e. Если --push: `docker push`
4. Собираем manifest.json: `docker inspect` каждого образа для получения layer digests
5. Выводим summary: сколько образов, сколько уникальных слоёв, общий размер

### Пулы пакетов для рандомизации

Для каждого pkg manager — список из 20-30 реальных пакетов, из которых выбираются случайные подмножества:

- **apt**: curl, wget, vim, git, build-essential, libssl-dev, nginx, postgresql-client, redis-tools, ...
- **apk**: curl, git, openssh, nginx, python3, py3-pip, nodejs, ...
- **dnf**: curl, git, vim, gcc, openssl-devel, nginx, ...
- **pip**: requests, flask, django, numpy, pandas, boto3, celery, ...
- **npm**: express, lodash, axios, moment, webpack, typescript, ...
- **go modules**: gin, cobra, viper, zap, gorm, ...

### Go-образы

Для Go: генерируем минимальный main.go + go.mod с реальными зависимостями. `go build` внутри Dockerfile. Multi-stage: build stage → scratch/distroless с бинарником. Это даёт реалистичный Go binary с embedded module info (которую Trivy сканирует через `go version -m`).

## Верификация

1. `python generate_images.py --derivatives-per-base 1 --versions-per-derivative 1` — минимальный прогон (6 образов), проверяем что всё собирается
2. `docker images | grep benchmark` — образы существуют
3. `cat manifest.json | python -m json.tool` — манифест валидный, layer digests присутствуют
4. Проверяем layer sharing: образы от одного base должны иметь общие нижние слои в манифесте
