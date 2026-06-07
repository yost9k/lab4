# Лабораторная работа №4

## Системные зависимости

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv curl docker.io docker-compose-plugin
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Установка `osv-scanner`:

```bash
curl -L https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o osv-scanner
chmod +x osv-scanner
```

## Запуск контейнеров

```bash
docker compose up -d
docker compose ps
```

После запуска доступны:

```text
Grafana:    http://localhost:3000
Prometheus: http://localhost:9090
SQL Exporter: http://localhost:9399/metrics
```

Grafana:

```text
admin / admin
```

## Тестовый запуск пайплайна

```bash
chmod +x run_pipeline.sh
./run_pipeline.sh
```

Пайплайн выполняет:

```text
task2.py — инвентаризация Rocky Linux и запись данных в PostgreSQL
task3.py — формирование BOM, OSV-сканирование и запись данных в PostgreSQL
```

## Запуск по расписанию

```bash
chmod +x setup_cron.sh
./setup_cron.sh
crontab -l
```

Cron запускает пайплайн каждые 5 минут.

## Основные метрики

```text
lab4_installed_packages_total
lab4_vulnerabilities_total
lab4_vulnerabilities_by_severity
```

## Grafana

Dashboard:

```text
Lab4 Vulnerability Monitoring
```

Alert rules:

```text
No inventory data for 30 minutes
No OSV data for 30 minutes
Vulnerability threshold exceeded
```
