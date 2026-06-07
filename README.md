# Лабораторная работа №4

## Тема

Развёртывание системы мониторинга инвентаризации и уязвимостей для Rocky Linux.

## Используемые компоненты

- Rocky Linux 9.8 — объект мониторинга
- Ubuntu — сервер мониторинга
- PostgreSQL — хранение результатов инвентаризации и OSV-сканирования
- Prometheus — сбор метрик
- SQL Exporter — публикация SQL-метрик для Prometheus
- Grafana — визуализация и alert rules
- node_exporter — системные метрики Rocky Linux
- osv-scanner — сканирование CycloneDX BOM
- cron — периодический запуск пайплайна

## Структура проекта

```text
docker-compose.yml      - запуск PostgreSQL, Prometheus, Grafana, SQL Exporter
init.sql                - схема базы данных
prometheus.yml          - конфигурация Prometheus
sql_exporter.yml        - SQL-метрики для Prometheus
task2.py                - инвентаризация Rocky Linux и запись в PostgreSQL
task3.py                - формирование BOM, OSV-сканирование и запись в PostgreSQL
run_pipeline.sh         - запуск task2.py и task3.py
setup_cron.sh           - настройка запуска пайплайна каждые 5 минут
requirements.txt        - Python-зависимости
