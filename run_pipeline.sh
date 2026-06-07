#!/bin/bash

cd /home/vboxuser/lab4
source .venv/bin/activate

echo "[$(date)] Starting inventory collection"
python3 task2.py

echo "[$(date)] Starting vulnerability scan"
python3 task3.py

echo "[$(date)] Pipeline finished"
