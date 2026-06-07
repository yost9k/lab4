#!/bin/bash

CRON_CMD="*/5 * * * * /home/vboxuser/lab4/run_pipeline.sh >> /home/vboxuser/lab4/results/pipeline.log 2>&1"

crontab -l 2>/dev/null | grep -v "/home/vboxuser/lab4/run_pipeline.sh" > /tmp/lab4_cron || true
echo "$CRON_CMD" >> /tmp/lab4_cron
crontab /tmp/lab4_cron
rm /tmp/lab4_cron

echo "Cron job installed:"
crontab -l | grep "/home/vboxuser/lab4/run_pipeline.sh"
