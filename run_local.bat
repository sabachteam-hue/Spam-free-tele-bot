@echo off
title TeleCampaign Pro - Anti-Spam Telegram Marketing Suite
cd /d "%~dp0"
echo Starting TeleCampaign Pro on http://localhost:8090 ...
start "" http://localhost:8090
python main.py
pause
