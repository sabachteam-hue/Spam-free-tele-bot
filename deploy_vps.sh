#!/bin/bash
set -e

echo "===================================================="
echo "🚀 Installing TeleCampaign Pro VPS (24/7 Service)"
echo "===================================================="

APP_DIR=$(pwd)
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-pip python3-venv curl

python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

SERVICE_FILE="/etc/systemd/system/telecampaign.service"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=TeleCampaign Pro Anti-Spam Telegram Marketing Suite
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8090
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable telecampaign
systemctl restart telecampaign

# Open firewall port 8090 if ufw is active
if command -v ufw >/dev/null 2>&1; then
    ufw allow 8090/tcp >/dev/null 2>&1 || true
fi

PUBLIC_IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')

echo "===================================================="
echo "✅ TeleCampaign Pro is now running 24/7 on port 8090!"
echo "🌐 Open in your browser: http://${PUBLIC_IP}:8090"
echo "===================================================="
