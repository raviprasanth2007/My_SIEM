#!/bin/bash

echo "╔════════════════════════════════════════════════════╗"
echo "║      🛡️  STARTING SIEM ON KALI                   ║"
echo "╚════════════════════════════════════════════════════╝"

cd ~/Documents/my_siem

# Ensure local UI config exists from .env if available
if [ -f .env ] && [ ! -f ui/js/config.js ]; then
    PUB_TOKEN=$(grep -E '^MAPBOX_PUBLIC_TOKEN=' .env | cut -d '=' -f2- | tr -d '"'\'' ')
    if [ -n "$PUB_TOKEN" ]; then
        echo "// Local SIEM Client Configuration (Git-Ignored)" > ui/js/config.js
        echo "window.MAPBOX_TOKEN = window.MAPBOX_TOKEN || '$PUB_TOKEN';" >> ui/js/config.js
    fi
fi

# Start Agent
echo "[*] Starting Log Agent..."
cd agent
nohup python3 linux_agent.py > /tmp/siem_agent.log 2>&1 &
echo "[+] Agent PID: $!"

# Start FIM
echo "[*] Starting FIM Module..."
nohup python3 fim_module.py > /tmp/siem_fim.log 2>&1 &
echo "[+] FIM PID: $!"

cd ~/Documents/my_siem/ui

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║  ✅ SIEM AGENTS ARE RUNNING!                      ║"
echo "║  📊 Dashboard: brave-browser index.html          ║"
echo "║  📝 Agent Logs: /tmp/siem_agent.log              ║"
echo "║  📝 FIM Logs:   /tmp/siem_fim.log                ║"
echo "╚════════════════════════════════════════════════════╝"

# Open Dashboard
brave-browser index.html 2>/dev/null || firefox index.html 2>/dev/null || xdg-open index.html