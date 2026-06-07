#!/bin/bash
# VulnCatch AI v4.0 — Setup & Run Script for Kali Linux
# ========================================================

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   VulnCatch AI v4.0  🏏🔒                   ║"
echo "║   AI-Powered Vulnerability Scanner           ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Check for root (recommended for full nmap scan)
if [ "$EUID" -ne 0 ]; then
  echo "⚠  Not running as root — some scans (OS detection, SYN) will be limited."
  echo "   Run 'sudo bash setup_and_run.sh' for full capabilities."
  echo ""
fi

# Install system tools
echo "[1/4] Checking system tools..."
command -v nmap    &>/dev/null || { echo "  Installing nmap...";   apt-get install -y nmap   2>/dev/null || echo "  Manual: sudo apt install nmap -y"; }
command -v nikto   &>/dev/null || { echo "  Installing nikto...";  apt-get install -y nikto  2>/dev/null || echo "  Manual: sudo apt install nikto -y"; }
command -v nuclei  &>/dev/null || { echo "  Installing nuclei..."; apt-get install -y nuclei 2>/dev/null || echo "  Manual: sudo apt install nuclei -y"; }
echo "  ✔ System tools check done"

# Install Python dependencies
echo ""
echo "[2/4] Installing Python packages..."
pip3 install -r requirements.txt --break-system-packages -q 2>/dev/null || \
pip3 install flask requests python-nmap dnspython python-whois urllib3 beautifulsoup4 --break-system-packages -q
echo "  ✔ Python packages installed"

# Update nuclei templates (optional)
if command -v nuclei &>/dev/null; then
  echo ""
  echo "[3/4] Updating Nuclei templates..."
  nuclei -update-templates -silent 2>/dev/null && echo "  ✔ Templates updated" || echo "  ⚠ Template update skipped (no internet)"
fi

# Start app
echo ""
echo "[4/4] Starting VulnCatch AI..."
echo ""
echo "  🌐  Open browser: http://localhost:5000"
echo ""
echo "  🤖  AI Copilot: Get free Gemini key at:"
echo "      https://aistudio.google.com/app/apikey"
echo "      → Paste in ⚙ Settings inside the app"
echo ""
echo "  🔑  AbuseIPDB (optional): https://www.abuseipdb.com/register"
echo ""

export PYTHONUNBUFFERED=1
python3 app.py
