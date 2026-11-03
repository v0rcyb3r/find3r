#!/usr/bin/env bash
# Find3r Turnkey Partner & Cloud Deployment Script
# Usage:
#   ./deploy-cloud.sh                 # Launches Docker Compose stack with generated Team Key
#   ./deploy-cloud.sh --tailscale     # Installs/configures Tailscale Serve + Docker Compose stack
set -euo pipefail

MODE="${1:-standard}"

if [ ! -f .env ]; then
  TEAM_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))' 2>/dev/null || openssl rand -hex 18)"
  PG_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))' 2>/dev/null || openssl rand -hex 18)"
  cat > .env <<EOF
# Find3r Shared Partner Environment
FIND3R_BIND_HOST=0.0.0.0
FIND3R_PORT=8765
FIND3R_TEAM_KEY=${TEAM_KEY}
POSTGRES_PASSWORD=${PG_PASS}

# Optional API Keys (can also be added live in the UI)
SHODAN_API_KEY=
CENSYS_API_TOKEN=
HIBP_API_KEY=
URLSCAN_API_KEY=
HUNTER_API_KEY=
GITHUB_TOKEN=
EOF
  chmod 600 .env
  echo "[find3r] Created .env with generated FIND3R_TEAM_KEY."
fi

# Load .env
set -a
source .env
set +a

if [ "$MODE" = "--tailscale" ]; then
  if ! command -v tailscale >/dev/null 2>&1; then
    echo "[find3r] Installing Tailscale for encrypted zero-trust partner mesh..."
    curl -fsSL https://tailscale.com/install.sh | sh
  fi
  echo "[find3r] Ensure Tailscale is authenticated ('sudo tailscale up'), then expose port ${FIND3R_PORT:-8765} via:"
  echo "         sudo tailscale serve --bg ${FIND3R_PORT:-8765}"
fi

echo "[find3r] Building and starting Find3r + PostgreSQL 16 + Ollama stack..."
docker compose up -d --build

echo ""
echo "=================================================================="
echo " Find3r Partner Workspace is live"
echo "------------------------------------------------------------------"
echo " Local / Tailscale URL : http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1'):${FIND3R_PORT:-8765}"
echo " Shared Team Passkey   : ${FIND3R_TEAM_KEY}"
echo "------------------------------------------------------------------"
echo " Share the URL and Team Passkey with your partner."
echo " In the Find3r top bar, click the Operator callsign pill to enter"
echo " your Callsign and Team Passkey."
echo "=================================================================="
