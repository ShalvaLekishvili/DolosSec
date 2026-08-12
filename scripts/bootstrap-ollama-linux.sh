#!/usr/bin/env bash
set -euo pipefail

MODEL="${1:-qwen3.5:9b}"

echo "[DolosSec] Installing Ollama from the official install endpoint..."
curl -fsSL https://ollama.com/install.sh | sh

echo "[DolosSec] Ollama version:"
ollama -v

if command -v systemctl >/dev/null 2>&1; then
  sudo systemctl start ollama || true
fi

echo "[DolosSec] Pulling local model: ${MODEL}"
ollama pull "${MODEL}"

echo "[DolosSec] Verifying local API..."
curl -fsS http://127.0.0.1:11434/api/version
echo

echo "[DolosSec] Done. Configure .env with:"
echo "DOLOS_LLM_PROVIDER=ollama"
echo "DOLOS_MODEL=${MODEL}"
echo "DOLOS_OLLAMA_BASE_URL=http://127.0.0.1:11434"
