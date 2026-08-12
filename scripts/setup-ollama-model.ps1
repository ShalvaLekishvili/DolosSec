param(
    [string]$Model = "qwen3.5:9b"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Error "Ollama CLI was not found. Install OllamaSetup.exe from the official Ollama download page, open a new PowerShell window, then rerun this script."
}

Write-Host "Ollama version:"
ollama -v

Write-Host "Pulling $Model ..."
ollama pull $Model

Write-Host "Verifying local API ..."
Invoke-RestMethod http://127.0.0.1:11434/api/version | Format-List

Write-Host "Configure DolosSec .env with:"
Write-Host "DOLOS_LLM_PROVIDER=ollama"
Write-Host "DOLOS_MODEL=$Model"
Write-Host "DOLOS_OLLAMA_BASE_URL=http://127.0.0.1:11434"
