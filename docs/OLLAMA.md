# DolosSec + Ollama Local AI Setup

DolosSec v0.4 can use Ollama as its primary planning model. This path is fully local: DolosSec calls the Ollama REST API on `http://127.0.0.1:11434` and does not require a paid API key.

The AI is a planner, not a security boundary. It proposes typed DolosSec actions; `ScopePolicy` and the trusted tool broker still validate targets, paths, methods, redirects and other execution constraints before a tool runs.

## Recommended models

| Profile | Ollama model | Approx. download | Use |
|---|---|---:|---|
| Lightweight | `qwen3.5:4b` | 3.4 GB | Small laptops, basic planning |
| Balanced | `qwen3.5:9b` | 6.6 GB | Recommended default |
| Strong | `qwen3.5:27b` | 17 GB | Larger-memory workstations |

The current Ollama library lists Qwen3.5 as an open-source model family with tool and thinking support. DolosSec uses structured JSON output rather than direct model tool execution.

## 1. Install Ollama

### Kali Linux / Debian / Ubuntu / other Linux

Official install command:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verify:

```bash
ollama -v
```

If you installed manually rather than through the service installer, start it in one terminal:

```bash
ollama serve
```

On a systemd installation:

```bash
sudo systemctl start ollama
sudo systemctl status ollama
```

Logs:

```bash
journalctl -e -u ollama
```

### macOS

The official preferred installation is the Ollama `.dmg` application:

1. Download the current macOS build from the official Ollama download page.
2. Mount the `.dmg`.
3. Drag `Ollama.app` into `/Applications`.
4. Launch Ollama once. It can create the `ollama` CLI link in `/usr/local/bin`.
5. Open a new terminal and run:

```bash
ollama -v
```

Current Ollama documentation requires macOS Sonoma 14 or newer. Apple Silicon has CPU/GPU support; x86 Macs run CPU-only.

### Windows

The official recommended Windows path is `OllamaSetup.exe`:

1. Download the current Windows installer from the official Ollama download page.
2. Run `OllamaSetup.exe`. The normal per-user install does not require Administrator rights.
3. Open a new PowerShell window.
4. Verify:

```powershell
ollama -v
```

Ollama runs in the background and serves the local API at `http://localhost:11434`.

## 2. Verify the local REST API

Linux/macOS:

```bash
curl http://127.0.0.1:11434/api/version
curl http://127.0.0.1:11434/api/tags
```

PowerShell:

```powershell
Invoke-RestMethod http://127.0.0.1:11434/api/version
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

DolosSec also provides:

```bash
dolos ollama status
```

## 3. Pull a model

Recommended:

```bash
ollama pull qwen3.5:9b
```

Or through DolosSec:

```bash
dolos ollama pull qwen3.5:9b
```

Lower-memory option:

```bash
ollama pull qwen3.5:4b
```

Larger workstation option:

```bash
ollama pull qwen3.5:27b
```

List installed models:

```bash
ollama list
```

## 4. Test the model by itself

```bash
ollama run qwen3.5:9b
```

Exit the interactive session with `/bye`.

## 5. Configure DolosSec

From the DolosSec repository:

```bash
cp .env.example .env
```

The important values are:

```dotenv
DOLOS_LLM_PROVIDER=ollama
DOLOS_MODEL=qwen3.5:9b
DOLOS_OLLAMA_BASE_URL=http://127.0.0.1:11434
DOLOS_OLLAMA_ALLOW_REMOTE=false
DOLOS_OLLAMA_TIMEOUT_SECONDS=180
DOLOS_OLLAMA_NUM_CTX=32768
DOLOS_OLLAMA_NUM_PREDICT=1200
DOLOS_OLLAMA_TEMPERATURE=0.1
DOLOS_OLLAMA_KEEP_ALIVE=10m
```

Verify the full integration:

```bash
dolos doctor
dolos ollama status
dolos ollama test
```

`dolos ollama test` asks the model for one structured DolosSec planning turn but does **not** execute the proposed security tool.

## 6. Start the web console

```bash
dolos web
```

Open:

```text
http://127.0.0.1:8787
```

The **Local AI engine** card shows:

- Ollama online/offline status;
- Ollama version;
- local endpoint;
- installed models;
- recommended local models.

For each assessment you can choose:

- Project default;
- Ollama local/free;
- Deterministic/no-AI;
- OpenAI if separately configured.

When Ollama is chosen, DolosSec refuses to start the scan if the service is unreachable or the selected model is not installed.

## 7. What DolosSec sends to Ollama

The planner receives:

- the authorized target descriptor;
- the current planning step;
- a bounded subset of recent tool observations;
- the required `PlannerTurn` JSON schema.

Untrusted strings are length-bounded before entering model context. The model receives a system policy stating that source code, HTTP responses, comments, README text and tool output are untrusted data rather than instructions.

Ollama returns JSON matching the planner schema. Example:

```json
{
  "summary": "Map the source tree before focused review.",
  "actions": [
    {
      "tool": "source_map",
      "arguments": {"path": "/authorized/project"},
      "reason": "Establish application structure and likely entry points."
    }
  ]
}
```

That JSON does not directly execute. DolosSec validates it into Pydantic models and hands the action to the trusted tool broker.

## 8. Security boundary for Ollama

Ollama's local API does not require authentication on localhost. DolosSec therefore defaults to:

```dotenv
DOLOS_OLLAMA_BASE_URL=http://127.0.0.1:11434
DOLOS_OLLAMA_ALLOW_REMOTE=false
```

With that default, hostnames other than `localhost`, `127.0.0.1` or another loopback address are rejected before a model request is made.

Do not expose an unauthenticated Ollama API directly to an untrusted LAN or the Internet.

A remote Ollama service can only be enabled explicitly:

```dotenv
DOLOS_OLLAMA_ALLOW_REMOTE=true
DOLOS_OLLAMA_BASE_URL=http://trusted-ai-host:11434
```

That mode is intended for controlled environments and is not the recommended single-user configuration.

## 9. Troubleshooting

### `Ollama is not reachable`

Linux:

```bash
sudo systemctl status ollama
sudo systemctl start ollama
curl http://127.0.0.1:11434/api/version
```

Manual server:

```bash
ollama serve
```

macOS/Windows: ensure the Ollama application is running, then open a new terminal and retry `ollama -v`.

### Model is not installed

```bash
ollama pull qwen3.5:9b
```

Then:

```bash
dolos ollama status
```

### Slow scans

Use a smaller model:

```dotenv
DOLOS_MODEL=qwen3.5:4b
```

Or reduce planner context:

```dotenv
DOLOS_OLLAMA_NUM_CTX=16384
```

### Out of memory

Stop other local models and inspect running Ollama models:

```bash
ollama ps
```

Then use `qwen3.5:4b` instead of 9B/27B.

## Official references

- Ollama Quickstart: https://docs.ollama.com/quickstart
- Linux: https://docs.ollama.com/linux
- macOS: https://docs.ollama.com/macos
- Windows: https://docs.ollama.com/windows
- API introduction: https://docs.ollama.com/api/introduction
- Chat API: https://docs.ollama.com/api/chat
- Structured outputs: https://docs.ollama.com/capabilities/structured-outputs
- Local model list API: https://docs.ollama.com/api/tags
