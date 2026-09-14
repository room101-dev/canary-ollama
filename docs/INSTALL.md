# Install

## Requirements

- **Python 3.10+**
- **c4nary** (`pip install c4nary`) — the static analysis engine
- **jq** — only for the bash wrapper (`check-ollama.sh`), not needed for the Python API

Optional:
- **notify-send** (libnotify) — desktop notifications on scan findings
- **FastAPI + Uvicorn** — API server
- **watchdog** — real-time filesystem watcher

## Quick start

```sh
git clone git@github.com:room101-dev/canary-ollama.git
cd canary-ollama
```

### Bash wrapper only

```sh
./check-ollama.sh                  # list models
./check-ollama.sh qwen3.8:27b      # scan one
```

Needs: `bash 4+`, `jq`, `canary` (from `pip install c4nary`).

### Python package

```sh
pip install .                    # core: list + scan
pip install ".[server]"          # + FastAPI HTTP server
pip install ".[watch]"           # + watchdog filesystem watcher
pip install ".[all]"             # everything
pip install -e ".[all]"          # editable/development install
```

### Development

```sh
pip install -e ".[dev]"
ruff check canary_ollama/
ruff format --check canary_ollama/
mypy canary_ollama/
```

## Install options

| Extra | Deps | What you get |
|---|---|---|
| _(core)_ | `c4nary` | `list_models()`, `scan_model()`, `scan_all()`, CLI |
| `server` | `fastapi`, `uvicorn` | HTTP API server (`canary-ollama serve`) |
| `watch` | `watchdog` | Real-time filesystem watcher (`canary-ollama watch`) |
| `dev` | `pytest`, `ruff`, `mypy` | Linting, type checking, testing |
| `all` | everything | Full install |

## Verify

```sh
# Check canary is available
canary --version

# List models (bash)
./check-ollama.sh

# List models (Python)
python -m canary_ollama list

# List models (if installed as package)
canary-ollama list

# Health check (if server installed)
canary-ollama serve --port 8420 &
curl http://localhost:8420/health
```

## Troubleshooting

**"c4nary not found"**
```sh
pip install c4nary
```

**"Ollama models directory not found"**
```sh
# Set the models directory explicitly
export OLLAMA_MODELS=/path/to/ollama/models
```

**"jq not found"** (bash wrapper only)
```sh
# Debian/Ubuntu
sudo apt install jq

# macOS
brew install jq
```

**"FastAPI not installed"** (server mode)
```sh
pip install ".[server]"
```

**"watchdog not installed"** (watch mode)
```sh
pip install ".[watch]"
```
