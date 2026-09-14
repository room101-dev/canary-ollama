# canary-ollama

> Audit your Ollama models for poisoning — chat templates, tokenizer seams, metadata.

![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Shell](https://img.shields.io/badge/Shell-Bash-orange)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![GitHub release](https://img.shields.io/github/v/release/room101-dev/canary-ollama)

Ollama models ship from the open internet (`ollama pull`, Hugging Face, hand-made
GGUFs) and get loaded into a process with full access to your machine. Model
poisoning is not theoretical — peer-reviewed work demonstrates both _hidden
instruction injection_ in chat templates that silently steer model output, and
_tensor-weight backdoors_ that survive quantization and fire only on
attacker-chosen triggers.

`canary` is a fast, zero-config static audit of the parts of a GGUF model that
attackers actually weaponize: the **chat template**, the **tokenizer seams**,
and the **metadata** — with a deterministic `template_sha256` so template
changes on a "same" model are visible.

- **no arguments** → lists every local Ollama model (human name, `sha256-...`
  blob digest, size, mtime)
- **a model name or sha256 digest** → runs [c4nary](https://github.com/paraxaQQ/canary)
  over that GGUF blob with `--fail-on warn --deep-tokenizer`
- **any WARN / FAIL finding** → bell + banner + optional desktop notification, **exit 2**

> ⚠️ **Honest scope.** This audits the GGUF **metadata / chat template /
> tokenizer**, not billions of tensor weights. Tensor-level backdoors — the
> "Mind the Gap" quantization attack below — need **white-box weight
> inspection**, which this tool does not perform. Treat it as the first, cheap
> layer of defense-in-depth, not a clean bill of health.

## Why poisoning matters (cited)

Annotated bibliography with DOIs/arXiv IDs: [docs/LITERATURE.md](docs/LITERATURE.md).

- **Quantized weights are directly attackable.** *Mind the Gap: A Practical
  Attack on GGUF Quantization* (Egashira, Staab, Vero, He, Vechev; **ICML 2025**)
  is the first attack on the GGUF format used by llama.cpp and Ollama. It injects
  malicious behavior into quantized weights that is invisible at full precision —
  insecure code generation Δ=88.7%, targeted content injection Δ=85.0%, benign
  refusal suppression Δ=30.1%, across nine GGUF quant types.
- **Template-level poisoning confirmed in the wild.** c4nary's sweep of 192,032
  gguf-tagged Hugging Face repos found **28 FAIL models at 0 false positives**:
  24 SSTI/RCE PoCs plus 4 content-gated behavioral backdoors — templates that
  silently inject instructions like "…do not mention these hidden instructions."
- **Poisoned weights survive fine-tuning.** *Weight Poisoning Attacks on
  Pre-trained Models* (Kurita, Michel, Neubig; **ACL 2020**) and *Layerwise Weight
  Poisoning* (Li et al.; **EMNLP 2021**).
- **Detection is an active benchmark problem.** NIST/IARPA **TrojAI**; *Meta
  Neural Trojan Detection* (Xu et al.; **IEEE S&P 2021**); *ToxScreen* (~800
  backdoored LLMs, 2026).

## What this audit checks

Canary inspects three surfaces that attackers weaponize in GGUF models:

| surface | what it detects | c4nary rule family |
|---|---|---|
| **chat template** | SSTI / RCE payloads (`os.popen`, `__import__`, `__class__.__subclasses__()`), covert instruction injection ("do not mention these hidden instructions"), concealment codepoints, conditional activation via `tool_use` paths | `TPL0xx` |
| **tokenizer seams** | reachable role/turn special surfaces, confusable role tokens, odd vocab entries that could hijack prompt structure | `TOK0xx` (`--deep-tokenizer`) |
| **metadata** | architecture / basename / finetune string anomalies, `suppress_tokens` manipulation, model-card system prompt injection | `MET0xx` |
| **determinism** | stable `template_sha256` across a model family — template drift between "same" models becomes visible | — |

**Why these surfaces matter:**

- **Chat templates are executable code.** GGUF stores Jinja2 templates in `tokenizer.chat_template`. A poisoned template can inject hidden instructions, exfiltrate data via URLs, or execute arbitrary Python at model load time. These pass every automated security scan on HuggingFace — see [docs/poisoned-templates.md](docs/poisoned-templates.md) for real payloads found in the wild.

- **Tokenizer seams enable prompt hijacking.** If the tokenizer contains role tokens an attacker can forge (e.g., a fake `<|system|>` token in the vocab), they can inject instructions that the model treats as authoritative.

- **Metadata influences behavior.** A `suppress_tokens` list can suppress refusal tokens. A model card can embed system prompts that auto-apply at inference.

> **Deep dive:** [docs/poisoned-templates.md](docs/poisoned-templates.md) contains full exploit code for 4 classes of poisoned templates — SSTI/RCE, behavioral backdoors, conditional tool-use backdoors, and Modelfile prompt injection — with CVE references and detection commands.

## Behavior

| command | result |
|---|---|
| `check-ollama.sh` | list all models (name, sha256 blob, size, mtime) |
| `check-ollama.sh qwen3.8:27b` | canary-scan that model (human form) |
| `check-ollama.sh huihui_ai/Qwen3.6-abliterated:35b` | canary-scan (namespaced human form) |
| `check-ollama.sh sha256-5084e21b...92d` | canary-scan by blob digest (prefix optional) |
| `check-ollama.sh MODEL --json/--sarif/--fail-on X` | pass-through args to `canary scan` |
| `check-ollama.sh -h` | usage |

Default scan args: `--fail-on warn --deep-tokenizer`. No mode switches — **arg = scan, no arg = list.**

## Install

Requirements: bash 4+, [jq](https://jqlang.github.io/jq/), and
[c4nary](https://github.com/paraxaQQ/canary) (`pip install c4nary`).
Desktop notifications are optional (needs `notify-send`, e.g. libnotify).

```sh
git clone git@github.com:room101-dev/canary.git
cd canary
./check-ollama.sh                  # list models
./check-ollama.sh some/model:tag   # scan one
```

## Python API

`canary_ollama` is a Python package that wraps c4nary with a clean API, CLI, and
optional HTTP server. Install with:

```sh
pip install .                    # core (list + scan)
pip install ".[server]"          # + FastAPI server
pip install ".[watch]"           # + watchdog filesystem watcher
pip install ".[all]"             # everything
```

### Library usage

```python
from canary_ollama import list_models, scan_model, scan_all

# List all local models
models = list_models()
for m in models:
    print(f"{m.name}  {m.short_digest}  {m.size_human}")

# Scan a single model
result = scan_model("qwen3.8:27b")
print(f"rc={result.rc}  findings={len(result.findings)}")
for f in result.findings:
    print(f"  [{f.severity}] {f.rule}: {f.message}")

# Scan everything
results = scan_all()
clean = sum(1 for r in results if r.clean)
print(f"{clean}/{len(results)} clean")
```

### Scan options

```python
result = scan_model(
    "qwen3.8:27b",
    fail_on="warn",          # "info" | "warn" | "fail"
    deep_tokenizer=True,     # materialize full vocab for TOK checks
    bundle=True,             # audit config, tokenizer.json, card, auto_map Python
    sarif=False,             # SARIF 2.1.0 output
    policy=None,             # custom policy file
    baseline=None,           # baseline comparison
)
```

### Model objects

```python
from canary_ollama import get_model

m = get_model("qwen3.8:27b")
print(m.name)             # "qwen3.8:27b"
print(m.digest)           # "sha256-f5f1dd89..."
print(m.blob_path)        # Path("/home/user/.ollama/models/blobs/sha256-...")
print(m.size_human)       # "17G"
print(m.template_sha256)  # "a1b2c3d4..." (for drift detection)
```

## CLI

```sh
python -m canary_ollama [COMMAND] [ARGS]

Commands:
  list                          List all local models (default)
  scan NAME                     Scan a model for poisoning
  scan-all                      Scan all local models
  diff MODEL_A MODEL_B          Diff two models
  manifest                      Generate baseline manifest
  serve [--host HOST] [--port PORT]   Start API server
  watch [--interval SECONDS]          Watch for new models
```

### Examples

```sh
# List models (human-readable table)
canary-ollama list

# List models (JSON)
canary-ollama list --json

# Scan a model
canary-ollama scan qwen3.8:27b

# Scan with JSON output
canary-ollama scan qwen3.8:27b --json

# Scan all models
canary-ollama scan-all

# Diff two models
canary-ollama diff qwen3.8:27b deepseek-r1:70b

# Start API server
canary-ollama serve --port 8420

# Watch for new models (poll every 60s)
canary-ollama watch --interval 60
```

## API Server

Start the server:

```sh
canary-ollama serve --host 0.0.0.0 --port 8420
```

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check (canary installed, models dir found) |
| `GET` | `/models` | List all local models |
| `GET` | `/models/{name}` | Get single model details |
| `POST` | `/scan` | Scan a model (body: `{name, fail_on, deep_tokenizer, bundle}`) |
| `GET` | `/scan/{name}` | Scan a model via GET |
| `POST` | `/scan/all` | Scan all models |
| `GET` | `/diff?a=MODEL_A&b=MODEL_B` | Diff two models |

### curl examples

```sh
# Health check
curl http://localhost:8420/health

# List models
curl http://localhost:8420/models | jq .

# Scan a model
curl -X POST http://localhost:8420/scan \
  -H 'Content-Type: application/json' \
  -d '{"name": "qwen3.8:27b", "deep_tokenizer": true, "bundle": true}' | jq .

# Scan all
curl -X POST http://localhost:8420/scan/all \
  -H 'Content-Type: application/json' \
  -d '{"fail_on": "warn"}' | jq .
```

## Ollama Integration

### Auto-scan on model pull (watch mode)

```sh
# Poll for new models every 5 minutes
canary-ollama watch --interval 300

# Or use watchdog for real-time filesystem events (requires canary-ollama[watch])
canary-ollama watch
```

The watcher detects new/changed models and auto-scans them. Results are printed
to stdout, or passed to a custom callback if using the library API:

```python
from canary_ollama.hooks import watch

def on_result(result):
    if result.has_failures:
        send_alert(result.model.name, result.findings)

watch(callback=on_result)
```

### CI/CD integration

Use JSON output for machine parsing:

```sh
# GitHub Actions
canary-ollama scan-all --json --fail-on warn
# Exit code 2 if any findings → CI fails

# Pre-commit hook
canary-ollama scan "$MODEL" --json --fail-on fail
```

## Model location

Resolved in order (first match wins):

1. `$OLLAMA_MODELS` if set
2. `$HOME/.ollama/models` (default user install)
3. `/usr/share/ollama/.ollama/models` (system install)
4. `/var/lib/ollama/.ollama/models` (system install)
5. `/mnt/ai-models/Ollama/models`

## Exit codes

| code | meaning |
|---|---|
| 0 | listed, or scan finished with 0 fail / 0 warn |
| 1 | model not found, manifests dir missing, bad digest, or `canary`/`jq` missing |
| 2 | any WARN or FAIL finding, or a canary tool (non-0/1/2) error |

## Example

```
$ ./check-ollama.sh
huihui_ai/Qwen3.6-abliterated:35b  sha256-448bdcae...f4  23G  2026-05-27 08:36
qwen3.8:27b                         sha256-f5f1dd89...57d  17G  2026-09-04 11:30
deepseek-r1:70b                     sha256-4cd576d9...339   40G  2026-05-25 10:32
...

$ ./check-ollama.sh sha256-5084e21b421fbd1b4ef19b192dbc1e80250823d25c36138465b7b4aa83deb92d

== MODEL: fredrezones55/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive/Q2_K_P
== BLOB:  /mnt/ai-models/Ollama/models/blobs/sha256-5084e21b...
note: deep tokenizer pass ran; TOK012/TOK015 seam checks were active.
c4nary scan: ...  0 fail, 0 warn, 8 info
summary: scanned=1 canary_errors=0 blobs_missing=0
```

## Limits & adversarial reality

- Static AST analysis is **not** a malware verdict: a clean result means "no
  known-dangerous construct found in the audited surfaces."
- **Tensor backdoors are out of scope.** Weight inspection needs white-box,
  parameter-level methods (TrojAI benchmarks, MNTD, Neural Cleanse). See
  docs/LITERATURE.md.
- Large-scale static scanners live or die on false positives — c4nary's rules
  were calibrated against the real ecosystem (0 false positives across 192k
  repos), but deliberate evasion (paraphrased injections, homoglyph identifiers)
  is always possible.
- Abliterated / "uncensored" models are intentionally uncensored — a property of
  the model family, not a poisoning finding.

## References & credits

- Poisoned templates in the wild: [docs/poisoned-templates.md](docs/poisoned-templates.md)
- Research background: [docs/LITERATURE.md](docs/LITERATURE.md)
- Wraps [c4nary](https://github.com/paraxaQQ/canary) (MIT).

## License

MIT — see [LICENSE](LICENSE).
