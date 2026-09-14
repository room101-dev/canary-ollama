# GGUF Model Security Tools: Comparison

Canary-ollama wraps c4nary for Ollama-specific ergonomics. Other tools go deeper
on different surfaces. This document maps the landscape.

---

## Tool overview

| Tool | Focus | GGUF support | Install | License |
|---|---|---|---|---|
| **c4nary** | Static audit: templates, tokenizer, metadata, config, model cards | ✅ Native | `pip install c4nary` | MIT |
| **check-ollama.sh** | Ollama-specific wrapper around c4nary | ✅ Via c4nary | `git clone` | MIT |
| **assay** | Offline binary scanner: provenance, integrity, weight inspection | ✅ Native | Single binary | MIT |
| **tensorguard** | Format-level inspection: tensor metadata, security patterns | ✅ Native | `pip install tensorguard` | MIT |
| **tensortrap** | Security scanner: pickle, safetensors, GGUF, ONNX | ✅ Native | `pip install tensortrap` | MIT |
| **garak** | LLM vulnerability scanner: 120+ probe categories, runtime testing | ✅ Via ggml | `pip install garak` | Apache-2.0 |
| **JFrog HF scanner** | Malicious code decompilation + deep data flow analysis | ✅ Native | HuggingFace integrated | Commercial |
| **Eresus Sentinel** | AI/LLM security: model artifact analysis, prompt injection firewall | ✅ Native | GitHub | TBD |

---

## What each tool detects

### Chat template attacks (SSTI / behavioral backdoors)

| Tool | SSTI/RCE detection | Behavioral backdoor detection | Render-free |
|---|---|---|---|
| **c4nary** | ✅ TPL001-TPL020 | ✅ TPL021-TPL023 | ✅ Static AST |
| **check-ollama.sh** | ✅ Via c4nary | ✅ Via c4nary | ✅ Via c4nary |
| **assay** | ⚠️ Template flagging only | ❌ | ✅ |
| **tensorguard** | ❌ | ❌ | ✅ |
| **tensortrap** | ⚠️ Jinja injection (1 rule) | ❌ | ✅ |
| **garak** | ❌ Dynamic probes only | ❌ | ❌ Runtime |
| **JFrog** | ✅ Deep analysis | ⚠️ Unknown | ✅ |

c4nary is the only tool that detects content-gated behavioral backdoors
("do not mention these hidden instructions") via static AST analysis.

### Tokenizer seam attacks

| Tool | Tokenizer inspection | Role token confusion | Deep vocab scan |
|---|---|---|---|
| **c4nary** | ✅ TOK0xx | ✅ TOK012 | ✅ `--deep-tokenizer` |
| **check-ollama.sh** | ✅ Via c4nary | ✅ Via c4nary | ✅ Default on |
| **assay** | ❌ | ❌ | ❌ |
| **tensorguard** | ⚠️ Format-level only | ❌ | ❌ |
| **tensortrap** | ❌ | ❌ | ❌ |
| **garak** | ❌ | ❌ | ❌ |

### Weight / tensor inspection

| Tool | Tensor-level analysis | Anomaly detection | Weight backdoor detection |
|---|---|---|---|
| **c4nary** | ❌ By design | ❌ | ❌ |
| **check-ollama.sh** | ❌ | ❌ | ❌ |
| **assay** | ✅ `--deep --profile` | ✅ MAD anomaly threshold | ⚠️ Statistical only |
| **tensorguard** | ⚠️ Metadata only | ❌ | ❌ |
| **tensortrap** | ❌ | ❌ | ❌ |
| **garak** | ❌ | ❌ | ❌ |

assay is the only tool that inspects tensor values without loading the model.
It uses mmap + online moments for peak RAM under model size. Catches statistical
anomalies that could indicate weight poisoning (Mind the Gap class).

### Metadata / config attacks

| Tool | suppress_tokens | Model card injection | Config audit | auto_map Python |
|---|---|---|---|---|
| **c4nary** | ✅ CFG | ✅ DOC/MET | ✅ CFG | ✅ `--bundle` |
| **check-ollama.sh** | ✅ Via c4nary | ✅ Via c4nary | ✅ Via c4nary | ⚠️ Needs `--bundle` |
| **assay** | ❌ | ❌ | ⚠️ Structural only | ❌ |
| **tensorguard** | ❌ | ⚠️ Metadata scan | ❌ | ❌ |
| **tensortrap** | ❌ | ❌ | ❌ | ❌ |

### Format-level security (pickle, safetensors, structural)

| Tool | Pickle detection | Safetensors validation | Structural integrity | Format fingerprinting |
|---|---|---|---|---|
| **c4nary** | ❌ Not in scope | ❌ | ✅ STR rules | ❌ |
| **assay** | ✅ Risk flagging | ✅ Header + offset validation | ✅ Manifest hashing | ✅ Architecture detection |
| **tensorguard** | ❌ | ✅ Header parsing | ✅ | ❌ |
| **tensortrap** | ✅ Primary focus | ✅ | ✅ | ❌ |

### Runtime / dynamic analysis

| Tool | Live inference | Adversarial probing | Jailbreak testing | Output scanning |
|---|---|---|---|---|
| **c4nary** | ❌ Never loads | ❌ | ❌ | ❌ |
| **garak** | ✅ Primary focus | ✅ 120+ probes | ✅ | ❌ |
| **tensortrap** | ❌ | ❌ | ❌ | ✅ Output files |
| **JFrog** | ❌ | ❌ | ❌ | ❌ |

---

## Complementary tool chains

### Layer 1: Static audit (what we do)

```
c4nary (via check-ollama.sh)
  → Chat template SSTI/RCE detection
  → Behavioral backdoor detection
  → Tokenizer seam analysis
  → Metadata/config audit
  → Deterministic, offline, render-free
```

### Layer 2: Format + weight inspection (go deeper)

```
assay
  → Tensor-level statistical analysis
  → Provenance + signature verification
  → Anomaly detection (Mind the Gap class)
  → Layer profiling + drift comparison

tensorguard
  → Suspicious tensor names
  → Shell metacharacters in metadata
  → Base64 payload detection
  → Zero dependencies, stdlib only
```

### Layer 3: Runtime + adversarial testing (deepest)

```
garak
  → 120+ vulnerability probe categories
  → Dynamic adversarial testing
  → Jailbreak resistance testing
  → Runtime behavior analysis
```

---

## Recommended workflow

```
1. check-ollama.sh --bundle          # fast static audit (seconds)
   ↓ findings?
2. assay scan ./model/ --deep        # weight inspection (minutes)
   ↓ anomalies?
3. garak --target_type gguf ...      # runtime probing (hours)
```

Or in Python:

```python
from canary_ollama import scan_model, list_models

# Layer 1: fast static check
result = scan_model("qwen3.8:27b")
if result.rc > 0:
    print(f"FINDINGS: {result.findings}")

# Layer 2: weight inspection (assay)
# assay scan ./model/ --deep --profile

# Layer 3: runtime probing (garak)
# garak --target_type gguf --target_name ./model.gguf
```

---

## Decision matrix

| If you need to... | Use |
|---|---|
| Quick scan all local Ollama models | `check-ollama.sh` |
| Scan a single model for template backdoors | `canary scan model.gguf` |
| Scan a model without downloading it | `canary scan --remote org/repo` |
| Detect behavioral backdoors in templates | `c4nary` (only tool that does this) |
| Inspect tensor values for weight poisoning | `assay scan --deep` |
| Check format integrity + provenance | `assay scan` or `tensorguard` |
| Runtime adversarial testing | `garak` |
| CI/CD integration | `canary scan --json --fail-on warn` |
| Structural diff of two models | `canary diff a.gguf b.gguf` |
| Drift detection against known-good | `canary scan --manifest known_good.json` |

---

## Gaps in the ecosystem

1. **No tool combines static template audit + weight inspection + runtime probing**
   in a single pipeline. Each layer requires a different tool.

2. **Behavioral backdoor detection is c4nary-only.** No other tool catches
   content-gated instruction injection via static analysis.

3. **Weight-level backdoor detection is unsolved.** assay does statistical
   anomaly detection, but cannot prove a model is clean or malicious.
   Mind the Gap attacks are invisible at full precision.

4. **No tool monitors Ollama model pulls in real-time.** All tools are
   scan-on-demand. A watch daemon that scans on `ollama pull` would be
   a valuable addition.

5. **No tool produces a combined report** across all layers. Each tool
   outputs its own format. A unified JSON/SARIF report aggregating
   c4nary + assay + garak findings would be useful.
