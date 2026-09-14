# canary-ollama

> Audit your Ollama models for poisoning — chat templates, tokenizer seams, metadata.

![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Shell](https://img.shields.io/badge/Shell-Bash-orange)
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

## What this audit covers

| surface | what it checks | c4nary rule family |
|---|---|---|
| chat template | SSTI paths (`cycler`/`lipsum`/`__globals__`), covert instruction injection, concealment codepoints | `TPL0xx` |
| tokenizer seams | reachable role/turn special surfaces, odd vocab entries | `TOK0xx` (`--deep-tokenizer`) |
| metadata | architecture / basename / finetune strings | `MET0xx` |
| determinism | stable `template_sha256` across a model family → template drift is visible | — |

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

- Research background: [docs/LITERATURE.md](docs/LITERATURE.md)
- Wraps [c4nary](https://github.com/paraxaQQ/canary) (MIT).

## License

MIT — see [LICENSE](LICENSE).
