# canary — audit your local Ollama GGUF models with c4nary

A zero-config shell wrapper that resolves every local Ollama model to its GGUF
blob and scans it with [c4nary](https://github.com/paraxaQQ/canary) for
known-dangerous chat templates and tokenizer seams.

- **no arguments** → prints every model (human name, `sha256-...` blob digest, size, mtime) — no canary needed
- **a model name** → scans that model's GGUF blob (human form **or** `sha256:...` digest form)
- any WARN / FAIL finding or scan error → bell + banner + optional desktop notification, and **exit 2**

## Behavior

| command | result |
|---|---|
| `check-ollama.sh` | list all models (name, sha256 blob, size, modified) |
| `check-ollama.sh qwen3.8:27b` | canary-scan that model (human form) |
| `check-ollama.sh huihui_ai/Qwen3.6-abliterated:35b` | canary-scan (namespaced human form) |
| `check-ollama.sh sha256-5084e21b...92d` | canary-scan by blob digest (prefix optional) |
| `check-ollama.sh MODEL --json/--sarif/--fail-on X` | pass-through args to `canary scan` |
| `check-ollama.sh -h` | usage |

Default scan args: `--fail-on warn --deep-tokenizer`.

No mode switches — there is no `--scan` / `--no-scan` machinery. **Arg = scan, no arg = list.**

## Install

Requirements: bash 4+, [jq](https://jqlang.github.io/jq/), and
[c4nary](https://github.com/paraxaQQ/canary) (`pip install c4nary`).
Desktop notifications are optional (needs `notify-send`, e.g. libnotify).

```sh
git clone git@github.com:room101/canary.git
cd canary
./check-ollama.sh                  # list models
./check-ollama.sh some/model:tag   # scan one
```

## Model location

Resolved in order:

1. `$OLLAMA_MODELS` if set
2. `$HOME/.ollama/models`
3. `/mnt/ai-models/Ollama/models`

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
```

```
$ ./check-ollama.sh fredrezones55/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive:Q2_K_P

== MODEL: fredrezones55/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive/Q2_K_P
== BLOB:  /mnt/ai-models/Ollama/models/blobs/sha256-5084e21b421fbd1b4ef19b192dbc1e80250823d25c36138465b7b4aa83deb92d
note: deep tokenizer pass ran; TOK012/TOK015 seam checks were active.
c4nary scan: /mnt/ai-models/Ollama/models/blobs/sha256-5084e21b...
  0 fail, 0 warn, 8 info
```

## Honesty

This is a static checker, not a malware verdict:

- it inspects the GGUF **chat template and tokenizer metadata**, never tensor weights
- a clean result means "no known-dangerous construct found", not "safe"
- abliterated / "uncensored" models are intentionally uncensored — a property of the model family, not a c4nary finding
- weight-level backdoors and paraphrase/homoglyph evasions are out of scope (see c4nary's docs)

## Credits

Wraps [c4nary](https://github.com/paraxaQQ/canary) (MIT). c4nary's full-catalog
sweep of 192,032 gguf-tagged Hugging Face repos found 28 model templates with
FAIL-level findings (24 SSTI/RCE proof-of-concepts + 4 content-triggered
behavioral backdoors) at **0 false positives** — see their
[FINDINGS.md](https://github.com/paraxaQQ/canary/blob/main/docs/FINDINGS.md).

## License

MIT — see [LICENSE](LICENSE).