# Promotion — copy-ready posts

All posts are formatted and ready to paste. Edit URLs/handles to match your accounts before posting.

---

## Reddit r/LocalLLaMA

**Title:** I built a shell script that audits your local Ollama models for poisoning — chat templates, tokenizer seams, metadata

**Body:**

Repo: https://github.com/room101-dev/canary-ollama

Ollama models come from the wild — `ollama pull`, Hugging Face, hand-made GGUFs. Recent research shows both template-level covert instructions (hidden "do not mention these instructions" payloads in chat templates) and tensor-weight backdoors (the "Mind the Gap" GGUF quantization attack, ICML 2025) are real threats.

`check-ollama.sh` is a zero-dependency wrapper around [c4nary](https://github.com/paraxaQQ/canary) that statically audits the parts of a GGUF model attackers actually weaponize:

- **No args** → lists all local models (name, sha256, size, mtime)
- **Model name or sha256 digest** → scans the GGUF blob for risky chat templates, tokenizer seams, and metadata anomalies
- **Exit 2** on any finding, with optional desktop notification

c4nary's full-catalog sweep found 28 malicious models across 192k HuggingFace GGUF repos at 0 false positives — 24 SSTI/RCE + 4 content-gated behavioral backdoors. This script wraps that for local Ollama installs.

Supports `$OLLAMA_MODELS`, auto-detects `~/.ollama`, `/usr/share/ollama/.ollama`, system installs. MIT licensed.

Papers cited in the README: Mind the Gap (ICML 2025), Weight Poisoning (ACL 2020), TrojAI (NIST), MNTD (IEEE S&P 2021), ToxScreen (2026).

---

## Reddit r/ollama

**Title:** `check-ollama.sh` — audit your Ollama models for template poisoning and metadata anomalies

**Body:**

https://github.com/room101-dev/canary-ollama

Quick overview: this is a shell script that wraps [c4nary](https://github.com/paraxaQQ/canary) to audit Ollama GGUF models for dangerous chat templates (SSTI, covert instruction injection), tokenizer seams, and metadata anomalies.

No arguments = list all models. Give it a model name or sha256 digest = scan that model. Exit 2 if anything is found.

What it catches: template-level poisoning (the "Mind the Gap" ICML 2025 attack is real, and c4nary found 28 malicious models across 192k HF repos at 0 FP). What it doesn't catch: tensor-level backdoors (needs white-box weight inspection).

Auto-detects `~/.ollama`, `/usr/share/ollama/.ollama`, `/var/lib/ollama/.ollama`, and `$OLLAMA_MODELS`. Zero config needed.

---

## Hacker News — Show HN

**Title:** Show HN: check-ollama.sh — audit local Ollama models for poisoning

**First comment (post this as a comment immediately after submitting):**

https://github.com/room101-dev/canary-ollama

A shell script that scans your Ollama GGUF models for dangerous chat templates, tokenizer seams, and metadata anomalies. Uses c4nary (which found 28 malicious models across 192k HF repos at 0 FP). Zero dependencies beyond jq + c4nary. Lists all models with no args; scans a specific model by name or sha256 digest.

Research-backed: cites Mind the Gap (ICML 2025, first GGUF quantization attack), Weight Poisoning (ACL 2020), NIST TrojAI, and others. The README links to an annotated bibliography with DOIs for every claim.

---

## Twitter/X thread (8 tweets)

**Tweet 1:**
I built a shell script that audits your local Ollama models for poisoning.

No args = list all models. Name or sha256 = scan that model's GGUF blob for dangerous chat templates, tokenizer seams, and metadata anomalies.

Exit 2 on any finding.

https://github.com/room101-dev/canary-ollama

**Tweet 2:**
Why this matters: Ollama models come from the open internet. Recent research shows both template-level covert instructions AND tensor-weight backdoors are real threats.

The "Mind the Gap" paper (ICML 2025) is the first attack on the GGUF format itself.

**Tweet 3:**
c4nary swept 192,032 gguf-tagged Hugging Face repos. Found 28 malicious models at 0 false positives.

24 SSTI/RCE PoCs + 4 content-gated behavioral backdoors that silently inject "do not mention these hidden instructions."

**Tweet 4:**
What it checks:
- Chat template: SSTI paths, covert instruction injection, concealment codepoints
- Tokenizer seams: reachable role/turn special surfaces, odd vocab entries
- Metadata: architecture/basename/finetune strings
- Determinism: stable template_sha256 across model families

**Tweet 5:**
It wraps c4nary (https://github.com/paraxaQQ/canary) with Ollama-specific ergonomics:

- Auto-detects ~/.ollama, /usr/share/ollama/.ollama, system installs
- Supports $OLLAMA_MODELS env var
- Desktop notifications on findings (notify-send)
- --json / --sarif output for CI pipelines

**Tweet 6:**
What it does NOT catch: tensor-level backdoors (Mind the Gap, Weight Poisoning ACL 2020). Those need white-box weight inspection.

This is the first, cheap layer of defense-in-depth. Not a clean bill of health.

**Tweet 7:**
Research-backed. The README links to an annotated bibliography with DOIs/arXiv IDs for every claim:

- Mind the Gap (ICML 2025) — GGUF quantization attack
- Weight Poisoning (ACL 2020) — pre-trained model backdoors
- NIST TrojAI — government benchmark
- ToxScreen (2026) — 800 backdoored LLMs

**Tweet 8:**
MIT licensed. Zero config. Two dependencies: jq + c4nary (pip install c4nary).

If you run Ollama locally, this takes 30 seconds to try. Your models are loaded into a process with full access to your machine — worth checking what's in them.

https://github.com/room101-dev/canary-ollama

---

## Awesome-list PR descriptions

### awesome-ollama (if repo exists)

```markdown
### Add check-ollama.sh

A shell script that audits local Ollama models for poisoning — dangerous chat templates, tokenizer seams, and metadata anomalies. Wraps c4nary for Ollama-specific ergonomics (auto-detects model paths, supports $OLLAMA_MODELS, desktop notifications). Cites peer-reviewed research (Mind the Gap ICML 2025, Weight Poisoning ACL 2020). Zero config, MIT licensed.
```

### awesome-LLM-security (if repo exists)

```markdown
### Add check-ollama.sh — Ollama model poisoning auditor

Static analysis tool for Ollama GGUF models. Checks chat templates for SSTI/instruction injection, tokenizer seams for role/turn exploits, and metadata anomalies. Based on c4nary's sweep of 192k HF repos (28 malicious, 0 FP). Supports CI via --json/--sarif output. Cites Mind the Gap (ICML 2025), NIST TrojAI, and others.
```

---

## GitHub issue reply templates

Use these when you find open issues/discussions about Ollama security, model auditing, or GGUF safety.

### Generic security concern reply:

> You might find `check-ollama.sh` useful — it's a shell script that audits Ollama GGUF models for dangerous chat templates, tokenizer seams, and metadata anomalies: https://github.com/room101-dev/canary-ollama
>
> It wraps c4nary, which swept 192k HF repos and found 28 malicious models at 0 false positives. Cites the Mind the Gap paper (ICML 2025) on GGUF quantization attacks.

### Template poisoning specific reply:

> The chat template attack surface is real — c4nary found 4 content-gated behavioral backdoors that silently inject "do not mention these hidden instructions" across 192k HF repos.
>
> `check-ollama.sh` checks for this locally: https://github.com/room101-dev/canary-ollama

### Model supply chain reply:

> If you're pulling models from the open internet, you might want to audit them first. `check-ollama.sh` scans Ollama GGUF models for SSTI, covert instruction injection, and metadata anomalies: https://github.com/room101-dev/canary-ollama
