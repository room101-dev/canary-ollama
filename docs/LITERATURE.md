# Poisoning research: annotated literature

Why audit Ollama GGUF models? Because model poisoning is peer-reviewed, real, and
growing. This document organizes the key papers by threat class, with DOIs/arXiv
IDs so you can verify every claim.

---

## A. GGUF quantization attacks — the direct threat

These papers target the exact format Ollama and llama.cpp use.

**Mind the Gap: A Practical Attack on GGUF Quantization**
Kazuki Egashira, Robin Staab, Mark Vero, Jingxuan He, Martin Vechev
**ICML 2025** · arXiv:2505.23786 · [ETH SRI Lab](https://www.sri.inf.ethz.ch/publications/egashira2025mind)

The first attack on the GGUF format. Injects malicious behavior into quantized
weights that is invisible at full precision — insecure code generation
(Δ=88.7%), targeted content injection (Δ=85.0%), benign refusal suppression
(Δ=30.1%). Tested across nine GGUF quant types on llama.cpp and Ollama (100M+
downloads, 70K+ shared models). Key insight: quantization error provides enough
flexibility to construct malicious quantized models that appear benign in full
precision.

**Understanding the Threats of Trojaned Quantized Neural Network in Model Supply Chains**
Xudong Pan, Mi Zhang, Yifan Yan, Min Yang
**ACSAC 2021**

Shows that quantized models in supply chains can carry trojans indistinguishable
from clean models under standard inspection. Directly precedes the GGUF-specific
attack above.

---

## B. Weight poisoning and backdoor attacks

**BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain**
Tianyu Gu, Brendan Dolan-Gavitt, Siddharth Garg
**NIPS 2017 Workshop** · arXiv:1708.06733

Origin paper for the concept of poisoned model weights as a supply chain attack.

**Weight Poisoning Attacks on Pre-trained Models**
Keita Kurita, Paul Michel, Graham Neubig
**ACL 2020** · DOI:10.18653/v1/2020.acl-main.249 · arXiv:2004.06660

Demonstrates RIPPLe + Embedding Surgery: pre-trained weights injected with
vulnerabilities that expose backdoors after fine-tuning. Attacker controls model
prediction via an arbitrary keyword. Works even without access to the training
dataset or hyperparameter settings.

**Backdoor Attacks on Pre-trained Models by Layerwise Weight Poisoning**
Linyang Li, Demin Song, Xiaonan Li, Jiehang Zeng, Ruotian Ma, Xipeng Qiu
**EMNLP 2021** · DOI:10.18653/v1/2021.emnlp-main.241

Layerwise weight poisoning strategy that plants deeper backdoors with
combinatorial triggers. Previous defense methods cannot resist this approach.

**BadPre: Task-agnostic Backdoor Attacks to Pre-trained NLP Foundation Models**
Kangjie Chen, Yuxian Meng, Xiaofei Sun, Shangwei Guo, Tianwei Zhang, Jiwei Li, Chun Fan
**ICLR 2022**

First backdoor attack against various downstream models built from pre-trained NLP
models. Same trigger works across tasks. Backdoor detectors are defeated by
adversarial trigger generation.

**Defending Against Weight-Poisoning Backdoor Attacks for Parameter-Efficient Fine-Tuning**
Shuai Zhao, Leilei Gan, Anh Tuan Luu, Jie Fu, Lingjuan Lyu, Meihuizi Jia, Jinming Wen
**NAACL 2024 Findings** · DOI:10.18653/v1/2024.findings-naacl.217

Addresses the vulnerability of PEFT methods (LoRA, etc.) to weight-poisoning
backdoor attacks.

**Trusted Weights, Treacherous Optimizations? Optimization-Triggered Backdoor Attacks on LLMs**
arXiv:2605.20641 (2026)

Triggerless backdoors embedded in LLM weights that activate only under specific
compiler/quantization optimizations. Model passes safety review under eager
execution but produces attacker-specified outputs under compiled execution.

**Poisoning Attacks on LLMs Require a Near-constant Number of Poison Samples**
Alexandra Souly, Robert Kirk et al.
**UK DSIT** · arXiv:2510.07192 (2025)

As few as 250 poisoned documents can backdoor large models (600M to 13B
parameters). Attack effectiveness is similar across model scales and training
data amounts. Backdoors become effective after exposure to a fixed number of
poison samples regardless of scale.

---

## C. Template-level and behavioral backdoors — what c4nary detects

**Hidden Trigger Backdoor Attack on NLP Models via Linguistic Style Manipulation (LISM)**
Xudong Pan, Mi Zhang, Beina Sheng, Jiaming Zhu, Min Yang
**USENIX Security 2022**

First hidden trigger backdoor exploiting linguistic style instead of inserted
words. Weaponizes text style transfer to generate sentences with attacker-
specified style that preserves malicious semantics and reveals almost no
abnormality.

**When Backdoors Speak: Understanding LLM Backdoor Attacks Through Model-Generated Explanations**
**ACL 2025** · 2025.acl-long.114

Uses LLMs' own generative capacity to explain backdoor behavior. Poisoned inputs
shift attention away from original input context during explanation generation.
Offers insights into detection via explanation analysis.

**Inserting and Activating Backdoor Attacks in LLM Agents (BadAgent)**
**ACL 2024** · 2024.acl-long.530

Backdoor attacks on LLM agents (not just models) — active attack (concealed
triggers) and passive attack (poisoned training data). Demonstrates that public
pre-trained models like Llama can carry agent-targeted backdoors.

**c4nary full-catalog gate (paraxaQQ/canary)**
v0.2.2: 192,032 gguf-tagged Hugging Face repos analyzed, 137,698 templates
scanned → **28 FAIL models, 0 false positives**. 24 SSTI/RCE PoCs + 4 content-
gated behavioral backdoors. The 4 behavioral backdoors (n0ni/test-qwen2.5-7B,
scruge/security-research, n0ni/test-mistral-8B, pragnyanramtha/gguf-chat-
template-backdoor-poc) are templates that silently inject instructions like
"do not mention these hidden instructions" — invisible to pickle scanners and
SSTI signature checks.

---

## D. Detection and benchmarks

**Detecting AI Trojans Using Meta Neural Analysis (MNTD)**
Xiaojun Xu, Qi Wang, Huichen Li, Nikita Borisov, Carl A. Gunter, Bo Li
**IEEE S&P 2021** · arXiv:1910.03137

Meta-classifier that predicts whether a given model is Trojaned using only
black-box access. Achieves 97% detection AUC. Generalizes against unforeseen
attacks. Robust variant achieves 90% AUC even against an attacker with full
knowledge of the detection system.

**Neural Cleanse: Identifying and Mitigating Backdoor Attacks in Neural Networks**
Brandon Wang, Dawn Song, Dawn et al.
**IEEE S&P 2019**

Classic trigger reverse-engineering: automatically identifies the minimal trigger
pattern that causes misclassification.

**NIST/IARPA TrojAI Program**
[nist.gov/itl/ai/trojai](https://www.nist.gov/itl/ai/trojai) ·
[github.com/usnistgov/trojai-example](https://github.com/usnistgov/trojai-example)

Ongoing government benchmark for trojan detection across multiple domains and
tasks. Reference datasets of clean and trojaned models. Leaderboard for detector
submissions.

**The Trojan Detection Challenge**
Mazeika et al. · **PMLR v220, 2023**

Benchmark competition for trojan detectors. 3,000 networks split across training,
validation, and test. Detection, target label prediction, and trigger synthesis
tracks.

**Baseline Pruning-Based Approach to Trojan Detection in Neural Networks**
Peter Bajcsy, Michael Majurski
**ICLR 2021 Security and Safety in ML Systems Workshop**

Pruning-based detection: measures how accuracy responds to systematic pruning.
Classifies models as clean or poisoned. 68–91% accuracy on TrojAI Rounds 1–4.

**ToxScreen: Detecting Whether an LLM Has Been Poisoned**
arXiv:2607.26849 (2026)

~800 backdoored models spanning four attack objectives (refusal suppression,
sentiment steering, safety misclassification, entity steering), multiple trigger
families, and six model scales (1B–70B). Token look-up recovers triggers
wherever backdoors are effective; gradient-based methods fail.

**Trojan Detection Through Pattern Recognition for Large Language Models**
arXiv:2501.11621

Multistage framework: token filtration → trigger identification → trigger
verification. Tested on TrojAI LLM Pretrain April 2024 dataset (Llama2 7B
architecture).

---

## E. Supply chain attacks on model hubs

**Models Are Codes: Towards Measuring Malicious Code Poisoning Attacks on Pre-trained Model Hubs (MalHug)**
arXiv:2409.09368

First systematic study of malicious code poisoning on Hugging Face. Pipeline for
detecting hidden authentication, backdoors, cryptojacking, embedded shells,
remote control, and data leakage in model/dataset repos.

**Data Scientists Targeted by Malicious Hugging Face ML Models with Silent Backdoor**
JFrog Security Research · March 2024

~100 malicious AI/ML model files on Hugging Face using Python pickle
deserialization for arbitrary code execution at load time. Introduced the
pickle-as-malware-vector awareness to the ML community.

**Poisoned Pipelines: Malicious AI Model and Skill Repositories**
Cloud Security Alliance · May 2026

Documents the growing attack surface: pickle serialization, ClawHavoc (1,184
malicious skills), cross-platform infection chains using Hugging Face as
staging infrastructure. Notes that GGUF (flat binary, no deserialization code
path) is safer than pickle — relevant context for why this tool audits GGUF
specifically.

**A Systematic Review of Poisoning Attacks Against Large Language Models**
Neil Fendley et al. · **JHU/APL** · arXiv:2506.06518

First comprehensive review. Proposes LLM poisoning threat model with 34 traits
across four dimensions: concept poisons, stealthy poisons, persistent poisons,
and poisons for unique tasks.

---

## F. GGUF loader memory safety (adjacent — not weight poisoning)

These are loader bugs, not model-content attacks, but relevant to the same attack
surface (untrusted GGUF files).

**GHSA-8wwf-w4qm-gpqr: Buffer Overflow in llama.cpp via Malicious GGUF Vocabulary**
GitHub Advisory · June 2025

Oversized token in GGUF vocabulary triggers signed-to-unsigned conversion error
in `token_to_piece()`, bypassing length check and causing unchecked `memcpy`.

**CVE-2026-7482 "Bleeding Llama" — Heap OOB Read in Ollama GGUF Loader**
CVSS 9.1 · Patched in Ollama 0.17.1 · February 2026

Unauthenticated attacker leaks process memory (API keys, prompts, env vars) via
crafted GGUF file to `/api/create`, then exfiltrates via `/api/push`. CSA
research note documents the attack chain.
