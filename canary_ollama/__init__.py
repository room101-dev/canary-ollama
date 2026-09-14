"""canary_ollama — Audit Ollama models for poisoning.

Python API, CLI, and server for scanning Ollama GGUF models using c4nary.
"""

from canary_ollama.models import Model, find_models_dir, get_model, list_models
from canary_ollama.scanner import (
    Finding,
    ScanResult,
    diff_models,
    generate_manifest,
    scan_all,
    scan_model,
)

__all__ = [
    "Model",
    "Finding",
    "ScanResult",
    "diff_models",
    "find_models_dir",
    "generate_manifest",
    "get_model",
    "list_models",
    "scan_all",
    "scan_model",
]

__version__ = "0.1.0"
