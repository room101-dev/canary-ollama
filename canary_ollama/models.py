"""Ollama model discovery and manifest parsing."""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Model:
    """A local Ollama model."""

    name: str  # "qwen3.8:27b" or "huihui_ai/Qwen3.6-abliterated:35b"
    digest: str  # "sha256-5084e21b...92d" (64 hex, sha256- prefix)
    blob_path: Path  # full path to the GGUF blob on disk
    manifest_path: Path  # full path to the Ollama manifest file
    size: int  # total size in bytes (all layers)
    modified: datetime  # manifest mtime
    template_sha256: str  # chat template digest (for drift detection)

    @property
    def short_digest(self) -> str:
        """Truncated digest for display: sha256-5084e21b...92d."""
        if len(self.digest) > 20:
            return f"{self.digest[:14]}...{self.digest[-3:]}"
        return self.digest

    @property
    def size_human(self) -> str:
        """Human-readable size: 17.0G, 230M, etc."""
        if self.size >= 1 << 30:
            return f"{self.size / (1 << 30):.1f}G"
        if self.size >= 1 << 20:
            return f"{self.size / (1 << 20):.0f}M"
        if self.size >= 1 << 10:
            return f"{self.size / (1 << 10):.0f}K"
        return f"{self.size}B"

    def to_dict(self) -> dict[str, str | int]:
        return {
            "name": self.name,
            "digest": self.digest,
            "blob_path": str(self.blob_path),
            "manifest_path": str(self.manifest_path),
            "size": self.size,
            "size_human": self.size_human,
            "modified": self.modified.isoformat(),
            "template_sha256": self.template_sha256,
        }


def find_models_dir() -> Path:
    """Auto-detect Ollama models directory.

    Resolution order (first match wins):
    1. $OLLAMA_MODELS
    2. $HOME/.ollama/models
    3. /usr/share/ollama/.ollama/models
    4. /var/lib/ollama/.ollama/models
    5. /mnt/ai-models/Ollama/models
    """
    candidates: list[str | None] = [
        os.environ.get("OLLAMA_MODELS"),
        os.path.expanduser("~/.ollama/models"),
    ]

    system = platform.system()
    if system == "Linux":
        candidates.extend([
            "/usr/share/ollama/.ollama/models",
            "/var/lib/ollama/.ollama/models",
        ])
    elif system == "Darwin":
        candidates.append("/usr/local/share/ollama/.ollama/models")

    candidates.append("/mnt/ai-models/Ollama/models")

    manifests_rel = Path("manifests/registry.ollama.ai")
    for d in candidates:
        if d and Path(d, manifests_rel).is_dir():
            return Path(d)

    raise FileNotFoundError(
        "Ollama models directory not found. Set $OLLAMA_MODELS or install Ollama."
    )


def _model_digest(manifest: Path) -> str | None:
    """Extract the model layer digest from an Ollama manifest file."""
    try:
        data = json.loads(manifest.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    for layer in data.get("layers", []):
        if layer.get("mediaType") == "application/vnd.ollama.image.model":
            digest = layer.get("digest", "")
            if digest.startswith("sha256:"):
                return "sha256-" + digest[7:]
    return None


def _template_digest(manifest: Path) -> str:
    """Extract the chat template digest from an Ollama manifest file."""
    try:
        data = json.loads(manifest.read_text())
    except (json.JSONDecodeError, OSError):
        return ""

    for layer in data.get("layers", []):
        if layer.get("mediaType") == "application/vnd.ollama.image.template":
            digest = layer.get("digest", "")
            if digest.startswith("sha256:"):
                return digest[7:]
    return ""


def _total_size(manifest: Path) -> int:
    """Sum all layer sizes in the manifest."""
    try:
        data = json.loads(manifest.read_text())
    except (json.JSONDecodeError, OSError):
        return 0
    return sum(layer.get("size", 0) for layer in data.get("layers", []))


def _mtime(path: Path) -> datetime:
    """File modification time as UTC datetime."""
    ts = path.stat().st_mtime
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def list_models() -> list[Model]:
    """List all local Ollama models.

    Returns a list of Model objects sorted by name.
    """
    models_dir = find_models_dir()
    manifests_dir = models_dir / "manifests" / "registry.ollama.ai"
    blobs_dir = models_dir / "blobs"

    results: list[Model] = []
    for manifest_path in sorted(manifests_dir.rglob("*")):
        if not manifest_path.is_file():
            continue

        digest = _model_digest(manifest_path)
        if not digest:
            continue

        blob_path = blobs_dir / digest
        if not blob_path.is_file():
            continue

        # Derive human-readable name from manifest path
        # e.g. .../registry.ollama.ai/library/qwen3.8/27b → qwen3.8:27b
        rel = manifest_path.relative_to(manifests_dir)
        parts = list(rel.parts)
        # Strip "library/" prefix if present
        if parts and parts[0] == "library":
            parts = parts[1:]
        if len(parts) >= 2:
            name = ":".join(parts[:2])
            # Handle namespaced models: org/model:tag
            if len(parts) > 2:
                name = "/".join(parts[:-1]) + ":" + parts[-1]
        elif parts:
            name = parts[0]
        else:
            continue

        results.append(Model(
            name=name,
            digest=digest,
            blob_path=blob_path,
            manifest_path=manifest_path,
            size=_total_size(manifest_path),
            modified=_mtime(manifest_path),
            template_sha256=_template_digest(manifest_path),
        ))

    return results


def get_model(name: str) -> Model | None:
    """Find a model by human name or sha256 digest.

    Supports:
    - Human form: "qwen3.8:27b", "huihui_ai/Qwen3.6-abliterated:35b"
    - Digest form: "sha256-5084e21b...", "sha256:5084e21b...", bare 64-hex
    """
    # Normalize digest form
    digest: str | None = None
    if name.startswith("sha256:"):
        digest = "sha256-" + name[7:]
    elif name.startswith("sha256-"):
        digest = name
    elif len(name) == 64 and all(c in "0123456789abcdef" for c in name.lower()):
        digest = "sha256-" + name.lower()

    if digest:
        # Fast path: direct blob lookup
        models_dir = find_models_dir()
        blob_path = models_dir / "blobs" / digest
        if blob_path.is_file():
            # Find the manifest that references this digest
            manifests_dir = models_dir / "manifests" / "registry.ollama.ai"
            for manifest_path in manifests_dir.rglob("*"):
                if not manifest_path.is_file():
                    continue
                if _model_digest(manifest_path) == digest:
                    rel = manifest_path.relative_to(manifests_dir)
                    parts = list(rel.parts)
                    if parts and parts[0] == "library":
                        parts = parts[1:]
                    if len(parts) >= 2:
                        model_name = ":".join(parts[:2])
                        if len(parts) > 2:
                            model_name = "/".join(parts[:-1]) + ":" + parts[-1]
                    elif parts:
                        model_name = parts[0]
                    else:
                        continue
                    return Model(
                        name=model_name,
                        digest=digest,
                        blob_path=blob_path,
                        manifest_path=manifest_path,
                        size=_total_size(manifest_path),
                        modified=_mtime(manifest_path),
                        template_sha256=_template_digest(manifest_path),
                    )
        return None

    # Human name lookup
    all_models = list_models()
    for model in all_models:
        if model.name == name or model.name == name.replace(":", "/"):
            return model
    return None
