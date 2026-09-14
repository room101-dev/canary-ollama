"""Subprocess wrapper around c4nary for model scanning."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from canary_ollama.models import Model, get_model, list_models


@dataclass(frozen=True)
class Finding:
    """A single canary finding."""

    rule: str  # "TPL021", "TOK012", etc.
    severity: str  # "FAIL", "WARN", "INFO"
    message: str
    line: int | None = None
    column: int | None = None
    context: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }
        if self.line is not None:
            d["line"] = self.line
        if self.column is not None:
            d["column"] = self.column
        if self.context:
            d["context"] = self.context
        return d


@dataclass(frozen=True)
class ScanResult:
    """Result of scanning a single model."""

    model: Model
    rc: int  # 0=clean, 1=warn, 2=fail
    findings: list[Finding]
    template_sha256: str
    raw_output: str
    elapsed_ms: int

    @property
    def clean(self) -> bool:
        return self.rc == 0

    @property
    def has_warnings(self) -> bool:
        return any(f.severity == "WARN" for f in self.findings)

    @property
    def has_failures(self) -> bool:
        return any(f.severity == "FAIL" for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model.to_dict(),
            "rc": self.rc,
            "findings": [f.to_dict() for f in self.findings],
            "template_sha256": self.template_sha256,
            "elapsed_ms": self.elapsed_ms,
            "clean": self.clean,
            "has_warnings": self.has_warnings,
            "has_failures": self.has_failures,
        }


def _find_canary() -> str:
    """Locate the canary binary."""
    path = shutil.which("canary")
    if path:
        return path
    raise FileNotFoundError(
        "c4nary not found. Install with: pip install c4nary"
    )


def _parse_json_output(raw: str) -> list[Finding]:
    """Parse canary JSON output into Finding objects."""
    findings: list[Finding] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Not JSON, try line-by-line parsing
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # Try to extract finding info from text output
            findings.append(Finding(
                rule="UNKNOWN",
                severity="INFO",
                message=line,
            ))
        return findings

    # Handle both single-object and array formats
    if isinstance(data, dict):
        data = [data]

    for item in data:
        if not isinstance(item, dict):
            continue
        findings.append(Finding(
            rule=item.get("rule", item.get("id", "UNKNOWN")),
            severity=item.get("severity", item.get("level", "INFO")).upper(),
            message=item.get("message", item.get("description", "")),
            line=item.get("line"),
            column=item.get("column"),
            context=item.get("context"),
        ))

    return findings


def scan_model(
    name_or_model: str | Model,
    *,
    fail_on: str = "warn",
    deep_tokenizer: bool = True,
    bundle: bool = True,
    json_output: bool = True,
    sarif: bool = False,
    policy: str | None = None,
    baseline: str | None = None,
    manifest_path: str | None = None,
    remote: str | None = None,
) -> ScanResult:
    """Scan a single model for poisoning.

    Args:
        name_or_model: Model name (human or digest) or Model object.
        fail_on: Severity threshold for non-zero exit ("info", "warn", "fail").
        deep_tokenizer: Materialize full vocab for TOK012/TOK015 checks.
        bundle: Audit config, tokenizer.json, card, auto_map Python.
        json_output: Request JSON output from canary.
        sarif: Request SARIF 2.1.0 output.
        policy: Custom policy file path.
        baseline: Baseline file for comparison.
        manifest_path: Manifest file for drift detection.
        remote: HuggingFace remote to scan (org/repo format).

    Returns:
        ScanResult with findings and metadata.
    """
    canary = _find_canary()

    # Resolve model
    if isinstance(name_or_model, str):
        model = get_model(name_or_model)
        if model is None:
            raise ValueError(f"Model not found: {name_or_model}")
    else:
        model = name_or_model

    # Build command
    cmd = [canary, "scan"]

    if json_output and not sarif:
        cmd.append("--json")
    if sarif:
        cmd.append("--sarif")
    if deep_tokenizer:
        cmd.append("--deep-tokenizer")
    if bundle:
        cmd.append("--bundle")
    if fail_on:
        cmd.extend(["--fail-on", fail_on])
    if policy:
        cmd.extend(["--policy", policy])
    if baseline:
        cmd.extend(["--baseline", baseline])
    if manifest_path:
        cmd.extend(["--manifest", manifest_path])
    if remote:
        cmd.extend(["--remote", remote])

    # Target: blob path or remote
    if remote:
        cmd.append(remote)
    else:
        cmd.append(str(model.blob_path))

    # Execute
    t0 = time.monotonic()
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,  # 5 minute timeout
    )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    # Parse output
    raw = result.stdout + result.stderr
    findings = _parse_json_output(result.stdout) if json_output else _parse_json_output(raw)

    return ScanResult(
        model=model,
        rc=result.returncode,
        findings=findings,
        template_sha256=model.template_sha256,
        raw_output=raw,
        elapsed_ms=elapsed_ms,
    )


def scan_all(
    *,
    fail_on: str = "warn",
    deep_tokenizer: bool = True,
    bundle: bool = True,
    **kwargs: Any,
) -> list[ScanResult]:
    """Scan every local model.

    Returns a list of ScanResults, one per model.
    """
    models = list_models()
    results: list[ScanResult] = []
    for model in models:
        try:
            result = scan_model(
                model,
                fail_on=fail_on,
                deep_tokenizer=deep_tokenizer,
                bundle=bundle,
                **kwargs,
            )
            results.append(result)
        except Exception as e:
            # Create an error result
            results.append(ScanResult(
                model=model,
                rc=2,
                findings=[Finding(rule="ERROR", severity="FAIL", message=str(e))],
                template_sha256=model.template_sha256,
                raw_output=str(e),
                elapsed_ms=0,
            ))
    return results


def diff_models(a: str | Model, b: str | Model) -> str:
    """Run canary diff between two models.

    Returns the raw diff output.
    """
    canary = _find_canary()

    model_a = get_model(a) if isinstance(a, str) else a
    model_b = get_model(b) if isinstance(b, str) else b

    if model_a is None:
        raise ValueError(f"Model not found: {a}")
    if model_b is None:
        raise ValueError(f"Model not found: {b}")

    cmd = [canary, "diff", str(model_a.blob_path), str(model_b.blob_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return result.stdout + result.stderr


def generate_manifest(*, output: str = "known_good.json") -> Path:
    """Generate a canary baseline manifest for drift detection.

    Returns the path to the generated manifest file.
    """
    canary = _find_canary()
    cmd = [canary, "scan", "--manifest", output]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to generate manifest: {result.stderr}")
    return Path(output)
