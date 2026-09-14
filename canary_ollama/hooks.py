"""Ollama model pull watcher — auto-scan on new models.

Two modes:
- Poll mode: check manifests dir every N seconds for new/changed models
- Watch mode: use watchdog for filesystem events (requires canary-ollama[watch])
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Callable

from canary_ollama.models import Model, find_models_dir, list_models
from canary_ollama.scanner import ScanResult, scan_model


def _digest_file(path: Path) -> str:
    """Quick SHA-256 of a file for change detection."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot_models() -> dict[str, str]:
    """Capture current model digests for change detection."""
    return {m.digest: _digest_file(m.manifest_path) for m in list_models()}


def watch(
    interval: int = 300,
    fail_on: str = "warn",
    callback: Callable[[ScanResult], None] | None = None,
    on_error: Callable[[Model, Exception], None] | None = None,
) -> None:
    """Watch for new or changed models and auto-scan them.

    Args:
        interval: Seconds between polls.
        fail_on: Severity threshold for canary scan.
        callback: Called with each ScanResult after scanning.
        on_error: Called if scanning a model fails.
    """
    print(f"Watching for new models (poll every {interval}s)...")

    known = _snapshot_models()
    print(f"Tracking {len(known)} existing model(s).")

    try:
        while True:
            time.sleep(interval)

            try:
                current = _snapshot_models()
            except FileNotFoundError:
                print("Models directory not found, retrying...")
                continue

            # Detect new models
            new_digests = set(current.keys()) - set(known.keys())
            # Detect changed models (same digest, different manifest hash)
            changed_digests = {
                d for d in set(current.keys()) & set(known.keys())
                if current[d] != known[d]
            }

            for digest in new_digests:
                models = list_models()
                model = next((m for m in models if m.digest == digest), None)
                if model is None:
                    continue

                print(f"\nNew model detected: {model.name} ({model.short_digest})")
                try:
                    result = scan_model(model, fail_on=fail_on)
                    if callback:
                        callback(result)
                    else:
                        severity = "CLEAN" if result.clean else "WARN" if result.has_warnings else "FAIL"
                        print(f"  Result: {severity} — {len(result.findings)} finding(s)")
                except Exception as e:
                    if on_error:
                        on_error(model, e)
                    else:
                        print(f"  Error scanning {model.name}: {e}")

            for digest in changed_digests:
                models = list_models()
                model = next((m for m in models if m.digest == digest), None)
                if model is None:
                    continue

                print(f"\nModel changed: {model.name} ({model.short_digest})")
                try:
                    result = scan_model(model, fail_on=fail_on)
                    if callback:
                        callback(result)
                    else:
                        severity = "CLEAN" if result.clean else "WARN" if result.has_warnings else "FAIL"
                        print(f"  Result: {severity} — {len(result.findings)} finding(s)")
                except Exception as e:
                    if on_error:
                        on_error(model, e)
                    else:
                        print(f"  Error scanning {model.name}: {e}")

            known = current

    except KeyboardInterrupt:
        print("\nStopped watching.")


def watch_watchdog(
    fail_on: str = "warn",
    callback: Callable[[ScanResult], None] | None = None,
) -> None:
    """Watch using watchdog filesystem events (requires canary-ollama[watch]).

    This is more efficient than polling — triggers on actual file changes.
    """
    try:
        from watchdog.events import FileSystemEvent, FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        raise ImportError(
            "watchdog not installed. Install with: pip install canary-ollama[watch]"
        )

    models_dir = find_models_dir()
    manifests_dir = models_dir / "manifests" / "registry.ollama.ai"

    class ManifestHandler(FileSystemEventHandler):
        def on_created(self, event: FileSystemEvent) -> None:
            if event.is_directory:
                return
            self._handle(event.src_path)

        def on_modified(self, event: FileSystemEvent) -> None:
            if event.is_directory:
                return
            self._handle(event.src_path)

        def _handle(self, path_str: str) -> None:
            path = Path(path_str)
            if not path.is_file():
                return

            # Find the model for this manifest
            from canary_ollama.models import _model_digest

            digest = _model_digest(path)
            if not digest:
                return

            models = list_models()
            model = next((m for m in models if m.digest == digest), None)
            if model is None:
                return

            print(f"\nModel event: {model.name} ({model.short_digest})")
            try:
                result = scan_model(model, fail_on=fail_on)
                if callback:
                    callback(result)
                else:
                    severity = "CLEAN" if result.clean else "WARN" if result.has_warnings else "FAIL"
                    print(f"  Result: {severity} — {len(result.findings)} finding(s)")
            except Exception as e:
                print(f"  Error scanning {model.name}: {e}")

    handler = ManifestHandler()
    observer = Observer()
    observer.schedule(handler, str(manifests_dir), recursive=True)
    observer.start()

    print(f"Watching {manifests_dir} for changes...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopped watching.")

    observer.join()
