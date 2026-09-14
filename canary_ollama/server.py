"""FastAPI API server for canary-ollama.

Provides HTTP endpoints for listing and scanning Ollama models.

Usage:
    python -m canary_ollama serve
    # or
    canary-ollama serve --host 0.0.0.0 --port 8420
"""

from __future__ import annotations

from typing import Any

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except ImportError:
    raise ImportError(
        "FastAPI not installed. Install with: pip install canary-ollama[server]"
    )


class ScanRequest(BaseModel):
    """Request body for scan endpoint."""

    name: str
    fail_on: str = "warn"
    deep_tokenizer: bool = True
    bundle: bool = True
    json_output: bool = True
    sarif: bool = False
    policy: str | None = None
    baseline: str | None = None


class ScanAllRequest(BaseModel):
    """Request body for scan-all endpoint."""

    fail_on: str = "warn"
    deep_tokenizer: bool = True
    bundle: bool = True


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="canary-ollama",
        description="Audit Ollama models for poisoning — API server",
        version="0.1.0",
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        """Health check endpoint."""
        from canary_ollama.models import find_models_dir
        from canary_ollama.scanner import _find_canary

        checks: dict[str, Any] = {"status": "ok"}
        try:
            find_models_dir()
            checks["models_dir"] = "ok"
        except FileNotFoundError:
            checks["models_dir"] = "missing"
            checks["status"] = "degraded"

        try:
            _find_canary()
            checks["canary"] = "ok"
        except FileNotFoundError:
            checks["canary"] = "missing"
            checks["status"] = "degraded"

        return checks

    @app.get("/models")
    def list_models_endpoint() -> list[dict[str, Any]]:
        """List all local Ollama models."""
        from canary_ollama.models import list_models

        return [m.to_dict() for m in list_models()]

    @app.get("/models/{name:path}")
    def get_model_endpoint(name: str) -> dict[str, Any]:
        """Get details for a single model."""
        from canary_ollama.models import get_model

        model = get_model(name)
        if model is None:
            raise HTTPException(status_code=404, detail=f"Model not found: {name}")
        return model.to_dict()

    @app.post("/scan")
    def scan_model_endpoint(req: ScanRequest) -> dict[str, Any]:
        """Scan a single model for poisoning."""
        from canary_ollama.scanner import scan_model

        try:
            result = scan_model(
                req.name,
                fail_on=req.fail_on,
                deep_tokenizer=req.deep_tokenizer,
                bundle=req.bundle,
                json_output=req.json_output,
                sarif=req.sarif,
                policy=req.policy,
                baseline=req.baseline,
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except FileNotFoundError as e:
            raise HTTPException(status_code=503, detail=str(e))

        return result.to_dict()

    @app.get("/scan/{name:path}")
    def scan_model_get_endpoint(name: str) -> dict[str, Any]:
        """Scan a model via GET (convenience endpoint)."""
        from canary_ollama.scanner import scan_model

        try:
            result = scan_model(name)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except FileNotFoundError as e:
            raise HTTPException(status_code=503, detail=str(e))

        return result.to_dict()

    @app.post("/scan/all")
    def scan_all_endpoint(req: ScanAllRequest) -> dict[str, Any]:
        """Scan all local models."""
        from canary_ollama.scanner import scan_all

        results = scan_all(
            fail_on=req.fail_on,
            deep_tokenizer=req.deep_tokenizer,
            bundle=req.bundle,
        )

        scanned = sum(1 for r in results if r.rc == 0)
        warned = sum(1 for r in results if r.has_warnings)
        failed = sum(1 for r in results if r.has_failures)

        return {
            "results": [r.to_dict() for r in results],
            "summary": {
                "total": len(results),
                "scanned": scanned,
                "warned": warned,
                "failed": failed,
            },
        }

    @app.get("/diff")
    def diff_endpoint(a: str, b: str) -> dict[str, str]:
        """Diff two models."""
        from canary_ollama.scanner import diff_models

        try:
            output = diff_models(a, b)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        return {"diff": output}

    return app
