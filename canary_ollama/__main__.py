"""CLI entry point: python -m canary_ollama."""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from typing import Sequence


def _cmd_list(args: argparse.Namespace) -> int:
    """List all local models."""
    from canary_ollama.models import list_models

    models = list_models()
    if not models:
        print("No models found.", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps([m.to_dict() for m in models], indent=2))
        return 0

    # Human-readable table
    print(f"{'NAME':<55}  {'DIGEST':<20} {'SIZE':>8}  {'MODIFIED'}")
    print("-" * 100)
    for m in models:
        print(f"{m.name:<55}  {m.short_digest:<20} {m.size_human:>8}  {m.modified:%Y-%m-%d %H:%M}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Scan a model."""
    from canary_ollama.scanner import scan_model

    try:
        result = scan_model(
            args.name,
            fail_on=args.fail_on,
            deep_tokenizer=not args.no_deep_tokenizer,
            bundle=not args.no_bundle,
            json_output=args.json,
            sarif=args.sarif,
            policy=args.policy,
            baseline=args.baseline,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json or args.sarif:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        # Human-readable output
        print(f"\n== MODEL: {result.model.name}")
        print(f"== BLOB:  {result.model.blob_path}")
        print(f"== DIGEST: {result.model.short_digest}")
        print(f"== TEMPLATE SHA256: {result.template_sha256[:16]}...")
        print(f"== TIME: {result.elapsed_ms}ms")

        if result.findings:
            print(f"\nFindings ({len(result.findings)}):")
            for f in result.findings:
                prefix = {"FAIL": "!!!", "WARN": " ! ", "INFO": " i "}.get(f.severity, " ? ")
                print(f"  {prefix} [{f.rule}] {f.message}")
        else:
            print("\nNo findings.")

        # Summary
        severity = "CLEAN" if result.clean else "WARN" if result.has_warnings else "FAIL"
        print(f"\nResult: {severity} (rc={result.rc})")

    return result.rc


def _cmd_scan_all(args: argparse.Namespace) -> int:
    """Scan all models."""
    from canary_ollama.scanner import scan_all

    results = scan_all(
        fail_on=args.fail_on,
        deep_tokenizer=not args.no_deep_tokenizer,
        bundle=not args.no_bundle,
    )

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        scanned = sum(1 for r in results if r.rc == 0)
        warned = sum(1 for r in results if r.has_warnings)
        failed = sum(1 for r in results if r.has_failures)
        errors = sum(1 for r in results if r.rc not in (0, 1, 2))

        print(f"\nScanned: {len(results)}")
        print(f"  Clean:  {scanned}")
        print(f"  Warn:   {warned}")
        print(f"  Fail:   {failed}")
        print(f"  Error:  {errors}")

        if failed or warned:
            print("\nFindings:")
            for r in results:
                if r.has_warnings or r.has_failures:
                    severity = "FAIL" if r.has_failures else "WARN"
                    print(f"  [{severity}] {r.model.name} — {len(r.findings)} finding(s)")

    return 2 if any(r.rc == 2 for r in results) else 1 if any(r.rc == 1 for r in results) else 0


def _cmd_diff(args: argparse.Namespace) -> int:
    """Diff two models."""
    from canary_ollama.scanner import diff_models

    try:
        output = diff_models(args.model_a, args.model_b)
        print(output)
        return 0
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _cmd_manifest(args: argparse.Namespace) -> int:
    """Generate a baseline manifest."""
    from canary_ollama.scanner import generate_manifest

    try:
        path = generate_manifest(output=args.output)
        print(f"Manifest written to: {path}")
        return 0
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _cmd_serve(args: argparse.Namespace) -> int:
    """Start the API server."""
    try:
        from canary_ollama.server import create_app
        import uvicorn
    except ImportError:
        print(
            "error: server dependencies not installed.\n"
            "Install with: pip install canary-ollama[server]",
            file=sys.stderr,
        )
        return 1

    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    """Watch for new models and auto-scan."""
    try:
        from canary_ollama.hooks import watch
    except ImportError:
        print(
            "error: watch dependencies not installed.\n"
            "Install with: pip install canary-ollama[watch]",
            file=sys.stderr,
        )
        return 1

    watch(interval=args.interval, fail_on=args.fail_on)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="canary-ollama",
        description="Audit Ollama models for poisoning.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              canary-ollama list                        # list all models
              canary-ollama scan qwen3.8:27b            # scan one model
              canary-ollama scan-all --json             # scan all, JSON output
              canary-ollama diff model-a model-b        # diff two models
              canary-ollama serve --port 8420           # start API server
              canary-ollama watch --interval 60         # watch for new models
        """),
    )
    sub = parser.add_subparsers(dest="command")

    # list
    p_list = sub.add_parser("list", help="list all local models")
    p_list.add_argument("--json", action="store_true", help="JSON output")
    p_list.set_defaults(func=_cmd_list)

    # scan
    p_scan = sub.add_parser("scan", help="scan a model for poisoning")
    p_scan.add_argument("name", help="model name or sha256 digest")
    p_scan.add_argument("--json", action="store_true", help="JSON output")
    p_scan.add_argument("--sarif", action="store_true", help="SARIF output")
    p_scan.add_argument("--fail-on", default="warn", help="fail threshold (default: warn)")
    p_scan.add_argument("--no-deep-tokenizer", action="store_true", help="skip deep tokenizer")
    p_scan.add_argument("--no-bundle", action="store_true", help="skip bundle audit")
    p_scan.add_argument("--policy", help="custom policy file")
    p_scan.add_argument("--baseline", help="baseline file for comparison")
    p_scan.set_defaults(func=_cmd_scan)

    # scan-all
    p_scan_all = sub.add_parser("scan-all", help="scan all local models")
    p_scan_all.add_argument("--json", action="store_true", help="JSON output")
    p_scan_all.add_argument("--fail-on", default="warn", help="fail threshold")
    p_scan_all.add_argument("--no-deep-tokenizer", action="store_true", help="skip deep tokenizer")
    p_scan_all.add_argument("--no-bundle", action="store_true", help="skip bundle audit")
    p_scan_all.set_defaults(func=_cmd_scan_all)

    # diff
    p_diff = sub.add_parser("diff", help="diff two models")
    p_diff.add_argument("model_a", help="first model")
    p_diff.add_argument("model_b", help="second model")
    p_diff.set_defaults(func=_cmd_diff)

    # manifest
    p_manifest = sub.add_parser("manifest", help="generate baseline manifest")
    p_manifest.add_argument("--output", default="known_good.json", help="output file")
    p_manifest.set_defaults(func=_cmd_manifest)

    # serve
    p_serve = sub.add_parser("serve", help="start API server")
    p_serve.add_argument("--host", default="0.0.0.0", help="bind host")
    p_serve.add_argument("--port", type=int, default=8420, help="bind port")
    p_serve.set_defaults(func=_cmd_serve)

    # watch
    p_watch = sub.add_parser("watch", help="watch for new models, auto-scan")
    p_watch.add_argument("--interval", type=int, default=300, help="poll interval (seconds)")
    p_watch.add_argument("--fail-on", default="warn", help="fail threshold")
    p_watch.set_defaults(func=_cmd_watch)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
