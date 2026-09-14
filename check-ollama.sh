#!/usr/bin/env bash
# check-ollama.sh [NAME] [--json|--sarif|--fail-on X]
#   no args            -> list all local models (human name, sha256 blob, size, mtime)
#   NAME               -> canary-scan that models GGUF blob
#                          human form    qwen3.8:7b | huihui_ai/Qwen3.6-abliterated:35b
#                          digest form   sha256-<64hex> | sha256:<64hex>
set -euo pipefail

MODELS_DIR=""
NAME=""
DIGEST=""
CANARY_ARGS=()

usage() {
  cat <<'EOF'
usage: check-ollama.sh [NAME] [--json|--sarif|--fail-on X]

  no NAME  : list every local model — human name, sha256 blob name, size, mtime.
  NAME     : run c4nary `canary scan` on that model's GGUF blob.
             NAME may be either form:
               human   qwen3.8:7b          huihui_ai/Qwen3.6-abliterated:35b
               digest  sha256-448bdcae...  (64 hex, with or without prefix)
  --json / --sarif / --fail-on X are passed through to canary scan.
  Default scan args: --fail-on warn --deep-tokenizer
  Exit: 0 clean/listed, 1 no such model / not found, 2 warnings or failures.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)     CANARY_ARGS+=(--json) ;;
    --sarif)    CANARY_ARGS+=(--sarif) ;;
    --fail-on)  shift; CANARY_ARGS+=(--fail-on "${1:-}") ;;
    -h|--help)  usage; exit 0 ;;
    -*)         echo "unknown flag: $1" >&2; usage >&2; exit 2 ;;
    *)          NAME="$1" ;;
  esac
  shift
done

if [[ -z "$MODELS_DIR" && -n "${OLLAMA_MODELS:-}" ]]; then
  MODELS_DIR="$OLLAMA_MODELS"
fi
if [[ -z "$MODELS_DIR" ]]; then
  for d in "$HOME/.ollama/models" /mnt/ai-models/Ollama/models; do
    if [[ -d "$d/manifests/registry.ollama.ai" ]]; then MODELS_DIR="$d"; break; fi
  done
fi
MODELS_DIR="${MODELS_DIR:-$HOME/.ollama/models}"
MANIFESTS="$MODELS_DIR/manifests/registry.ollama.ai"
BLOBS="$MODELS_DIR/blobs"

[[ -d "$MANIFESTS" ]] || { echo "error: $MANIFESTS not found" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "error: jq required but not installed" >&2; exit 1; }

if [[ "$NAME" == sha256:* ]]; then
  DIGEST="${NAME#sha256:}"
elif [[ "$NAME" == sha256-* ]]; then
  DIGEST="${NAME#sha256-}"
elif [[ -n "$NAME" && "$NAME" =~ ^[0-9a-f]{64}$ ]]; then
  DIGEST="$NAME"
fi

if [[ -z "$NAME" && -z "$DIGEST" ]]; then
  mode=list
else
  mode=scan
  if [[ -z "$DIGEST" ]]; then
    NAME="$(printf '%s' "$NAME" | tr ':' '/')"
  else
    [[ "$DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo "error: bad digest: $NAME" >&2; exit 1; }
  fi
  command -v canary >/dev/null 2>&1 || { echo "error: canary (c4nary) not found — pip install c4nary" >&2; exit 1; }
  [[ ${#CANARY_ARGS[@]} -eq 0 ]] && CANARY_ARGS+=(--fail-on warn --deep-tokenizer)
fi

model_digest() {
  jq -r '.layers[] | select(.mediaType=="application/vnd.ollama.image.model") | .digest' "$1" 2>/dev/null | head -n1
}

list_all() {
  local f rel name digest size mtime ts
  while IFS= read -r f; do
    digest="$(model_digest "$f" || true)"
    [[ -n "$digest" && "$digest" != "null" ]] || continue
    rel="${f#$MANIFESTS/}"
    rel="${rel#library/}"
    name="${rel%/*}:${rel##*/}"
    size="$(jq -r '[.layers[].size] | add' "$f" 2>/dev/null || echo 0)"
    if command -v numfmt >/dev/null 2>&1; then
      size="$(numfmt --to=iec <<<"$size" 2>/dev/null || echo "$size")"
    else
      size="$size B"
    fi
    ts="$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0)"
    mtime="$(date -d "@$ts" '+%Y-%m-%d %H:%M' 2>/dev/null || date -r "$ts" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "?")"
    printf '%-55s  %-71s %8s  %s\n' "$name" "${digest/:/-}" "$size" "$mtime"
  done < <(find "$MANIFESTS" -type f | sort)
}

scanned=0; failed=0; missing=0

scan_one() {
  local rel="$1" blobpath="$2"
  printf '\n== MODEL: %s\n== BLOB:  %s\n' "$rel" "$blobpath"
  set +e
  canary scan "$blobpath" "${CANARY_ARGS[@]}"
  local rc=$?
  set -e
  if   (( rc == 0 )); then
    scanned=$((scanned+1))
  elif (( rc == 1 )); then
    printf '\a!!! WARN on %s (rc=1)\n' "$rel" >&2
    if command -v notify-send >/dev/null 2>&1; then
      notify-send -u normal "c4nary WARN: $rel" "WARN findings (rc=1)"
    fi
    failed=$((failed+1))
  elif (( rc == 2 )); then
    printf '\a!!! PROBLEM on %s (rc=2)\n' "$rel" >&2
    if command -v notify-send >/dev/null 2>&1; then
      notify-send -u critical "c4nary PROBLEM: $rel" "FAIL findings (rc=2)"
    fi
    failed=$((failed+1))
  else
    printf 'CANARY ERROR on %s (rc=%d)\n' "$rel" "$rc" >&2
    failed=$((failed+1))
  fi
}

if [[ "$mode" == list ]]; then
  list_all
  exit 0
fi

if [[ -n "$DIGEST" ]]; then
  blobpath="$BLOBS/sha256-$DIGEST"
  found=""
  while IFS= read -r f; do
    d="$(model_digest "$f" || true)"
    if [[ "$d" == "sha256:$DIGEST" ]]; then found="$f"; break; fi
  done < <(find "$MANIFESTS" -type f)
  if [[ -n "$found" ]]; then
    scan_one "${found#$MANIFESTS/}" "$blobpath"
  elif [[ -f "$blobpath" ]]; then
    scan_one "sha256-$DIGEST" "$blobpath"
  else
    echo "no such model: $NAME" >&2
    exit 1
  fi
else
  matched=0
  while IFS= read -r f; do
    [[ "$f" == *"/$NAME" ]] || continue
    matched=1
    digest="$(model_digest "$f" || true)"
    [[ -n "$digest" && "$digest" != "null" ]] || continue
    blobpath="$BLOBS/${digest/:/-}"
    if [[ ! -f "$blobpath" ]]; then
      printf 'MISS  %-55s %s\n' "${f#$MANIFESTS/}" "${digest/:/-}"
      missing=$((missing+1))
      continue
    fi
    scan_one "${f#$MANIFESTS/}" "$blobpath"
  done < <(find "$MANIFESTS" -type f)
  if (( matched == 0 )); then
    echo "no such model: $NAME" >&2
    exit 1
  fi
fi

echo ""
echo "summary: scanned=$scanned canary_errors=$failed blobs_missing=$missing"
[[ "$failed" -eq 0 ]] || exit 2