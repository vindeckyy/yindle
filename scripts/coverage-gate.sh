#!/usr/bin/env bash
# coverage-gate.sh — enforce per-crate line coverage threshold across every
# workspace package using cargo-llvm-cov.
#
# Usage:
#   ./scripts/coverage-gate.sh [OPTIONS] [PACKAGE...]
#
# Options:
#   --threshold N   Minimum line coverage percentage per crate (default: ${THRESHOLD:-95})
#   --summary       Run all packages and print a consolidated PASS/FAIL table
#   --fail-fast     Abort immediately on the first package below threshold
#   --package PKG   Check a specific workspace package (may be repeated)
#   -h, --help      Show this help message
#
# Environment:
#   THRESHOLD       Default minimum line coverage percent (default: 95)

set -euo pipefail
cd "$(dirname "$0")/.."

command -v cargo >/dev/null 2>&1 || PATH="$HOME/.cargo/bin:$PATH"
[ -d "$HOME/.cargo/bin" ] && case ":$PATH:" in *":$HOME/.cargo/bin:"*) ;; *) PATH="$HOME/.cargo/bin:$PATH" ;; esac

THRESHOLD="${THRESHOLD:-95}"
SUMMARY=0
FAIL_FAST=0
PACKAGES=()

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --threshold)
            [ $# -ge 2 ] || { echo "coverage-gate.sh: --threshold requires a number" >&2; exit 2; }
            THRESHOLD="$2"; shift ;;
        --threshold=*)
            THRESHOLD="${1#--threshold=}" ;;
        --summary)
            SUMMARY=1 ;;
        --fail-fast)
            FAIL_FAST=1 ;;
        --package|-p)
            [ $# -ge 2 ] || { echo "coverage-gate.sh: --package requires a package name" >&2; exit 2; }
            PACKAGES+=("$2"); shift ;;
        --package=*)
            PACKAGES+=("${1#--package=}") ;;
        -h|--help)
            usage; exit 0 ;;
        -*)
            echo "coverage-gate.sh: unknown option: $1" >&2; exit 2 ;;
        *)
            PACKAGES+=("$1") ;;
    esac
    shift
done

if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "coverage-gate.sh: cargo-llvm-cov is not installed." >&2
    echo "  Install with: rustup component add llvm-tools-preview && cargo install cargo-llvm-cov --locked" >&2
    exit 1
fi

# Discover all workspace member packages dynamically when none are specified.
if [ "${#PACKAGES[@]}" -eq 0 ]; then
    while IFS= read -r pkg; do
        [ -n "$pkg" ] && PACKAGES+=("$pkg")
    done < <(
        cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
meta = json.load(sys.stdin)
member_ids = set(meta.get("workspace_members", []))
names = sorted(p["name"] for p in meta.get("packages", []) if p["id"] in member_ids)
for n in names:
    print(n)
'
    )
fi

if [ "${#PACKAGES[@]}" -eq 0 ]; then
    echo "coverage-gate.sh: no workspace packages found" >&2
    exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

echo "=== Yindle Per-Crate Coverage Gate (threshold: >= ${THRESHOLD}% lines) ==="

for pkg in "${PACKAGES[@]}"; do
    OUT_FILE=$(mktemp)
    RC=0
    if [ "$SUMMARY" = 1 ]; then
        cargo llvm-cov --package "$pkg" --fail-under-lines "$THRESHOLD" >"$OUT_FILE" 2>&1 || RC=$?
    else
        echo ""
        echo "--- Checking package: $pkg ---"
        cargo llvm-cov --package "$pkg" --fail-under-lines "$THRESHOLD" 2>&1 | tee "$OUT_FILE" || RC=${PIPESTATUS[0]}
    fi

    # Extract line coverage % from llvm-cov TOTAL row (column 10 is Lines Cover%).
    LINE_COV=$(awk '/^TOTAL[[:space:]]/ { print $10; exit }' "$OUT_FILE")
    [ -n "$LINE_COV" ] || LINE_COV="N/A"

    if [ "$RC" -eq 0 ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        STATUS="PASS"
        RESULTS+=("$(printf '%-28s %-8s %s' "$pkg" "$STATUS" "$LINE_COV")")
        if [ "$SUMMARY" = 1 ]; then
            printf '  [PASS] %-26s %s\n' "$pkg" "$LINE_COV"
        fi
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        STATUS="FAIL"
        RESULTS+=("$(printf '%-28s %-8s %s' "$pkg" "$STATUS" "$LINE_COV")")
        if [ "$SUMMARY" = 1 ]; then
            printf '  [FAIL] %-26s %s (< %s%%)\n' "$pkg" "$LINE_COV" "$THRESHOLD"
            tail -n 20 "$OUT_FILE" | sed 's/^/         /'
        fi
        rm -f "$OUT_FILE"
        if [ "$FAIL_FAST" = 1 ]; then
            echo "coverage-gate.sh: failing fast on $pkg ($LINE_COV < ${THRESHOLD}%)" >&2
            exit 1
        fi
        continue
    fi
    rm -f "$OUT_FILE"
done

echo ""
echo "=== Per-Crate Coverage Summary (threshold: >= ${THRESHOLD}% lines) ==="
printf '%-28s %-8s %s\n' "PACKAGE" "STATUS" "LINES"
printf '%-28s %-8s %s\n' "----------------------------" "--------" "--------"
for row in "${RESULTS[@]}"; do
    printf '%s\n' "$row"
done
echo ""
echo "Total: ${PASS_COUNT} passed, ${FAIL_COUNT} failed (out of ${#PACKAGES[@]} workspace packages)"

[ "$FAIL_COUNT" -eq 0 ]
