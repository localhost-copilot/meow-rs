#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 2 ]; then
    echo "usage: $0 MIHOMO_CHECKOUT OUTPUT_BINARY" >&2
    exit 2
fi
reference=$(cd "$1" && pwd)
source_dir=$(cd "$(dirname "$0")" && pwd)
output_dir=$(cd "$(dirname "$2")" && pwd)
output="$output_dir/$(basename "$2")"
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/meow-reference-gateway.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
cp "$source_dir/main.go" "$build_dir/main.go"
cd "$build_dir"
go mod init github.com/metacubex/mihomo/phase-zero-probe
go mod edit -require=github.com/metacubex/mihomo@v0.0.0
go mod edit "-replace=github.com/metacubex/mihomo=$reference"
# A main module does not inherit its dependency's replace directives. The
# referenced checkout uses single-line replacements, which we carry verbatim.
awk '/^replace / { print }' "$reference/go.mod" >> go.mod
go mod tidy
go build -o "$output" .
