#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
binary=${1:?Usage: tests/test_transparent_linux.sh /absolute/path/to/linux/meow [--tcp-only]}
shift
test -f "$binary"
binary=$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")
docker build -t meow-transparent-linux-test "$root/tests/transparent-linux"
docker run --rm --privileged -v "$binary:/usr/local/bin/meow:ro" meow-transparent-linux-test "$@"
