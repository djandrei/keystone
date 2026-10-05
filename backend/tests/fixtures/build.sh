#!/usr/bin/env bash
# Rebuild bin/ from src/. The binary is committed so the tests never compile
# anything (the worker image has no compiler); rebuild only when a source changes.
# No -g: Ghidra should recover the program from the code, not from debug info.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
mkdir -p bin
gcc -O0 -fno-pie -no-pie -fno-stack-protector -o bin/keycheck.x86_64 src/keycheck.c
chmod 0644 bin/keycheck.x86_64
