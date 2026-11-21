#!/usr/bin/env bash
# MobileTrace AI launcher.  Usage: ./run.sh [web|desktop|setup|test|doctor] [--no-open] [--port N]
cd "$(dirname "$0")" || exit 1
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js not found. Install Node 20.11+ (22 LTS recommended) from https://nodejs.org" >&2
  exit 1
fi
exec node run.mjs "$@"
