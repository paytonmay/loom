#!/bin/sh
# Run the loom CLI from this repo's virtualenv.
exec "$(dirname "$0")/.venv/bin/python" -m loom "$@"
