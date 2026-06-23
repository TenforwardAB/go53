#!/usr/bin/env bash
# Regenerate docs/roadmap.md from the go53 Roadmap GitHub Project.
# Requires `gh` authenticated with a token that can read the org project
# (read:project). See .github/workflows/roadmap.yml for the CI variant.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 scripts/gen_roadmap.py "$@"
