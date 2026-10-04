#!/usr/bin/env bash
# Run the AI Triage test suite in its own Python environment.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: run-tests.sh [--help] [pytest arguments...]

Creates .venv-dev on first use, installs the pinned test dependencies, lints the
shell scripts when shellcheck is available, and runs pytest.

Examples:
  ./run-tests.sh
  ./run-tests.sh tests/test_guard.py -k kubectl

Exit codes: the exit code of shellcheck or pytest; 1 if setup fails.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv="${root}/.venv-dev"

if [[ ! -x "${venv}/bin/python" ]]; then
  python3 -m venv "${venv}"
fi
"${venv}/bin/python" -m pip install --quiet --disable-pip-version-check -r "${root}/requirements-dev.txt"

# Lint only the shell scripts that exist, so the suite runs while the project is still being built.
shell_scripts=()
for script in "${root}/install.sh" "${root}/run-tests.sh" "${root}/skill/ai-triage/scripts/guard_hook.sh"; do
  if [[ -f "${script}" ]]; then
    shell_scripts+=("${script}")
  fi
done
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "${shell_scripts[@]}"
else
  echo "shellcheck not found; skipping the shell lint." >&2
fi

cd "${root}"
exec "${venv}/bin/python" -m pytest "$@"
