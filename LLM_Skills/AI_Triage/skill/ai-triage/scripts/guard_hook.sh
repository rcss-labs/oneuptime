#!/usr/bin/env bash
# PreToolUse hook wrapper for the AI Triage guard.
# Runs guard_hook.py with the skill's own Python. If that Python is missing or
# the script fails, commands that mention aws or kubectl are denied.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: guard_hook.sh [--help]

Reads a Claude Code PreToolUse hook payload on stdin and prints a permission
decision as JSON. Prints nothing when the guard has no opinion.
Always exits 0.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

skill_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${skill_dir}/.venv/bin/python"
# A different interpreter is honoured only in tests.
if [[ "${AI_TRIAGE_TEST:-}" == "1" && -n "${AI_TRIAGE_PYTHON:-}" ]]; then
  python_bin="${AI_TRIAGE_PYTHON}"
fi
payload="$(cat)"

# No word boundaries: JSON escapes such as \n or \t hide the boundary before the tool
# name, and a false deny is acceptable when the guard itself is broken.
deny_if_sensitive() {
  local reason="$1"
  if printf '%s' "${payload}" | grep -Eq 'aws|kubectl'; then
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"AI Triage guard: %s"}}\n' "${reason}"
  fi
}

if [[ ! -x "${python_bin}" ]]; then
  deny_if_sensitive "the skill is not installed correctly (no Python environment). Run install.sh again."
  exit 0
fi

if output="$(printf '%s' "${payload}" | "${python_bin}" "${skill_dir}/scripts/guard_hook.py" 2>/dev/null)"; then
  if [[ -n "${output}" ]]; then
    printf '%s\n' "${output}"
  fi
else
  deny_if_sensitive "the guard failed to run. Run install.sh again."
fi
exit 0
