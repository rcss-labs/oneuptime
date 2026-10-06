#!/usr/bin/env bash
# PreToolUse hook wrapper for the AI Triage guard.
# Runs guard_hook.py with the skill's own Python. If that Python is missing or
# the script fails, a text-only fallback denies:
#   - any payload that mentions aws or kubectl, opensearch_query, or a configured OpenSearch host;
#   - the file tools on any path under the cases root or a skill folder;
#   - every OneUptime, Slack, Atlassian or Confluence connector tool, reads included.
# What the fallback cannot cover: aws or kubectl reached without those words (a script
# or alias that calls them), a path or host written in pieces or encoded, a cases root
# the config names in a form other than a plain path, and every other connector.
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
# JSON may escape a slash as \/; matching works on the text without backslashes.
plain="${payload//\\/}"

config_dir="${skill_dir}/config"
fallback_skill_dir=""
if [[ "${AI_TRIAGE_TEST:-}" == "1" && -n "${AI_TRIAGE_SKILL_DIR:-}" ]]; then
  fallback_skill_dir="${AI_TRIAGE_SKILL_DIR}"
  config_dir="${AI_TRIAGE_SKILL_DIR}/config"
fi
config_file="${config_dir}/triage-config.yaml"

# The cases root as the config states it (a plain path, ~ expanded), else the default.
cases_root="${HOME:-}/.ai-triage/cases"
if [[ -r "${config_file}" ]]; then
  configured="$(sed -n 's/^cases_dir:[[:space:]]*//p' "${config_file}" | head -n 1 | tr -d "\"'")"
  if [[ -n "${configured}" ]]; then
    cases_root="${configured/#\~/${HOME:-}}"
  fi
fi

contains() {
  [[ -n "$2" ]] && printf '%s' "$1" | grep -Fqi -- "$2"
}

fallback_reason_for_payload() {
  if printf '%s' "${plain}" | grep -Eq 'aws|kubectl|opensearch_query'; then
    return 0
  fi
  if [[ -r "${config_file}" ]]; then
    local host
    while IFS= read -r host; do
      if contains "${plain}" "${host}"; then
        return 0
      fi
    done < <(sed -n 's|^[[:space:]]*endpoint:[[:space:]]*["'"'"']*https\{0,1\}://\([^/:"'"'"' ]*\).*|\1|p' "${config_file}")
  fi
  local tool
  tool="$(printf '%s' "${plain}" | grep -Eo '"tool_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/')"
  case "${tool}" in
    Write|Edit|MultiEdit|NotebookEdit)
      local marker
      for marker in "${cases_root}" "${skill_dir}" "${fallback_skill_dir}" ".ai-triage/cases" ".claude/skills/ai-triage"; do
        if contains "${plain}" "${marker}"; then
          return 0
        fi
      done
      ;;
    mcp__*)
      if printf '%s' "${tool}" | grep -Eqi 'oneuptime|slack|atlassian|confluence'; then
        return 0
      fi
      ;;
  esac
  return 1
}

# No word boundaries: JSON escapes such as \n or \t hide the boundary before the tool
# name, and a false deny is acceptable when the guard itself is broken.
deny_if_sensitive() {
  local reason="$1"
  if fallback_reason_for_payload; then
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
