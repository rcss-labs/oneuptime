#!/usr/bin/env bash
# Install or upgrade the AI Triage skill into ~/.claude/skills/ai-triage.
set -euo pipefail

readonly EXIT_FAILURE=1
readonly EXIT_USAGE=2
readonly EXIT_PREREQUISITE=3

usage() {
  cat <<'USAGE'
Usage: install.sh [--dry-run] [--help]

Installs or upgrades the AI Triage skill in ~/.claude/skills/ai-triage.

  --dry-run   Print every step without changing anything.
  --help      Show this text.

An upgrade replaces the skill's code and keeps your config, service map, and
kubeconfig. They are backed up to ~/.ai-triage/backups/<timestamp>/ first.

Environment:
  AI_TRIAGE_SKIP_VENV=1   Do not create the Python environment (used by tests).

Exit codes: 0 done, 1 failure, 2 usage error, 3 missing prerequisite.
USAGE
}

dry_run=0
while (($# > 0)); do
  case "$1" in
    --dry-run) dry_run=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit "${EXIT_USAGE}"
      ;;
  esac
  shift
done

if [[ -z "${HOME:-}" || ! -d "${HOME}" ]]; then
  printf 'Error: %s\n' "HOME is not set to a directory" >&2
  exit "${EXIT_FAILURE}"
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="${script_dir}/skill/ai-triage"
dest_dir="${HOME}/.claude/skills/ai-triage"
backup_root="${HOME}/.ai-triage/backups"

log() { printf '%s\n' "$*"; }

# Say what happened, or in a dry run what would happen: announce <would text> <did text>.
announce() {
  if ((dry_run)); then
    log "[dry-run] Would $1"
  else
    log "$2"
  fi
}

fail() {
  local code="$1"
  shift
  printf 'Error: %s\n' "$*" >&2
  exit "${code}"
}

run() {
  if ((dry_run)); then
    log "[dry-run] Would run: $*"
  else
    "$@"
  fi
}

check_prerequisites() {
  [[ -f "${source_dir}/SKILL.md" ]] || fail "${EXIT_FAILURE}" "skill source not found at ${source_dir}"
  command -v aws >/dev/null 2>&1 || fail "${EXIT_PREREQUISITE}" "the aws command was not found. Install AWS CLI version 2."
  local aws_version
  aws_version="$(aws --version 2>&1)"
  [[ "${aws_version}" == aws-cli/2.* ]] || fail "${EXIT_PREREQUISITE}" "AWS CLI version 2 is required, found: ${aws_version}"
  command -v python3 >/dev/null 2>&1 || fail "${EXIT_PREREQUISITE}" "python3 was not found. Install Python 3.10 or newer."
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' ||
    fail "${EXIT_PREREQUISITE}" "Python 3.10 or newer is required."
  if ! command -v kubectl >/dev/null 2>&1; then
    log "Warning: kubectl was not found. It is needed only if you configure EKS clusters."
  fi
}

# Refuse to install into the repository: removing the old code would delete the source.
check_destination() {
  local message="the install folder points into the repository; remove the link and run again"
  if [[ -L "${dest_dir}" ]]; then
    fail "${EXIT_FAILURE}" "${message}"
  fi
  # Judge the nearest existing ancestor, so a linked ~/.claude is caught before the folder exists.
  local nearest="${dest_dir}"
  while [[ ! -d "${nearest}" ]]; do
    nearest="$(dirname "${nearest}")"
  done
  local physical_dest physical_source
  physical_dest="$(cd "${nearest}" && pwd -P)"
  physical_source="$(cd "${source_dir}" && pwd -P)"
  if [[ "${physical_dest}" == "${physical_source}" || "${physical_dest}" == "${physical_source}/"* ]]; then
    fail "${EXIT_FAILURE}" "${message}"
  fi
}

backup_config() {
  [[ -d "${dest_dir}/config" ]] || return 0
  local backup_dir
  backup_dir="${backup_root}/$(date +%Y%m%d-%H%M%S)-$$"
  # Resolve the folder itself, then copy with cp -R so links inside it stay links.
  local physical_config
  physical_config="$(cd "${dest_dir}/config" && pwd -P)" ||
    fail "${EXIT_FAILURE}" "could not back up your config folder: ${dest_dir}/config"
  run mkdir -p "${backup_dir}"
  if ! run cp -R "${physical_config}" "${backup_dir}/config"; then
    rm -rf "${backup_dir:?}"
    fail "${EXIT_FAILURE}" "could not back up your config folder: ${dest_dir}/config"
  fi
  announce "back up your config to ${backup_dir}" "Backed up your config to ${backup_dir}"
}

copy_code() {
  run mkdir -p "${dest_dir}"
  local path name
  for path in "${source_dir}"/*; do
    name="$(basename "${path}")"
    [[ "${name}" == "config" ]] && continue
    run rm -rf "${dest_dir:?}/${name}"
    run cp -R "${path}" "${dest_dir}/${name}"
  done
  if ((!dry_run)); then
    find "${dest_dir}/scripts" -type d -name '__pycache__' -prune -exec rm -rf {} +
  fi
}

install_config() {
  run mkdir -p "${dest_dir}/config"
  local name
  for name in triage-config service-map; do
    run cp "${source_dir}/config/${name}.example.yaml" "${dest_dir}/config/${name}.example.yaml"
    if [[ -f "${dest_dir}/config/${name}.yaml" ]]; then
      announce "keep your existing ${name}.yaml" "Kept your existing ${name}.yaml"
    else
      run cp "${source_dir}/config/${name}.example.yaml" "${dest_dir}/config/${name}.yaml"
      announce "create ${name}.yaml from the example" "Created ${name}.yaml from the example. Edit it before the first run."
    fi
  done
}

install_python_environment() {
  if [[ "${AI_TRIAGE_SKIP_VENV:-0}" == "1" ]]; then
    log "Skipping the Python environment (AI_TRIAGE_SKIP_VENV=1)."
    return 0
  fi
  if [[ ! -x "${dest_dir}/.venv/bin/python" ]]; then
    run python3 -m venv "${dest_dir}/.venv"
  fi
  run "${dest_dir}/.venv/bin/python" -m pip install --quiet --disable-pip-version-check -r "${dest_dir}/requirements.txt"
}

print_next_steps() {
  cat <<NEXT

Installed in ${dest_dir}

Next steps:

1. Edit ${dest_dir}/config/triage-config.yaml and service-map.yaml.

2. Add one profile per account to ~/.aws/config:

     [profile triage-<account-alias>]
     sso_session = <your sso session name>
     sso_account_id = <account id>
     sso_role_name = ai-triage-read-only
     region = <region>

3. For each EKS cluster, add a context to the skill's own kubeconfig:

     aws eks update-kubeconfig --name <cluster> --alias triage-<cluster> \\
       --kubeconfig ${dest_dir}/config/kubeconfig \\
       --profile triage-<account-alias> --region <region>

4. Connect OneUptime as read only, then Confluence and Slack:

     claude mcp add --transport http oneuptime <your OneUptime URL>/mcp

5. Install the TypeSafe plugin and set TYPESAFE_API_KEY in your shell profile:

     claude plugin marketplace add typesafe-ai/skills
     claude plugin install typesafe@typesafe-ai

6. Check your setup:

     ${dest_dir}/.venv/bin/python ${dest_dir}/scripts/validate_map.py
     ${dest_dir}/.venv/bin/python ${dest_dir}/scripts/verify_access.py

See README.md and docs/aws-permissions.md for details.
NEXT
}

check_prerequisites
check_destination
backup_config
copy_code
install_config
install_python_environment
if ((dry_run)); then
  log "[dry-run] Nothing was changed."
else
  print_next_steps
fi
