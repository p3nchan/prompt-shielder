#!/usr/bin/env bash
# =============================================================================
# prompt-shielder.sh — Integrity monitor for AI agent config files
#
# Tracks SHA256 baselines for behavior-defining files such as CLAUDE.md,
# system prompts, .env, and workflow config. Detects unauthorized changes that
# could alter agent behavior or signal config tampering.
#
# Usage:
#   prompt-shielder.sh verify
#   prompt-shielder.sh --init [--config FILE]
#   prompt-shielder.sh --update <filepath>
#   prompt-shielder.sh --add <filepath>
#   prompt-shielder.sh --remove <filepath>
#   prompt-shielder.sh --list [--config FILE]
#   prompt-shielder.sh --help
# =============================================================================

set -euo pipefail

RAW_ROOT="${PROMPT_SHIELDER_ROOT:-${INTEGRITY_ROOT:-$(pwd)}}"
if ! PROMPT_SHIELDER_ROOT="$(cd "${RAW_ROOT}" 2>/dev/null && pwd -P)"; then
    printf 'ERROR: cannot resolve project root: %s\n' "${RAW_ROOT}" >&2
    exit 1
fi

STATE_DIR="${PROMPT_SHIELDER_ROOT}/.prompt-shielder"
BASELINE_FILE="${STATE_DIR}/baseline.json"
LOG_DIR="${STATE_DIR}/logs"
LOG_FILE="${LOG_DIR}/check-$(date +%Y-%m-%d).log"
DEFAULT_MONITORED_FILES=()
CONFIG_FILE=""

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'
BOLD='\033[1m'

JQ_AVAILABLE=false
PYTHON3_AVAILABLE=false
HASH_TOOL=""

if command -v jq >/dev/null 2>&1; then
    JQ_AVAILABLE=true
fi

if command -v python3 >/dev/null 2>&1; then
    PYTHON3_AVAILABLE=true
fi

if command -v shasum >/dev/null 2>&1; then
    HASH_TOOL="shasum"
elif command -v sha256sum >/dev/null 2>&1; then
    HASH_TOOL="sha256sum"
else
    printf 'ERROR: missing SHA256 tool (need shasum or sha256sum)\n' >&2
    exit 1
fi

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%dT%H:%M:%S')"
    mkdir -p "${LOG_DIR}"
    printf '%s [PROMPT-SHIELDER] [%s] %s\n' "${timestamp}" "${level}" "${message}" >> "${LOG_FILE}"

    case "${level}" in
        ALERT) printf "${RED}${BOLD}[ALERT]${RESET} %s\n" "${message}" ;;
        WARN)  printf "${YELLOW}[WARN]${RESET}  %s\n" "${message}" ;;
        INFO)  printf "${CYAN}[INFO]${RESET}  %s\n" "${message}" ;;
        OK)    printf "${GREEN}[OK]${RESET}    %s\n" "${message}" ;;
    esac
}

die() {
    printf "${RED}${BOLD}ERROR:${RESET} %s\n" "$*" >&2
    exit 1
}

ensure_json_backend() {
    if [[ "${JQ_AVAILABLE}" != "true" && "${PYTHON3_AVAILABLE}" != "true" ]]; then
        die "JSON operations require jq or python3"
    fi
}

baseline_exists() {
    [[ -f "${BASELINE_FILE}" ]]
}

resolve_cli_path() {
    local input="$1"
    if [[ "${input}" = /* ]]; then
        printf '%s\n' "${input}"
        return
    fi

    local dir
    local base
    local abs_dir
    dir="$(dirname "${input}")"
    base="$(basename "${input}")"
    abs_dir="$(cd "${dir}" 2>/dev/null && pwd -P)" || die "Cannot resolve path: ${input}"
    printf '%s/%s\n' "${abs_dir}" "${base}"
}

resolve_root_relative_path() {
    local input="$1"
    if [[ "${input}" = /* ]]; then
        printf '%s\n' "${input}"
        return
    fi

    case "${input}" in
        ./*) printf '%s/%s\n' "${PROMPT_SHIELDER_ROOT}" "${input#./}" ;;
        *)   printf '%s/%s\n' "${PROMPT_SHIELDER_ROOT}" "${input}" ;;
    esac
}

get_file_size() {
    local filepath="$1"
    stat -f%z "${filepath}" 2>/dev/null || stat -c%s "${filepath}" 2>/dev/null || echo "0"
}

compute_hash() {
    local filepath="$1"
    if [[ ! -f "${filepath}" ]]; then
        echo "FILE_NOT_FOUND"
        return
    fi

    if [[ "${HASH_TOOL}" == "shasum" ]]; then
        shasum -a 256 "${filepath}" | awk '{print $1}'
    else
        sha256sum "${filepath}" | awk '{print $1}'
    fi
}

config_requested() {
    [[ -n "${CONFIG_FILE}" ]]
}

parse_config_files() {
    if [[ -z "${CONFIG_FILE}" ]]; then
        return
    fi

    [[ -f "${CONFIG_FILE}" ]] || die "Config file not found: ${CONFIG_FILE}"
    ensure_json_backend

    if [[ "${JQ_AVAILABLE}" == "true" ]]; then
        jq -r '.monitored_files[]? | select(type == "string")' "${CONFIG_FILE}"
    else
        python3 - "${CONFIG_FILE}" <<'PYEOF'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

for item in payload.get("monitored_files", []):
    if isinstance(item, str):
        print(item)
PYEOF
    fi
}

write_empty_baseline() {
    ensure_json_backend
    mkdir -p "${STATE_DIR}"
    local now
    local tmp
    now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    tmp="$(mktemp)"

    if [[ "${JQ_AVAILABLE}" == "true" ]]; then
        jq -n --arg ts "${now}" '{created: $ts, updated: $ts, files: {}}' > "${tmp}"
    else
        python3 - "${now}" <<'PYEOF' > "${tmp}"
import json
import sys

ts = sys.argv[1]
print(json.dumps({"created": ts, "updated": ts, "files": {}}, indent=2))
PYEOF
    fi

    mv "${tmp}" "${BASELINE_FILE}"
}

get_baseline_hash() {
    local filepath="$1"
    if ! baseline_exists; then
        echo ""
        return
    fi

    ensure_json_backend

    if [[ "${JQ_AVAILABLE}" == "true" ]]; then
        jq -r --arg fp "${filepath}" '.files[$fp].hash // ""' "${BASELINE_FILE}" 2>/dev/null || echo ""
    else
        python3 - "${BASELINE_FILE}" "${filepath}" <<'PYEOF' 2>/dev/null || echo ""
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

print(payload.get("files", {}).get(sys.argv[2], {}).get("hash", ""))
PYEOF
    fi
}

update_baseline_entry() {
    local filepath="$1"
    local hash="$2"
    local size
    local now
    local tmp

    ensure_json_backend
    size="$(get_file_size "${filepath}")"
    now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    mkdir -p "${STATE_DIR}"
    tmp="$(mktemp)"

    if [[ "${JQ_AVAILABLE}" == "true" ]]; then
        if baseline_exists; then
            jq \
                --arg fp "${filepath}" \
                --arg h "${hash}" \
                --argjson sz "${size}" \
                --arg ts "${now}" \
                '.files[$fp] = {"hash": $h, "size": $sz, "recorded": $ts}
                 | .updated = $ts
                 | if .created == null then .created = $ts else . end' \
                "${BASELINE_FILE}" > "${tmp}"
        else
            jq -n \
                --arg fp "${filepath}" \
                --arg h "${hash}" \
                --argjson sz "${size}" \
                --arg ts "${now}" \
                '{created: $ts, updated: $ts, files: {($fp): {"hash": $h, "size": $sz, "recorded": $ts}}}' \
                > "${tmp}"
        fi
    else
        python3 - "${BASELINE_FILE}" "${filepath}" "${hash}" "${size}" "${now}" <<'PYEOF' > "${tmp}"
import json
import os
import sys

baseline_path = sys.argv[1]
filepath = sys.argv[2]
sha = sys.argv[3]
size = int(sys.argv[4])
timestamp = sys.argv[5]

payload = {}
if os.path.isfile(baseline_path):
    with open(baseline_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

payload.setdefault("created", timestamp)
payload.setdefault("files", {})
payload["files"][filepath] = {"hash": sha, "size": size, "recorded": timestamp}
payload["updated"] = timestamp

print(json.dumps(payload, indent=2))
PYEOF
    fi

    mv "${tmp}" "${BASELINE_FILE}"
}

remove_baseline_entry() {
    local filepath="$1"
    local now
    local tmp

    if ! baseline_exists; then
        log "WARN" "No baseline exists; nothing to remove."
        return
    fi

    ensure_json_backend
    now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    tmp="$(mktemp)"

    if [[ "${JQ_AVAILABLE}" == "true" ]]; then
        jq --arg fp "${filepath}" --arg ts "${now}" \
            'del(.files[$fp]) | .updated = $ts' \
            "${BASELINE_FILE}" > "${tmp}"
    else
        python3 - "${BASELINE_FILE}" "${filepath}" "${now}" <<'PYEOF' > "${tmp}"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

payload.get("files", {}).pop(sys.argv[2], None)
payload["updated"] = sys.argv[3]
print(json.dumps(payload, indent=2))
PYEOF
    fi

    mv "${tmp}" "${BASELINE_FILE}"
    log "INFO" "Removed from monitoring: ${filepath}"
}

list_baseline_files() {
    if ! baseline_exists; then
        return
    fi

    ensure_json_backend

    if [[ "${JQ_AVAILABLE}" == "true" ]]; then
        jq -r '.files | keys[]' "${BASELINE_FILE}" 2>/dev/null || true
    else
        python3 - "${BASELINE_FILE}" <<'PYEOF'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

for key in payload.get("files", {}):
    print(key)
PYEOF
    fi
}

collect_init_files() {
    local raw
    if config_requested; then
        while IFS= read -r raw; do
            [[ -n "${raw}" ]] || continue
            resolve_root_relative_path "${raw}"
        done < <(parse_config_files)
    elif (( ${#DEFAULT_MONITORED_FILES[@]} > 0 )); then
        printf '%s\n' "${DEFAULT_MONITORED_FILES[@]}"
    fi | awk 'NF && !seen[$0]++'
}

collect_report_files() {
    local raw
    if config_requested; then
        while IFS= read -r raw; do
            [[ -n "${raw}" ]] || continue
            resolve_root_relative_path "${raw}"
        done < <(parse_config_files)
    else
        list_baseline_files
    fi | awk 'NF && !seen[$0]++'
}

print_recommendations() {
    printf "\nRecommended actions:\n"
    printf "  1. Review the diff to understand what changed\n"
    printf "  2. If intentional: run --update <filepath>\n"
    printf "  3. If unintentional: treat as a security incident\n"
    printf "     - Restore from a known-good baseline\n"
    printf "     - Review recent prompts, inputs, and tool outputs\n"
    printf "     - Check for config tampering or injected workflow changes\n\n"
}

cmd_init() {
    log "INFO" "Initializing SHA256 baseline..."
    write_empty_baseline

    local count=0
    local filepath
    while IFS= read -r filepath; do
        [[ -n "${filepath}" ]] || continue
        if [[ ! -f "${filepath}" ]]; then
            log "WARN" "File not found (skipping baseline): ${filepath}"
            continue
        fi

        local hash
        hash="$(compute_hash "${filepath}")"
        update_baseline_entry "${filepath}" "${hash}"
        log "OK" "Baseline recorded: ${filepath} [${hash:0:12}...]"
        count=$(( count + 1 ))
    done < <(collect_init_files)

    if (( count == 0 )); then
        log "WARN" "No files were added. Use --config, --add, or edit the watchlist."
    fi

    log "INFO" "Baseline initialized for ${count} file(s). Stored at: ${BASELINE_FILE}"
    printf "\n${GREEN}${BOLD}Baseline initialized: %d file(s).${RESET}\n" "${count}"
    printf "Baseline stored at: %s\n\n" "${BASELINE_FILE}"
}

cmd_update() {
    local filepath
    local hash

    filepath="$(resolve_cli_path "$1")"
    [[ -f "${filepath}" ]] || die "File not found: ${filepath}"

    hash="$(compute_hash "${filepath}")"
    update_baseline_entry "${filepath}" "${hash}"
    log "OK" "Baseline updated: ${filepath} [${hash:0:12}...]"
    printf "\n${GREEN}Baseline updated for: %s${RESET}\n\n" "${filepath}"
}

cmd_add() {
    local filepath
    local existing_hash
    local hash

    filepath="$(resolve_cli_path "$1")"
    [[ -f "${filepath}" ]] || die "File not found: ${filepath}"

    if ! baseline_exists; then
        write_empty_baseline
    fi

    existing_hash="$(get_baseline_hash "${filepath}")"
    if [[ -n "${existing_hash}" ]]; then
        log "WARN" "File already tracked: ${filepath}. Use --update to refresh."
        exit 0
    fi

    hash="$(compute_hash "${filepath}")"
    update_baseline_entry "${filepath}" "${hash}"
    log "OK" "Added to monitoring: ${filepath} [${hash:0:12}...]"
    printf "\n${GREEN}Added to integrity monitoring: %s${RESET}\n\n" "${filepath}"
}

cmd_remove() {
    local filepath
    filepath="$(resolve_cli_path "$1")"
    remove_baseline_entry "${filepath}"
}

cmd_list() {
    if ! baseline_exists; then
        printf "No baseline found. Run: %s --init\n" "$0"
        exit 0
    fi

    printf "\n${BOLD}Monitored files:${RESET}\n"
    printf "%-72s  %-14s  %s\n" "File" "Hash (prefix)" "Status"
    printf "%-72s  %-14s  %s\n" "$(printf '%0.s-' {1..72})" "$(printf '%0.s-' {1..14})" "------"

    local filepath
    while IFS= read -r filepath; do
        [[ -n "${filepath}" ]] || continue

        local baseline_hash
        local current_hash
        local status

        baseline_hash="$(get_baseline_hash "${filepath}")"
        current_hash="$(compute_hash "${filepath}")"

        if [[ -z "${baseline_hash}" ]]; then
            status="${YELLOW}UNTRACKED${RESET}"
            printf "%-72s  %-14s  %b\n" "${filepath}" "(none)" "${status}"
            continue
        fi

        if [[ "${current_hash}" == "FILE_NOT_FOUND" ]]; then
            status="${YELLOW}MISSING${RESET}"
        elif [[ "${current_hash}" == "${baseline_hash}" ]]; then
            status="${GREEN}OK${RESET}"
        else
            status="${RED}MODIFIED${RESET}"
        fi

        printf "%-72s  %-14s  %b\n" "${filepath}" "${baseline_hash:0:12}..." "${status}"
    done < <(collect_report_files)

    printf "\nBaseline: %s\n" "${BASELINE_FILE}"
    if config_requested; then
        printf "Config:   %s\n" "${CONFIG_FILE}"
    fi
    printf "\n"
}

cmd_verify() {
    if ! baseline_exists; then
        log "WARN" "No baseline found. Run: $(basename "$0") --init"
        printf "\n${YELLOW}No baseline found.${RESET} Initialize with:\n"
        printf "  bash %s --init\n\n" "$0"
        exit 2
    fi

    log "INFO" "Starting integrity verification."

    local total=0
    local ok_count=0
    local mismatch_count=0
    local missing_count=0
    local untracked_count=0
    local filepath
    local mismatch_files=()
    local missing_files=()
    local untracked_files=()

    while IFS= read -r filepath; do
        [[ -n "${filepath}" ]] || continue
        total=$(( total + 1 ))

        local baseline_hash
        local current_hash

        baseline_hash="$(get_baseline_hash "${filepath}")"
        current_hash="$(compute_hash "${filepath}")"

        if [[ -z "${baseline_hash}" ]]; then
            log "ALERT" "UNTRACKED — ${filepath}"
            untracked_count=$(( untracked_count + 1 ))
            untracked_files+=("${filepath}")
            continue
        fi

        if [[ "${current_hash}" == "FILE_NOT_FOUND" ]]; then
            log "ALERT" "MISSING — ${filepath} (baseline: ${baseline_hash:0:12}...)"
            missing_count=$(( missing_count + 1 ))
            missing_files+=("${filepath}")
        elif [[ "${current_hash}" == "${baseline_hash}" ]]; then
            log "OK" "VERIFIED — ${filepath} [${current_hash:0:12}...]"
            ok_count=$(( ok_count + 1 ))
        else
            log "ALERT" "MISMATCH — ${filepath}"
            log "ALERT" "  Expected: ${baseline_hash}"
            log "ALERT" "  Current:  ${current_hash}"
            mismatch_count=$(( mismatch_count + 1 ))
            mismatch_files+=("${filepath}")
        fi
    done < <(collect_report_files)

    if (( total == 0 )); then
        log "WARN" "No files selected for verification."
        printf "\n${YELLOW}No files selected for verification.${RESET}\n"
        printf "Use --config, --add, or initialize a baseline first.\n\n"
        exit 0
    fi

    printf "\n%s\n" "================================================================"
    printf "${BOLD}Integrity Check Summary${RESET}\n"
    printf "  Date:      %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    printf "  Total:     %d\n" "${total}"
    printf "  OK:        ${GREEN}%d${RESET}\n" "${ok_count}"
    printf "  Mismatch:  ${RED}%d${RESET}\n" "${mismatch_count}"
    printf "  Missing:   ${YELLOW}%d${RESET}\n" "${missing_count}"
    printf "  Untracked: ${YELLOW}%d${RESET}\n" "${untracked_count}"
    printf "  Log:       %s\n" "${LOG_FILE}"
    printf "%s\n" "================================================================"

    if (( mismatch_count > 0 )); then
        printf "\n${RED}${BOLD}INTEGRITY VIOLATION — %d file(s) modified:${RESET}\n" "${mismatch_count}"
        for filepath in "${mismatch_files[@]}"; do
            printf "  - %s\n" "${filepath}"
        done
        print_recommendations
        log "ALERT" "Integrity check failed. ${mismatch_count} mismatch(es), ${missing_count} missing, ${untracked_count} untracked."
        exit 1
    fi

    if (( missing_count > 0 )); then
        printf "\n${YELLOW}${BOLD}WARNING — %d monitored file(s) missing:${RESET}\n" "${missing_count}"
        for filepath in "${missing_files[@]}"; do
            printf "  - %s\n" "${filepath}"
        done
        printf "\nIf deletion was intentional, remove them from monitoring:\n"
        printf "  bash %s --remove <filepath>\n\n" "$0"
        log "WARN" "Integrity check found ${missing_count} missing file(s)."
        exit 1
    fi

    if (( untracked_count > 0 )); then
        printf "\n${YELLOW}${BOLD}WARNING — %d configured file(s) are not in the baseline:${RESET}\n" "${untracked_count}"
        for filepath in "${untracked_files[@]}"; do
            printf "  - %s\n" "${filepath}"
        done
        printf "\nRun --init --config <file> or --add <filepath> to start tracking them.\n\n"
        log "WARN" "Integrity check found ${untracked_count} untracked configured file(s)."
        exit 1
    fi

    printf "\n${GREEN}${BOLD}All %d file(s) verified. Integrity intact.${RESET}\n\n" "${ok_count}"
    log "INFO" "Integrity check passed. ${ok_count}/${total} files verified."
}

usage() {
    cat <<EOF
Usage: $(basename "$0") [--config FILE] [COMMAND]

Commands:
  verify                    Verify files against the stored baseline
  (none)                    Same as verify
  --init                    Create a baseline from the config watchlist
  --update <filepath>       Refresh one baseline entry after an intentional edit
  --add <filepath>          Add a file to monitoring
  --remove <filepath>       Remove a file from monitoring
  --list                    List monitored files and their current status
  --help                    Show this help message

Configuration file format:
  {
    "monitored_files": [
      "CLAUDE.md",
      ".env",
      "config.yaml"
    ]
  }

Environment:
  PROMPT_SHIELDER_ROOT      Project root to monitor (default: current directory)
  INTEGRITY_ROOT            Alias for PROMPT_SHIELDER_ROOT

Examples:
  bash prompt-shielder.sh --config .prompt-shielder.example.json --init
  bash prompt-shielder.sh
  bash prompt-shielder.sh verify --config .prompt-shielder.example.json
  bash prompt-shielder.sh --add ./CLAUDE.md
  bash prompt-shielder.sh --update ./CLAUDE.md
  bash prompt-shielder.sh --remove ./CLAUDE.md
  bash prompt-shielder.sh --list

Baseline file: ${BASELINE_FILE}
Log file:      ${LOG_FILE}
EOF
}

COMMAND="verify"
COMMAND_ARG=""

while (( $# > 0 )); do
    case "$1" in
        --config)
            shift
            [[ -n "${1:-}" ]] || die "--config requires a file path"
            CONFIG_FILE="$(resolve_cli_path "$1")"
            ;;
        --init|--list|--help)
            COMMAND="$1"
            ;;
        --update|--add|--remove)
            COMMAND="$1"
            shift
            [[ -n "${1:-}" ]] || die "${COMMAND} requires a filepath argument"
            COMMAND_ARG="$1"
            ;;
        verify)
            COMMAND="verify"
            ;;
        --*)
            die "Unknown option: $1. Run --help for usage."
            ;;
        *)
            die "Unexpected argument: $1. Run --help for usage."
            ;;
    esac
    shift
done

case "${COMMAND}" in
    --init)   cmd_init ;;
    --update) cmd_update "${COMMAND_ARG}" ;;
    --add)    cmd_add "${COMMAND_ARG}" ;;
    --remove) cmd_remove "${COMMAND_ARG}" ;;
    --list)   cmd_list ;;
    --help)   usage ;;
    verify)   cmd_verify ;;
    *)        die "Unknown command: ${COMMAND}" ;;
esac
