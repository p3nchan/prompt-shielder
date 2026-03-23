# prompt-shielder

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Integrity monitor for AI agent config files.

## The Problem

AI agents do not just run code. Their behavior is often defined by local files such as `CLAUDE.md`, system prompts, `.env`, workflow manifests, or skill instructions. If one of those files is silently modified, the agent can be behaviorally hijacked without any obvious signal.

That means prompt injection is not only an input-layer problem. It can also show up as config tampering: a changed instruction file, a replaced prompt template, or a poisoned environment file that quietly shifts how the agent behaves.

## The Solution

`prompt-shielder` uses SHA256 baseline tracking. You record a known-good hash for each behavior-defining file, then verify those hashes on demand or on a schedule. Any modification, missing file, or untracked configured file is surfaced immediately.

## Quick Start

```bash
cp .prompt-shielder.example.json .prompt-shielder.json
./prompt-shielder.sh --config .prompt-shielder.json --init
./prompt-shielder.sh verify --config .prompt-shielder.json
./prompt-shielder.sh --list
```

## All Commands

- `verify`: verify files against the stored baseline. Running the script with no command does the same thing.
- `--init`: create a new baseline using the watchlist from `--config`. With no config, the default watchlist is empty.
- `--update <filepath>`: refresh a single baseline entry after an intentional change.
- `--add <filepath>`: add a new file to the baseline.
- `--remove <filepath>`: remove a file from the baseline.
- `--list`: show tracked files and whether they are `OK`, `MODIFIED`, `MISSING`, or `UNTRACKED`.

## Configuration

The config file is JSON with a single `monitored_files` array:

```json
{
  "monitored_files": [
    "CLAUDE.md",
    ".env",
    "config.yaml",
    "system-prompt.md"
  ]
}
```

Relative paths are resolved against `PROMPT_SHIELDER_ROOT`, which defaults to the current working directory. The script stores its state in `.prompt-shielder/baseline.json` and logs in `.prompt-shielder/logs/check-YYYY-MM-DD.log`.

Environment variables:

- `PROMPT_SHIELDER_ROOT`: override the project root to monitor.
- `INTEGRITY_ROOT`: alias for `PROMPT_SHIELDER_ROOT`.

## How It Works

At initialization time, the script computes a SHA256 hash and file size for each monitored file and writes that metadata to a JSON baseline. On verification, it recomputes the hash and compares it to the stored value.

The script is dependency-light: it supports macOS and Linux, uses `shasum -a 256` or `sha256sum`, uses `stat -f%z` or `stat -c%s`, and handles JSON via `jq` when available with a `python3` fallback.

## Use Cases

- Claude Code repositories with `CLAUDE.md`, agent instructions, and local environment files.
- OpenAI Codex or other terminal agents whose behavior depends on prompt/config files in the repo.
- Any file-based agent setup where system prompts, policies, or secrets should not drift silently.

## Contributing

Issues and pull requests are welcome. Keep the tool dependency-light, shell-first, and focused on integrity monitoring rather than full host intrusion detection.

## License

MIT. See [LICENSE](./LICENSE).
