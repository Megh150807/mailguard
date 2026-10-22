#!/usr/bin/env bash
# MailGuard setup for Linux and macOS.
# Installs uv (if missing), a pinned Python, all dependencies, then runs the self-check.
# Usage: ./install.sh [--yes]     (--yes: install uv without asking)
set -euo pipefail
cd "$(dirname "$0")"

UV_VERSION="0.12.6"
ASSUME_YES=0
[ "${1:-}" = "--yes" ] && ASSUME_YES=1

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

if ! command -v uv >/dev/null 2>&1; then
  if [ -x "$HOME/.local/bin/uv" ]; then
    export PATH="$HOME/.local/bin:$PATH"
  else
    say "uv (Python package manager) is not installed."
    if [ "$ASSUME_YES" -ne 1 ]; then
      read -r -p "Install uv $UV_VERSION from https://astral.sh now? [y/N] " answer
      case "$answer" in [yY]*) ;; *) echo "Aborted. Install uv yourself: https://docs.astral.sh/uv/"; exit 1;; esac
    fi
    command -v curl >/dev/null 2>&1 || { echo "curl is required to install uv"; exit 1; }
    curl -LsSf "https://astral.sh/uv/$UV_VERSION/install.sh" | sh
    export PATH="$HOME/.local/bin:$PATH"
  fi
fi

say "Using $(uv --version)"
say "Installing Python $(cat .python-version) and dependencies (locked)"
uv python install
uv sync --locked

say "Running the installation self-check"
uv run python -m mailguard.selfcheck

cat <<'DONE'

MailGuard is installed. Start the gateway in front of your mail server, for example:
  uv run python -m mailguard.relay --port 1025 --downstream 127.0.0.1:25
See README.md for configuration, quarantine review and sender authentication.
DONE
