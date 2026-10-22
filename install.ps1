# MailGuard setup for Windows (PowerShell 5.1 or 7+).
# Installs uv (if missing), a pinned Python, all dependencies, then runs the self-check.
# Usage: powershell -ExecutionPolicy Bypass -File .\install.ps1 [-Yes]
param([switch]$Yes)
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$UvVersion = "0.12.6"
function Say($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    $localUv = Join-Path $HOME ".local\bin"
    if (Test-Path (Join-Path $localUv "uv.exe")) {
        $env:Path = "$localUv;$env:Path"
    } else {
        Say "uv (Python package manager) is not installed."
        if (-not $Yes) {
            $answer = Read-Host "Install uv $UvVersion from https://astral.sh now? [y/N]"
            if ($answer -notmatch '^[yY]') { Write-Host "Aborted. Install uv yourself: https://docs.astral.sh/uv/"; exit 1 }
        }
        Invoke-RestMethod "https://astral.sh/uv/$UvVersion/install.ps1" | Invoke-Expression
        $env:Path = "$localUv;$env:Path"
    }
}

Say "Using $(uv --version)"
Say "Installing Python $(Get-Content .python-version) and dependencies (locked)"
uv python install
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
uv sync --locked
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Say "Running the installation self-check"
uv run python -m mailguard.selfcheck
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "MailGuard is installed. Start the gateway in front of your mail server, for example:"
Write-Host "  uv run python -m mailguard.relay --port 1025 --downstream 127.0.0.1:25"
Write-Host "See README.md for configuration, quarantine review and sender authentication."
