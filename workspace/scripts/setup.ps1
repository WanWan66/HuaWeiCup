$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path '.venv\Scripts\python.exe')) { python -m venv .venv; if ($LASTEXITCODE) { exit $LASTEXITCODE } }
$env:PIP_CACHE_DIR = Join-Path $PWD '.cache\pip'
& '.venv\Scripts\python.exe' -m pip install -r requirements-lock.txt
exit $LASTEXITCODE
