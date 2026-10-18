param([switch]$Demo, [int]$Port = 8765)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not $env:SECRETRADAR_HMAC_KEY) { throw 'Set SECRETRADAR_HMAC_KEY independently (at least 32 UTF-8 bytes).' }
$env:PYTHONPYCACHEPREFIX = Join-Path $PWD '.cache\pycache'
$mode = if ($Demo) { 'demo' } else { 'real' }
$db = "runtime/$mode.db"
if ($Demo) {
    & '.venv\Scripts\python.exe' -m secretradar demo --db $db
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}
& '.venv\Scripts\python.exe' -m secretradar serve --db $db --mode $mode --port $Port
