$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPYCACHEPREFIX = Join-Path $PWD '.cache\pycache'
& '.venv\Scripts\python.exe' -m secretradar evaluate --output ../reports/evaluation.json
exit $LASTEXITCODE
