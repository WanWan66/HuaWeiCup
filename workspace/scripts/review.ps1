$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPYCACHEPREFIX = Join-Path $PWD '.cache\pycache'
& '.venv\Scripts\python.exe' -m pytest -q --basetemp=runtime/pytest --junitxml=../reports/pytest.xml
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& '.venv\Scripts\python.exe' scripts/review.py
exit $LASTEXITCODE
