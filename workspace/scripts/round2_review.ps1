param([switch]$RunExperiments)
$ErrorActionPreference='Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPYCACHEPREFIX=Join-Path $PWD '.cache\pycache'
& '.venv\Scripts\python.exe' -m pytest -q --basetemp=runtime/round2-review --junitxml=../reports/ROUND2_REPRO_TESTS.xml
if($LASTEXITCODE){exit $LASTEXITCODE}
& '.venv\Scripts\python.exe' scripts/round2_evaluate.py --split development --verify-recorded
if($LASTEXITCODE){exit $LASTEXITCODE}
& '.venv\Scripts\python.exe' scripts/round2_evaluate.py --split holdout --verify-recorded
if($LASTEXITCODE){exit $LASTEXITCODE}
if($RunExperiments){
    & '.venv\Scripts\python.exe' scripts/round2_experiments.py scale
    if($LASTEXITCODE){exit $LASTEXITCODE}
    & '.venv\Scripts\python.exe' scripts/round2_experiments.py timing
    if($LASTEXITCODE){exit $LASTEXITCODE}
}
