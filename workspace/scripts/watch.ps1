param([string]$Config='config.example.json',[string]$Database='runtime/watch.db',[double]$Interval=60,[double]$Timeout=30)
$ErrorActionPreference='Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if(-not $env:SECRETRADAR_HMAC_KEY){throw 'Supply an independent stable SECRETRADAR_HMAC_KEY.'}
$env:PYTHONPYCACHEPREFIX=Join-Path $PWD '.cache\pycache'
& '.venv\Scripts\python.exe' -m secretradar watch --config $Config --db $Database --interval $Interval --timeout $Timeout --event-log runtime/alerts.jsonl --stop-file runtime/WATCH_STOP
exit $LASTEXITCODE
