$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$python = "python"
$env:PYTHONPATH = Join-Path $Root "src"

& $python -m pip install -r requirements.txt

& $python -m PyInstaller `
  --noconfirm `
  --clean `
  --windowed `
  --name ETestingCenter `
  --paths "src" `
  --add-data "src/etesting_center/data;etesting_center/data" `
  "src/etesting_center/main.py"

Write-Host "Built: $Root\dist\ETestingCenter\ETestingCenter.exe"
