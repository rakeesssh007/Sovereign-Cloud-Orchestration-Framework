param(
  [Parameter(Mandatory = $true)][string]$Dir
)

$env:AWS_ACCESS_KEY_ID         = "mock-access-key"
$env:AWS_SECRET_ACCESS_KEY     = "mock-secret-key"
$env:AWS_EC2_METADATA_DISABLED = "true"
if (-not $env:TF_PLUGIN_CACHE_DIR) { $env:TF_PLUGIN_CACHE_DIR = "C:\Work\Tools\tf-plugin-cache" }
$env:TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE = "true"
New-Item -ItemType Directory -Force -Path $env:TF_PLUGIN_CACHE_DIR | Out-Null

function Invoke-Tf {
  param([string[]]$TfArgs)
  & terraform @TfArgs
  if ($LASTEXITCODE -ne 0) { throw "terraform $($TfArgs -join ' ') failed (exit code $LASTEXITCODE)" }
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
Invoke-Tf @("-chdir=$Dir", "init", "-input=false", "-no-color")
Invoke-Tf @("-chdir=$Dir", "validate", "-no-color")
Invoke-Tf @("-chdir=$Dir", "plan", "-input=false", "-no-color", "-out=plan.tfplan")

$json = & terraform "-chdir=$Dir" show -json plan.tfplan
if ($LASTEXITCODE -ne 0) { throw "terraform show -json failed" }

$target = Join-Path (Resolve-Path $Dir).Path "plan.json"
[System.IO.File]::WriteAllText($target, ($json -join "`n"), (New-Object System.Text.UTF8Encoding($false)))
$sw.Stop()
Write-Host ("OK  {0} -> plan.json  ({1:N1}s wall time incl. init; NOT a research measurement)" -f $Dir, $sw.Elapsed.TotalSeconds) -ForegroundColor Green