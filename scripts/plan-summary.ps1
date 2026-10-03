$rows = Get-ChildItem tests,terraform -Recurse -Filter plan.json -File |
  Where-Object { $_.FullName -notmatch '\\\.terraform\\' } |
  ForEach-Object {
    $p = Get-Content $_.FullName -Raw | ConvertFrom-Json
    $region = $p.configuration.provider_config.aws.expressions.region.constant_value
    if (-not $region) { $region = "(not literal)" }
    $rc = @($p.resource_changes)
    [pscustomobject]@{
      Dir       = $_.DirectoryName.Replace((Get-Location).Path + "\", "")
      Resources = $rc.Count
      Region    = $region
      Types     = (($rc | ForEach-Object { $_.type }) -join ",")
    }
  }
$rows | Sort-Object Dir | Format-Table -AutoSize -Wrap | Out-String -Width 220