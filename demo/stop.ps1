<#
.SYNOPSIS
  Stops the xlate demo and optionally deletes its scratch directory.
#>
[CmdletBinding()]
param([switch]$Purge, [switch]$Quiet)

$work = Join-Path ([System.IO.Path]::GetTempPath()) "xlate-demo"
foreach ($n in @("xlate", "upstream")) {
  $f = Join-Path $work "$n.pid"
  if (Test-Path $f) {
    $id = Get-Content $f -ErrorAction SilentlyContinue
    if ($id) {
      try {
        Stop-Process -Id $id -Force -ErrorAction Stop
        if (-not $Quiet) { Write-Host "stopped $n (pid $id)" }
      } catch { }
    }
    Remove-Item $f -Force -ErrorAction SilentlyContinue
  }
}
if ($Purge) {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
  if (-not $Quiet) { Write-Host "removed $work" }
}
