<#
.SYNOPSIS
  Brings up a fully populated xlate demo: gateway, mock destination,
  dummy accounts and shaped traffic.

.DESCRIPTION
  Everything runs on loopback and writes to a scratch directory. No real
  systems, no real credentials. Stop it with demo/stop.ps1.

.PARAMETER Minutes
  Spread traffic across this many minutes so the dashboard chart has a
  profile instead of a single spike. 1 is instant; 5 looks best.

.PARAMETER Port
  Port for the gateway. Default 8080.

.EXAMPLE
  ./demo/demo.ps1
  ./demo/demo.ps1 -Minutes 5
#>
[CmdletBinding()]
param(
  [int]$Minutes = 1,
  [int]$Port = 8080,
  [int]$UpstreamPort = 9090,
  [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$demo = $PSScriptRoot
$work = Join-Path ([System.IO.Path]::GetTempPath()) "xlate-demo"
$seed = Get-Content (Join-Path $demo "seed.json") -Raw | ConvertFrom-Json
$tok  = $seed.admin_token
$base = "http://127.0.0.1:$Port"

function Say($m) { Write-Host "  $m" -ForegroundColor DarkGray }
function Head($m) { Write-Host "`n$m" -ForegroundColor Cyan }

Head "xlate demo"
Say "workdir  $work"
Say "gateway  $base"

# --- clean slate --------------------------------------------------------
& (Join-Path $demo "stop.ps1") -Quiet
New-Item -ItemType Directory -Force $work | Out-Null
Remove-Item -Force (Join-Path $work "state.json"),(Join-Path $work "trail.jsonl") -ErrorAction SilentlyContinue

# --- build --------------------------------------------------------------
Head "Building"
Push-Location $root
& go build -o (Join-Path $work "xlate.exe") .
if ($LASTEXITCODE -ne 0) { throw "xlate build failed" }
Pop-Location
Push-Location (Join-Path $demo "upstream")
& go build -o (Join-Path $work "upstream.exe") .
if ($LASTEXITCODE -ne 0) { throw "mock upstream build failed" }
Pop-Location
Say "ok"

# --- start --------------------------------------------------------------
Head "Starting"
$up = Start-Process -FilePath (Join-Path $work "upstream.exe") `
  -ArgumentList @("-listen","127.0.0.1:$UpstreamPort","-quiet") `
  -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $work "upstream.out") `
  -RedirectStandardError  (Join-Path $work "upstream.err")
$up.Id | Set-Content (Join-Path $work "upstream.pid")

$xl = Start-Process -FilePath (Join-Path $work "xlate.exe") `
  -ArgumentList @("-listen","127.0.0.1:$Port",
                  "-state",(Join-Path $work "state.json"),
                  "-audit",(Join-Path $work "trail.jsonl"),
                  "-admin-token",$tok) `
  -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $work "xlate.out") `
  -RedirectStandardError  (Join-Path $work "xlate.err")
$xl.Id | Set-Content (Join-Path $work "xlate.pid")

$deadline = (Get-Date).AddSeconds(20)
do {
  Start-Sleep -Milliseconds 200
  try { $ok = (Invoke-WebRequest "$base/healthz" -TimeoutSec 2).StatusCode -eq 200 } catch { $ok = $false }
} until ($ok -or (Get-Date) -gt $deadline)
if (-not $ok) { throw "gateway did not become ready; see $work\xlate.err" }
Say "gateway pid $($xl.Id), mock destination pid $($up.Id)"

# --- seed accounts ------------------------------------------------------
$H = @{ Authorization = "Bearer $tok"; "Content-Type" = "application/json" }
Head "Creating accounts"
foreach ($a in $seed.accounts) {
  $body = $a | ConvertTo-Json -Depth 10
  $r = Invoke-WebRequest -Method POST -Uri "$base/api/admin/accounts" -Headers $H -Body $body -SkipHttpErrorCheck
  if ($r.StatusCode -ne 201) { throw "creating $($a.id) failed ($($r.StatusCode)): $($r.Content)" }
  Say "$($a.id)  ($($a.map.Count) field pairs)"
}

# Contoso ships with no map on purpose: it is the onboarding story.
Invoke-WebRequest -Method POST -Uri "$base/api/admin/accounts/contoso/discover" `
  -Headers $H -Body '{"minutes":60}' -SkipHttpErrorCheck | Out-Null
Say "contoso: field discovery open for 60 minutes"

# --- traffic ------------------------------------------------------------
Head "Generating traffic"
$tokens = @{}
foreach ($id in @("acme","northwind","contoso")) {
  $tokens[$id] = ((Invoke-WebRequest "$base/api/admin/accounts/$id" -Headers $H).Content | ConvertFrom-Json).a.inbound_token
}
$P = $seed.payloads
function Send($id, $tok, $obj) {
  $b = $obj | ConvertTo-Json -Depth 10 -Compress
  try {
    Invoke-WebRequest -Method POST -Uri "$base/t/$id/a2b" `
      -Headers @{ Authorization = "Bearer $tok"; "Content-Type" = "application/json" } `
      -Body $b -SkipHttpErrorCheck | Out-Null
  } catch {}
}

$profile = @(34, 61, 22, 48, 15)
for ($m = 0; $m -lt $Minutes; $m++) {
  $n = $profile[$m % $profile.Count]
  for ($i = 0; $i -lt $n; $i++) {
    Send "acme" $tokens["acme"] $P.acme
    if ($i % 2 -eq 0) { Send "northwind" $tokens["northwind"] $P.northwind }
    if ($i % 3 -eq 0) { Send "contoso"   $tokens["contoso"]   $P.contoso }
    if ($i % 11 -eq 0) { Send "acme" $tokens["acme"] $P.acme_bad_date }   # fails open, one warning
  }
  # One credential-guessing burst, in the first minute only, then the
  # operator clears it. Left running, the lockout would 429 every
  # subsequent request and the demo would look like an outage.
  if ($m -eq 0) {
    for ($i = 0; $i -lt 7; $i++) { Send "northwind" "wrong-token" @{} }
    Invoke-WebRequest -Method POST -Uri "$base/api/admin/accounts/northwind/tripwire/reset" `
      -Headers $H -SkipHttpErrorCheck | Out-Null
    Say "northwind: 7 refused attempts tripped the wire, then reset"
  }
  Say "minute $($m+1)/$Minutes  ($n batches)"
  if ($m -lt $Minutes - 1) { Start-Sleep -Seconds 62 }
}

$s = ((Invoke-WebRequest "$base/api/admin/stats" -Headers $H).Content | ConvertFrom-Json).stats
Say ("{0} requests, {1} delivered ({2:N1}%), {3} refused, {4} fields translated" -f `
      $s.total, $s.ok, $s.success_pct, ($s.denied + $s.blocked), $s.applied)

# --- done ---------------------------------------------------------------
Head "Ready"
Write-Host "  Console   $base/admin/"
Write-Host "  Token     $tok"
Write-Host ""
Write-Host "  Try:" -ForegroundColor DarkGray
Write-Host "    Dashboard  totals, per-minute chart, per-account rollup" -ForegroundColor DarkGray
Write-Host "    contoso    open it -> field discovery learned its vocabulary" -ForegroundColor DarkGray
Write-Host "    northwind  refused attempts, tripwire counter" -ForegroundColor DarkGray
Write-Host "    Activity   one row per request, metadata only" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Verify the audit chain:" -ForegroundColor DarkGray
Write-Host "    $work\xlate.exe -verify-audit $work\trail.jsonl" -ForegroundColor DarkGray
Write-Host "  Stop:" -ForegroundColor DarkGray
Write-Host "    ./demo/stop.ps1" -ForegroundColor DarkGray
Write-Host ""

if (-not $NoBrowser) { Start-Process "$base/admin/" }
