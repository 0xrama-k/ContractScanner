# Smoke test: submit a Solidity file, poll to completion, print the report.
#
# Usage (with the server already running):
#   ./scripts/smoke-test.ps1
#   ./scripts/smoke-test.ps1 -File path\to\Contract.sol
#   ./scripts/smoke-test.ps1 -BaseUrl http://127.0.0.1:8080

param(
    [string]$BaseUrl = "http://127.0.0.1:8080",
    [string]$File = "$PSScriptRoot\..\examples\Vault.sol"
)

$ErrorActionPreference = "Stop"

$src = Get-Content -Raw -Path $File
$body = @{
    input_type  = "pasted_code"
    filename    = (Split-Path $File -Leaf)
    source_code = $src
} | ConvertTo-Json

Write-Host "POST $BaseUrl/api/scans  ($File)" -ForegroundColor Cyan
$create = Invoke-RestMethod -Uri "$BaseUrl/api/scans" -Method Post -ContentType "application/json" -Body $body
$scanId = $create.scan_id
Write-Host "scan_id = $scanId  (status $($create.status))"

$status = ""
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 2
    $s = Invoke-RestMethod -Uri "$BaseUrl/api/scans/$scanId" -Method Get
    $status = $s.status
    Write-Host ("[{0,3}s] {1} ({2}%)" -f ($i * 2), $status, $s.progress)
    if ($status -eq "report_ready" -or $status -eq "failed") { break }
}

if ($status -ne "report_ready") {
    Write-Host "Scan did not complete: $status" -ForegroundColor Yellow
    $s | ConvertTo-Json -Depth 6
    exit 1
}

$r = Invoke-RestMethod -Uri "$BaseUrl/api/scans/$scanId/report" -Method Get
Write-Host "`n=== Summary ===" -ForegroundColor Green
$r.summary | ConvertTo-Json
Write-Host "`n=== Findings ===" -ForegroundColor Green
$r.findings | ForEach-Object {
    "{0} [{1}/{2}] {3} -> {4}  (score {5})" -f `
        $_.id, $_.severity, $_.confidence, $_.category, $_.title, $_.score.final_score
}
Write-Host "`nJSON:     $BaseUrl/api/scans/$scanId/export/json"
Write-Host "Markdown: $BaseUrl/api/scans/$scanId/export/markdown"
