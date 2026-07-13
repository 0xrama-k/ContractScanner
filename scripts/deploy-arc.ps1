<#
.SYNOPSIS
  Deploy the ScanPayments USDC gate to Circle's Arc testnet.

.DESCRIPTION
  Reads DEPLOYER_PRIVATE_KEY and ARC_RPC_HTTP_URL from .env (or the environment)
  and deploys contracts/ScanPayments.sol with Foundry's `forge create`.

  On Arc, USDC is the native gas asset, so the deployer address must hold a small
  amount of testnet USDC. Request it from the Circle faucet before running:
    https://faucet.circle.com  (select network: Arc Testnet)

  After a successful deploy, copy the printed "Deployed to" address into .env as
  PAYMENT_CONTRACT_ADDRESS and set PAYMENT_BYPASS=false to enable the live gate.

.EXAMPLE
  pwsh ./scripts/deploy-arc.ps1
#>
[CmdletBinding()]
param(
  [string]$RpcUrl,
  [string]$PrivateKey
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# --- Load .env if present (does not overwrite already-set env vars) ---
$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
  Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
      $k, $v = $line -split "=", 2
      if (-not [System.Environment]::GetEnvironmentVariable($k)) {
        [System.Environment]::SetEnvironmentVariable($k, $v)
      }
    }
  }
}

if (-not $RpcUrl)     { $RpcUrl     = $env:ARC_RPC_HTTP_URL }
if (-not $RpcUrl)     { $RpcUrl     = "https://rpc.testnet.arc.network" }
if (-not $PrivateKey) { $PrivateKey = $env:DEPLOYER_PRIVATE_KEY }

if (-not $PrivateKey) {
  throw "DEPLOYER_PRIVATE_KEY is not set (in .env or as an env var). Aborting."
}
if (-not (Get-Command forge -ErrorAction SilentlyContinue)) {
  throw "Foundry's 'forge' was not found on PATH. Install from https://getfoundry.sh"
}

Write-Host "Deploying ScanPayments to Arc testnet" -ForegroundColor Cyan
Write-Host "  RPC: $RpcUrl"
Write-Host "  Chain ID: 5042002 (Arc testnet)"
Write-Host ""

Push-Location $root
try {
  forge create "contracts/ScanPayments.sol:ScanPayments" `
    --rpc-url $RpcUrl `
    --private-key $PrivateKey `
    --broadcast
} finally {
  Pop-Location
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  1. Copy the 'Deployed to' address into .env as PAYMENT_CONTRACT_ADDRESS"
Write-Host "  2. Set PAYMENT_BYPASS=false in .env"
Write-Host "  3. Restart the server; the payment watcher will pick up the new contract"
