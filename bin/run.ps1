$ErrorActionPreference = "Stop"

$PluginRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { "amd64" }
}

# 1. Pre-built platform binary (from CI or goreleaser).
$Binary = Join-Path $PluginRoot "dist" "claude-gatekeeper-windows-${Arch}.exe"
if (Test-Path $Binary) {
    $input = $Input | Out-String
    $input | & $Binary @args
    exit $LASTEXITCODE
}

# 2. Local build (from make build).
$Binary = Join-Path $PluginRoot "bin" "claude-gatekeeper.exe"
if (Test-Path $Binary) {
    $input = $Input | Out-String
    $input | & $Binary @args
    exit $LASTEXITCODE
}

# 3. Fallback: build from source (requires Go).
if (Get-Command go -ErrorAction SilentlyContinue) {
    Write-Host "Building claude-gatekeeper..." -ForegroundColor Yellow
    Push-Location $PluginRoot
    & go build -ldflags "-s -w" -o "bin/claude-gatekeeper.exe" ./cmd/claude-gatekeeper
    Pop-Location
    $Binary = Join-Path $PluginRoot "bin" "claude-gatekeeper.exe"
    $input = $Input | Out-String
    $input | & $Binary @args
    exit $LASTEXITCODE
}

Write-Error "No claude-gatekeeper binary found and Go is not installed. Install Go 1.22+ or use a pre-built release."
exit 0  # abstain rather than error
