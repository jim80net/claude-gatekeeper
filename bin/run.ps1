$ErrorActionPreference = "Stop"

$PluginRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { "amd64" }
}

# 1. Pre-built binary (from make build or downloaded).
$Binary = Join-Path $PluginRoot "bin" "claude-gatekeeper.exe"
if (Test-Path $Binary) {
    $input = $Input | Out-String
    $input | & $Binary @args
    exit $LASTEXITCODE
}

# 2. Auto-download from GitHub Releases.
$Repo = "jim80net/claude-gatekeeper"
$Asset = "claude-gatekeeper_windows_${Arch}.zip"
$Url = "https://github.com/$Repo/releases/latest/download/$Asset"
try {
    Write-Host "Downloading claude-gatekeeper binary..." -ForegroundColor Yellow
    $TmpFile = [System.IO.Path]::GetTempFileName() + ".zip"
    Invoke-WebRequest -Uri $Url -OutFile $TmpFile -UseBasicParsing
    Expand-Archive -Path $TmpFile -DestinationPath $PluginRoot -Force
    Remove-Item $TmpFile -ErrorAction SilentlyContinue

    if (Test-Path $Binary) {
        $input = $Input | Out-String
        $input | & $Binary @args
        exit $LASTEXITCODE
    }
} catch {
    Write-Host "Download failed: $_" -ForegroundColor Yellow
}

# 3. Fallback: build from source (requires Go).
if (Get-Command go -ErrorAction SilentlyContinue) {
    Write-Host "Building claude-gatekeeper..." -ForegroundColor Yellow
    Push-Location $PluginRoot
    & go build -ldflags "-s -w" -o "bin/claude-gatekeeper.exe" ./cmd/claude-gatekeeper
    Pop-Location
    $input = $Input | Out-String
    $input | & $Binary @args
    exit $LASTEXITCODE
}

Write-Error "No claude-gatekeeper binary found and Go is not installed. Install Go 1.22+ or use a pre-built release."
exit 0  # abstain rather than error
