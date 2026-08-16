$ErrorActionPreference = "Stop"

$PluginRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$BootstrapPosture = "deny"
$BootstrapSource = "default deny"

function Apply-PostureFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    try {
        $Lines = Get-Content -LiteralPath $Path -ErrorAction Stop
    } catch {
        $script:BootstrapPosture = "deny"
        $script:BootstrapSource = "unreadable config: $Path"
        return $true
    }
    $Value = ""
    foreach ($Line in $Lines) {
        $Normalized = $Line -replace '[ \t\r]', ''
        if ($Normalized -match '^on_error="abstain"') {
            $Value = "abstain"
        } elseif ($Normalized -match '^on_error="deny"') {
            $Value = "deny"
        }
    }
    if ($Value) {
        $script:BootstrapPosture = $Value
        $script:BootstrapSource = "on_error = `"$Value`" in $Path"
    }
    return $true
}

function Apply-FirstPostureFile {
    param([string[]]$Paths)
    foreach ($Path in $Paths) {
        if (Apply-PostureFile -Path $Path) {
            return
        }
    }
}

function Resolve-BootstrapPosture {
    $HomeRoot = $env:HOME
    if (-not $HomeRoot) {
        $HomeRoot = [Environment]::GetFolderPath("UserProfile")
    }
    $ConfigHome = $env:XDG_CONFIG_HOME
    if (-not $ConfigHome) {
        $ConfigHome = Join-Path $HomeRoot ".config"
    }
    Apply-FirstPostureFile -Paths @(
        (Join-Path $ConfigHome "gatekeeper/gatekeeper.toml"),
        (Join-Path $HomeRoot ".claude/gatekeeper.toml")
    )
    Apply-FirstPostureFile -Paths @(
        (Join-Path $PWD ".gatekeeper/gatekeeper.toml"),
        (Join-Path $PWD ".claude/gatekeeper.toml")
    )
}

function Exit-BootstrapFailure {
    [Console]::Error.WriteLine("Error: gatekeeper bootstrap exhausted binary, download, and Go build recovery paths.")
    [Console]::Error.WriteLine("Remediation: install bin/claude-gatekeeper.exe or restore release/network access.")
    if ($env:GATEKEEPER_BOOTSTRAP_ABSTAIN -eq "1") {
        [Console]::Error.WriteLine("WARNING: abstaining because GATEKEEPER_BOOTSTRAP_ABSTAIN=1; no gatekeeper policy is enforced.")
        exit 0
    }
    Resolve-BootstrapPosture
    if ($script:BootstrapPosture -eq "abstain") {
        [Console]::Error.WriteLine("WARNING: abstaining because $script:BootstrapSource; no gatekeeper policy is enforced.")
        exit 0
    }
    [Console]::Error.WriteLine("Blocking tool call because $script:BootstrapSource.")
    exit 2
}

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
$Repo = "jim80net/gatekeeper-claude"
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
    if (($LASTEXITCODE -eq 0) -and (Test-Path $Binary)) {
        $input = $Input | Out-String
        $input | & $Binary @args
        exit $LASTEXITCODE
    }
    [Console]::Error.WriteLine("Go build failed or did not produce the gatekeeper binary.")
}

Exit-BootstrapFailure
