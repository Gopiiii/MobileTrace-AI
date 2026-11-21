$ErrorActionPreference = "Stop"

# Always work from the project root, no matter where this script was launched from.
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== MobileTrace AI Windows Setup ==="
Write-Host "Project folder: $ProjectRoot"

# Find a working Python 3.11+ (python.exe first, then the 'py' launcher).
function Find-Python {
    foreach ($cand in @(@("python"), @("py", "-3"))) {
        $exe = Get-Command $cand[0] -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        $extra = @()
        if ($cand.Count -gt 1) { $extra = $cand[1..($cand.Count - 1)] }
        try {
            $ver = & $cand[0] @extra -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
            if ($LASTEXITCODE -eq 0 -and $ver) {
                $parts = $ver.Trim().Split(".")
                if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 11)) {
                    return ,$cand
                }
            }
        } catch { }
    }
    return $null
}

$Py = Find-Python
if (-not $Py) {
    throw "Python 3.11+ was not found. Install it from python.org (tick 'Add python.exe to PATH') and retry."
}
$PyCmd = $Py[0]
$PyArgs = @()
if ($Py.Count -gt 1) { $PyArgs = $Py[1..($Py.Count - 1)] }

$VenvPath = Join-Path $ProjectRoot ".venv"
$VenvPy = Join-Path $VenvPath "Scripts\python.exe"
if (-not (Test-Path $VenvPy)) {
    Write-Host "Creating Python virtual environment at .venv ..."
    & $PyCmd @PyArgs -m venv $VenvPath
    if ($LASTEXITCODE -ne 0) { throw "Could not create the virtual environment." }
}

Write-Host "Upgrading pip and installing core dependencies..."
& $VenvPy -m pip install --upgrade pip
& $VenvPy -m pip install -r (Join-Path $ProjectRoot "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Core dependency installation failed (see messages above)." }
& $VenvPy -m pip install -e $ProjectRoot
if ($LASTEXITCODE -ne 0) { throw "Installing the mobiletrace package failed." }

Write-Host "Installing optional iOS helpers (failure here is not fatal)..."
& $VenvPy -m pip install -r (Join-Path $ProjectRoot "requirements-ios.txt")
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Optional iOS packages could not be installed. Encrypted-backup decryption will be unavailable; everything else works."
}

$EnvFile = Join-Path $ProjectRoot ".env"
if (-not (Test-Path $EnvFile)) {
    Copy-Item (Join-Path $ProjectRoot ".env.example") $EnvFile
    Write-Host "Created .env from .env.example."
}

Write-Host "Running Alembic / SQLite database migrations..."
& $VenvPy -c "from mobiletrace.config import load_config; from mobiletrace.db.migrations import apply_migrations; cfg = load_config(); print('Migrations applied:', apply_migrations(cfg.db_path))"
if ($LASTEXITCODE -ne 0) { throw "Database migration failed." }

Write-Host ""
Write-Host "Setup complete."
Write-Host "1. To install Android SDK Platform-Tools (adb), run: .\scripts\download_platform_tools.ps1"
Write-Host "2. For live iPhone USB acquisition on Windows, install Apple Devices (Microsoft Store) or iTunes + libimobiledevice."
Write-Host "3. Launch the desktop app by double-clicking run.bat (or: .\.venv\Scripts\python.exe -m mobiletrace)"
