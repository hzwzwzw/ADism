$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    cmake -S . -B build -A x64
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
    cmake --build build --config Release
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    Write-Host 'Executable: build/Release/ADism.exe'
} finally { Pop-Location }
