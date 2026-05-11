$ErrorActionPreference = "Stop"

$project = "SCAScanner.csproj"
$publishConfig = @(
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-p:PublishTrimmed=false",
    "-c", "Release"
)

$targets = @(
    @{ Rid = "osx-arm64"; Output = "publish/osx-arm64"; Source = "SCAScanner";     Artifact = "SCAScanner-osx-arm64" },
    @{ Rid = "linux-x64"; Output = "publish/linux-x64"; Source = "SCAScanner";     Artifact = "SCAScanner-linux-x64" },
    @{ Rid = "win-x64";   Output = "publish/win-x64";   Source = "SCAScanner.exe"; Artifact = "SCAScanner-win-x64.exe" }
)

Write-Host "Building SCAScanner - self-contained single-file executables"
Write-Host ""

foreach ($target in $targets) {
    dotnet publish $project -r $target.Rid @publishConfig -o $target.Output
    Write-Host ""
}

$releaseDir = "publish/release"
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

foreach ($target in $targets) {
    $sourcePath = Join-Path $target.Output $target.Source
    $destPath = Join-Path $releaseDir $target.Artifact
    Move-Item -LiteralPath $sourcePath -Destination $destPath -Force
}

Write-Host "Build complete:"
Get-ChildItem -LiteralPath $releaseDir -File |
    Where-Object { $_.Name -in @("SCAScanner-osx-arm64", "SCAScanner-linux-x64", "SCAScanner-win-x64.exe") } |
    Select-Object Name, @{ Name = "SizeMB"; Expression = { "{0:N2}" -f ($_.Length / 1MB) } }
