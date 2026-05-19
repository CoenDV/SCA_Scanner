$ErrorActionPreference = "Stop"

$project = "SCAScanner.csproj"
$publishConfig = @(
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-p:PublishTrimmed=false",
    "-c", "Release"
)

$targets = @(
    @{ Rid = "osx-arm64"; Output = "publish/osx-arm64"; Source = "SCAScanner"; Artifact = "SCAScanner-osx-arm64" },
    @{ Rid = "linux-x64"; Output = "publish/linux-x64"; Source = "SCAScanner"; Artifact = "SCAScanner-linux-x64" },
    @{ Rid = "win-x64"; Output = "publish/win-x64"; Source = "SCAScanner.exe"; Artifact = "SCAScanner-win-x64.exe" }
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
    $bundleDir = Join-Path $releaseDir $target.Artifact
    if (Test-Path $bundleDir) {
        Remove-Item -LiteralPath $bundleDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null

    $sourcePath = Join-Path $target.Output $target.Source
    $destPath = Join-Path $bundleDir $target.Source
    Copy-Item -LiteralPath $sourcePath -Destination $destPath -Force

    $publishedPolicies = Join-Path $target.Output "Policies"
    if (Test-Path $publishedPolicies) {
        Copy-Item -LiteralPath $publishedPolicies -Destination (Join-Path $bundleDir "Policies") -Recurse -Force
    }
    elseif (Test-Path "Policies") {
        Copy-Item -LiteralPath "Policies" -Destination (Join-Path $bundleDir "Policies") -Recurse -Force
    }

    if ($target.Rid -eq "win-x64") {
        $trivyPath = "bin/trivy.exe"
        if (Test-Path $trivyPath) {
            Copy-Item -LiteralPath $trivyPath -Destination (Join-Path $bundleDir "trivy.exe") -Force
        }
        else {
            Write-Warning "Trivy not found at $trivyPath"
        }
    }

    $zipPath = "$bundleDir.zip"
    if (Test-Path $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $bundleDir "*") -DestinationPath $zipPath -Force
}

Write-Host "Build complete:"
Get-ChildItem -LiteralPath $releaseDir -Filter "*.zip" -File |
Select-Object Name, @{ Name = "SizeMB"; Expression = { "{0:N2}" -f ($_.Length / 1MB) } }
