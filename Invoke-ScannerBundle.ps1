[CmdletBinding()]
param(
    [string]$BundleZip,
    [string]$BundleRoot,
    [string]$ScannerExecutable = 'SCAScanner.exe',
    [string]$PolicyPath = 'Policies',
    [string]$OutputRoot,
    [string]$RunName = 'scan',
    [switch]$DisplayDetails,
    [string]$SbomTarget,
    [switch]$KeepStagingRoot,
    [string[]]$ExtraScannerArgs = @()
)

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

function Resolve-OutputRoot {
    param(
        [string]$RootPath,
        [string]$BundlePath
    )

    if (-not [string]::IsNullOrWhiteSpace($RootPath)) {
        return $RootPath
    }

    return Join-Path $BundlePath 'results'
}

function Get-SafeName {
    param(
        [string]$Value,
        [string]$Fallback = 'scan'
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Fallback
    }

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    $safe = -join ($Value.ToCharArray() | ForEach-Object {
        if ($invalidChars -contains $_) { '_' } else { $_ }
    })

    $safe = $safe.Trim('_', '.', ' ')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return $Fallback
    }

    return $safe
}

function Get-WorkingRoot {
    param(
        [string]$ZipPath,
        [string]$RootPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ZipPath)) {
        if (-not (Test-Path -LiteralPath $ZipPath)) {
            throw "Bundle zip not found: $ZipPath"
        }

        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('sca-bundle-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $tempRoot -Force
        return [pscustomobject]@{ Path = $tempRoot; Temporary = $true }
    }

    if (-not [string]::IsNullOrWhiteSpace($RootPath)) {
        if (-not (Test-Path -LiteralPath $RootPath)) {
            throw "Bundle root not found: $RootPath"
        }

        return [pscustomobject]@{ Path = (Resolve-Path -LiteralPath $RootPath).Path; Temporary = $false }
    }

    return [pscustomobject]@{ Path = $PSScriptRoot; Temporary = $false }
}

function Resolve-ScannerPath {
    param(
        [string]$BundlePath,
        [string]$ExecutableName
    )

    $candidate = Join-Path $BundlePath $ExecutableName
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }

    throw "Scanner executable not found in bundle: $candidate"
}

function Resolve-PolicyTarget {
    param(
        [string]$BundlePath,
        [string]$RelativeTarget
    )

    if ([System.IO.Path]::IsPathRooted($RelativeTarget)) {
        if (-not (Test-Path -LiteralPath $RelativeTarget)) {
            throw "Policy target not found: $RelativeTarget"
        }

        return (Resolve-Path -LiteralPath $RelativeTarget).Path
    }

    $candidate = Join-Path $BundlePath $RelativeTarget
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Policy target not found: $candidate"
    }

    return (Resolve-Path -LiteralPath $candidate).Path
}

function Invoke-Scanner {
    param(
        [string]$ScannerPath,
        [string]$PolicyTarget,
        [string]$OutputRoot,
        [string]$ArtifactBase,
        [switch]$UseDetailedOutput,
        [string]$SbomTarget,
        [string[]]$AdditionalArguments
    )

    $logFile = Join-Path $OutputRoot "$ArtifactBase.log"
    $csvFile = Join-Path $OutputRoot "$ArtifactBase.csv"
    $reportFile = Join-Path $OutputRoot "$ArtifactBase.txt"
    $sbomFile = Join-Path $OutputRoot "$ArtifactBase.sbom.cdx.json"

    $arguments = @()
    if ($UseDetailedOutput) {
        $arguments += '--display-details'
    }
    else {
        $arguments += '--no-details'
    }

    $arguments += '--output-dir', $OutputRoot
    $arguments += '--log', $logFile
    $arguments += '--csv', $csvFile
    $arguments += '--report', $reportFile
    $arguments += '--sbom-file', $sbomFile

    $sbomTargetLabel = if (-not [string]::IsNullOrWhiteSpace($SbomTarget)) {
        $arguments += '--sbom-target', $SbomTarget
        $SbomTarget
    }
    else {
        $arguments += '--sbom-all-drives'
        'all drives'
    }

    if ($AdditionalArguments.Count -gt 0) {
        $arguments += $AdditionalArguments
    }

    $arguments += $PolicyTarget

    Write-Host "Running scanner: $ScannerPath"
    Write-Host "Policy target: $PolicyTarget"
    Write-Host "Output root: $OutputRoot"
    Write-Host "SBOM target: $sbomTargetLabel"

    & $ScannerPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Scanner returned exit code $LASTEXITCODE."
    }
}

$workingRootInfo = Get-WorkingRoot -ZipPath $BundleZip -RootPath $BundleRoot
$OutputRoot = Resolve-OutputRoot -RootPath $OutputRoot -BundlePath $workingRootInfo.Path

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
}

try {

    $scannerPath = Resolve-ScannerPath -BundlePath $workingRootInfo.Path -ExecutableName $ScannerExecutable
    $policyTarget = Resolve-PolicyTarget -BundlePath $workingRootInfo.Path -RelativeTarget $PolicyPath

    $runStamp = Get-Date -Format 'yyyyMMdd'
    $computerName = $env:COMPUTERNAME
    $policyName = Get-SafeName ([System.IO.Path]::GetFileNameWithoutExtension($policyTarget))
    $safeRunName = Get-SafeName $RunName
    $artifactBase = "${safeRunName}-${policyName}-${computerName}-${runStamp}"

    Invoke-Scanner -ScannerPath $scannerPath -PolicyTarget $policyTarget -OutputRoot $OutputRoot -ArtifactBase $artifactBase -UseDetailedOutput:$DisplayDetails -SbomTarget $SbomTarget -AdditionalArguments $ExtraScannerArgs

    Write-Host ""
    Write-Host "Artifacts created:"
    Write-Host "  Log        : $(Join-Path $OutputRoot "$artifactBase.log")"
    Write-Host "  CSV        : $(Join-Path $OutputRoot "$artifactBase.csv")"
    Write-Host "  Report     : $(Join-Path $OutputRoot "$artifactBase.txt")"
    Write-Host "  SBOM       : $(Join-Path $OutputRoot "$artifactBase.sbom.cdx.json")"
}
finally {
    if (-not $KeepStagingRoot -and $workingRootInfo.Temporary -and (Test-Path -LiteralPath $workingRootInfo.Path)) {
        # Leave the working tree in place when requested; otherwise clean up the extracted bundle.
        Remove-Item -LiteralPath $workingRootInfo.Path -Recurse -Force
    }
}