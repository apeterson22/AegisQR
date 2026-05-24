param(
    [string]$Repo = "apeterson22/AegisQR",
    [string]$Version = "latest",
    [string]$Archive,
    [string]$ArchiveSha256,
    [string]$InstallDir,
    [string]$BinDir,
    [switch]$Force,
    [switch]$SkipChecksum
)

$ErrorActionPreference = "Stop"

if (-not $InstallDir) {
    if ($env:LOCALAPPDATA) {
        $InstallDir = Join-Path $env:LOCALAPPDATA "AegisQR"
    } else {
        $InstallDir = Join-Path $HOME ".local/AegisQR"
    }
}

if (-not $BinDir) {
    $BinDir = Join-Path $InstallDir "bin"
}

function Get-AssetUrl {
    param(
        [string]$Repository,
        [string]$ReleaseVersion,
        [string]$AssetName
    )

    if ($ReleaseVersion -eq "latest") {
        return "https://github.com/$Repository/releases/latest/download/$AssetName"
    }

    return "https://github.com/$Repository/releases/download/$ReleaseVersion/$AssetName"
}

function Get-ChecksumValue {
    param(
        [string]$ChecksumFile,
        [string]$AssetName
    )

    foreach ($line in Get-Content $ChecksumFile) {
        if ($line -match "^\s*([0-9a-fA-F]+)\s+$([regex]::Escape($AssetName))\s*$") {
            return $Matches[1].ToLowerInvariant()
        }
    }

    throw "Could not find checksum entry for $AssetName"
}

function Get-HostTarget {
    if (-not $IsWindows) {
        throw "install.ps1 is intended for Windows hosts"
    }

    switch ($env:PROCESSOR_ARCHITECTURE.ToUpperInvariant()) {
        "AMD64" { return "x86_64-pc-windows-msvc" }
        "ARM64" { return "aarch64-pc-windows-msvc" }
        default { throw "Unsupported Windows architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

function Assert-HttpsArchiveUrl {
    param([string]$Url)

    if ($Url -match '^https://') {
        return
    }

    if ($Url -match '^http://') {
        throw "Remote archives must use HTTPS: $Url"
    }

    throw "Unsupported remote archive URL: $Url"
}

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("aegisqr-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    if ($Archive) {
        $assetName = Split-Path -Leaf $Archive
        $assetPath = Join-Path $tempDir $assetName
        if ($Archive -match '^https?://') {
            Assert-HttpsArchiveUrl -Url $Archive
            if ((-not $SkipChecksum) -and (-not $ArchiveSha256)) {
                throw "Remote archives require -ArchiveSha256 unless -SkipChecksum is used"
            }
            Invoke-WebRequest -Uri $Archive -OutFile $assetPath
        } else {
            Copy-Item -Path $Archive -Destination $assetPath
        }
        if ($ArchiveSha256) {
            $expected = $ArchiveSha256.ToLowerInvariant()
            $actual = (Get-FileHash -Algorithm SHA256 -Path $assetPath).Hash.ToLowerInvariant()
            if ($actual -ne $expected) {
                throw "Checksum mismatch for $assetName"
            }
        }
    } else {
        $target = Get-HostTarget
        $assetName = "aegisqr-$target.zip"
        $assetPath = Join-Path $tempDir $assetName
        Invoke-WebRequest -Uri (Get-AssetUrl -Repository $Repo -ReleaseVersion $Version -AssetName $assetName) -OutFile $assetPath

        if (-not $SkipChecksum) {
            $checksumsPath = Join-Path $tempDir "SHA256SUMS"
            Invoke-WebRequest -Uri (Get-AssetUrl -Repository $Repo -ReleaseVersion $Version -AssetName "SHA256SUMS") -OutFile $checksumsPath
            $expected = Get-ChecksumValue -ChecksumFile $checksumsPath -AssetName $assetName
            $actual = (Get-FileHash -Algorithm SHA256 -Path $assetPath).Hash.ToLowerInvariant()
            if ($actual -ne $expected) {
                throw "Checksum mismatch for $assetName"
            }
        }
    }

    if ((Test-Path $InstallDir) -and (-not $Force)) {
        throw "Install directory already exists: $InstallDir (use -Force to replace it)"
    }

    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Expand-Archive -Path $assetPath -DestinationPath $tempDir -Force
    $bundleDirs = @(Get-ChildItem -Path $tempDir -Directory | Where-Object { $_.Name -like 'aegisqr-*' })
    if ($bundleDirs.Count -ne 1) {
        throw "Expected exactly one extracted bundle directory named aegisqr-*, found $($bundleDirs.Count)"
    }
    $bundleDir = $bundleDirs[0]

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path (Join-Path $bundleDir.FullName '*') -Destination $InstallDir -Recurse -Force

    if ($BinDir) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
        Copy-Item -Path (Join-Path $InstallDir 'aegisqr.exe') -Destination (Join-Path $BinDir 'aegisqr.exe') -Force
    }

    Write-Host "Installed AegisQR to $InstallDir"
    if ($BinDir) {
        Write-Host "Copied aegisqr.exe to $BinDir"
    }
}
finally {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
