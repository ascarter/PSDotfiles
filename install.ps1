<#
.SYNOPSIS
    PSDotfiles Install script for Windows 10 and Windows 11
.DESCRIPTION
	Install user profile and configuration
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Dotfiles destination
    [string]$Path = (Join-Path -Path $env:USERPROFILE -ChildPath '.config\PSDotfiles')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Use TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

switch ($PSVersionTable.PSEdition) {
    'Desktop' { Import-Module -Name Appx }
    Default { Import-Module -Name Appx -UseWindowsPowerShell }
}

Write-Output 'Installing prerequisites'

# Verify winget package manager
if (-not (Get-AppPackage -Name 'Microsoft.DesktopAppInstaller')) {
    Write-Error "winget required. See https://github.com/microsoft/winget-cli/" -ErrorAction Stop
}

# Install base packages via Windows Package Manager
$packages = @('Git.Git', 'Microsoft.PowerShell')
foreach ($p in $packages) {
    winget list --id $p --exact | Out-Null
    if (-not $?) {
        Write-Output "Installing $p"
        winget install --id $p --exact --interactive
    }
    else {
        Write-Verbose "$p installed"
    }
}

Write-Output 'Installing PSDotfiles'
# Clone PSdotfiles
if (-not (Test-Path -Path $Path)) {
    Write-Output 'Clone PSDotfiles'
    $dotfileParent = Split-Path -Path $Path
    if (-not (Test-Path -Path $dotfileParent)) {
        New-Item -Path $dotfileParent -ItemType Directory -Force
    }
    Start-Process -FilePath (Get-Command git.exe) -ArgumentList "clone https://github.com/ascarter/PSDotfiles.git $Path" -Wait -NoNewWindow
}
else {
    Write-Verbose 'PSDotfiles installed'
}

# Set PSDOTFILES environment variable
if ($null -eq [System.Environment]::GetEnvironmentVariable('PSDOTFILES', [System.EnvironmentVariableTarget]::User)) {
    Write-Output 'Set PSDOTFILES environment variable'
    [System.Environment]::SetEnvironmentVariable('PSDOTFILES', $Path, [System.EnvironmentVariableTarget]::User)
    Write-Output "PSDOTFILES=$([System.Environment]::GetEnvironmentVariable('PSDOTFILES', [System.EnvironmentVariableTarget]::User))"
}
else {
    Write-Verbose 'PSDotfiles env set'
}

Write-Output 'Bootstrap PSDotfiles'
if (-not (Get-Module PSDotfiles)) { Import-Module (Join-Path -Path $Path -ChildPath Modules\PSDotfiles) }
Install-Bootstrap -Path $Path -Force:$Force -Verbose

$bootstrapScript = Join-Path -Path $Path -ChildPath bootstrap.ps1
Start-Process pwsh -ArgumentList "-NoProfile -File $bootstrapScript -Path $Path -Verbose" -Wait -NoNewWindow

Write-Output 'PSDotfiles install complete'
Write-Output 'Reload session to apply configuration'
