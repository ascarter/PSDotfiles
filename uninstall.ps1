<#
.SYNOPSIS
    Uninstall script for Windows
.DESCRIPTION
    Remove PSDotfiles configuration for current Windows user
#>
[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Remove user profile
if (Test-Path -Path $PROFILE.CurrentUserAllHosts) {
    Remove-Item -Path $PROFILE.CurrentUserAllHosts -Force
}

# Remove vimrc
$vimrc = Join-Path -Path $env:USERPROFILE -ChildPath _vimrc
if (Test-Path -Path $vimrc) { Remove-Item -Path $vimrc -Force }

# Remove gitconfig
$gitconfig = Join-Path -Path $env:USERPROFILE -ChildPath .gitconfig
if (Test-Path -Path $gitconfig) { Remove-Item -Path $gitconfig -Force }

# Remove PSDotfiles
if ((-not ($null -eq $Env:PSDOTFILES)) -and (Test-Path $Env:PSDOTFILES)) {
    Remove-Item -Path $Env:PSDOTFILES -Recurse -Force
}

# Unset PSDOTFILES environment variable
[System.Environment]::SetEnvironmentVariable("PSDOTFILES", $null, [System.EnvironmentVariableTarget]::User)

Write-Output "PSDotfiles uninstalled"
