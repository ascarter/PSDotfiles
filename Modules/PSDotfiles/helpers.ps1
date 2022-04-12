function Set-LocationDotfiles {
    Set-Location -Path $Env:PSDOTFILES
}
Set-Alias -Name dotfiles -Value Set-LocationDotfiles

function Start-ProfileEdit {
    code -n $PROFILE.CurrentUserAllHosts
}
Set-Alias -Name editprofile -Value Start-ProfileEdit

function Test-Adminstrator {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Administrator {
    <#
    .SYNOPSIS
    Execute command using elevated privileges (sudo for Windows)
    .EXAMPLE
    PS> Invoke-Administrator -Command &{Write-Host "I am admin"}

    This example runs a Write-Host command as Administrator
    .PARAMETER Command
    Script block for command to execute as Administrator
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter()]
        [string]$Command,
        [switch]$Core
    )
    process {
        if ($Core) {
            $pwsh = 'pwsh'
        } else {
            $pwsh = 'powershell'
        }
        Start-Process $pwsh -Verb RunAs -ArgumentList @('-Command', $Command) -Wait
    }
}
Set-Alias -Name sudo -Value Invoke-Administrator

function Update-Path {
    <#
    .SYNOPSIS
    Add list of paths to current path
    .EXAMPLE
    PS> Update-Path @(C:\bin, C:\tools)

    This example adds C:\bin and C:\tools to the current path
    .PARAMETER Paths
    List of paths to add
    .PARAMETER SetEnv
    Flag to indicate if the list of paths should be saved to the User PATH environment variable
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$Paths,

        [Parameter(Mandatory = $false)]
        [switch]$SetEnv
    )
    process {
        $parts = ($Env:PATH -Split ';' | Sort-Object | Get-Unique)
        if ($SetEnv) {
            $envparts = ([System.Environment]::GetEnvironmentVariable('PATH') -Split ';' | Sort-Object | Get-Unique)
        }

        foreach ($p in $paths) {
            if (Test-Path -Path $p) {
                # Add to current path
                if ($parts -NotContains $p) { $parts += $p }
                # Add to environment path if requested
                if (($SetEnv) -and ($envparts -NotContains $p)) { $envparts += $p }
            }
        }

        # Set current path
        $Env:PATH = $parts -Join ';'

        # Save to environment path if requested
        if ($SetEnv) {
            [System.Environment]::SetEnvironmentVariable('PATH', $envparts -Join ';', [System.EnvironmentVariableTarget]::User)
        }
    }
}

$OwnerKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

function Get-Owner {
    <#
    .SYNOPSIS
        Show register owner and organziation
    #>

    Get-ItemProperty -Path $OwnerKey | Format-Table RegisteredOwner, RegisteredOrganization
}
function Update-Owner {
    <#
    .SYNOPSIS
        Set owner and organization
    #>
    [CmdletBinding()]
    param(
        [string]$Owner = (Get-ItemProperty -Path $OwnerKey).RegisteredOwner,
        [string]$Organization = (Get-ItemProperty -Path $OwnerKey).RegisteredOrganization
    )

    $values = @{
        RegisteredOwner        = $Owner
        RegisteredOrganization = $Organization
    }

    $current = Get-ItemProperty -Path $OwnerKey
    foreach ($prop in $values.Keys) {
        $value = $values[$prop]
        if ($value -ne $current.$prop) {
            Invoke-Administrator "& { Set-ItemProperty -Path '$OwnerKey' -Name '$prop' -Value '$value' }"
        }
        else {
            Write-Output "No change for $prop"
        }
    }

    Get-Owner
}
