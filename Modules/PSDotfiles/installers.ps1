#region Tasks

function Install-Bootstrap {
    <#
        .SYNOPSIS
            Bootstrap PSDotfiles
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        # PSDotfiles path
        [string]$Path = $Env:PSDOTFILES,

        # Replace existing configuration
        [switch]$Force
    )

    Write-Output 'Bootstrap PSDotfiles'

    Write-Verbose "Install profile to $Path"
    Install-Profile -Path $Path -Force:$Force

    Write-Verbose 'Install vimrc'
    Install-Vimrc -Path $Path -Force:$Force

    Write-Verbose 'Install bin'
    Install-Bin

    Write-Output 'Boostrap complete'
}

function Update-DevTools {
    <#
    .SYNOPSIS
        Update/install developer tools
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Replace existing configuration
        [switch]$Force
    )

    Write-Output 'Updating developer system settings'

    Install-Bootstrap -Force:$Force

    Write-Output 'Update git configuration'
    Write-GitConfig

    Write-Output 'Update PowerShell modules'
    Update-PowerShellModules -Force:$Force

    # Enable Windows Features
    foreach ($f in @(
            'VirtualMachinePlatform',
            'HypervisorPlatform',
            'Microsoft-Hyper-V'
        )) {
        try {
            Write-Output "Enable $f"
            Invoke-Administrator -Command "& { Enable-WindowsOptionalFeature -Online -FeatureName '$f' -All -NoRestart }"
        }
        catch {
            Write-Warning $_
        }
    }

    # Write-Output 'Enable WSL'
    # Invoke-Administrator -Command { wsl --update; wsl --install --distribution Ubuntu }

    # Install developer tools
    # winget install --id GoLang.Go.1.19 --interactive
    # go install github.com/jstarks/npiperelay@latest

    Write-Output 'Recommend reboot to enable all services'
}

#endregion

#region Helpers

function Install-Zip {
    <#
    .SYNOPSIS
        Download and extract zip archive to target location
    .EXAMPLE
        PS C:\> Install-Zip -Uri https://example.com/myapp.zip -Dest C;\bin
        Downloads myapp.zip from URI and extracts to C:\bin
    .PARAMETER Uri
    URI of zip file
    .PARAMETER Dest
    Destination path
    #>
    [CmdletBinding()]
    param (
        [string]$Uri,
        [string]$Dest
    )
    process {
        try {
            # Create a random file in temp
            $zipfile = [System.IO.Path]::GetRandomFileName()
            $target = Join-Path -Path $env:TEMP -ChildPath $zipfile

            # Download to temp
            Write-Verbose "Downloading $uri to $target"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($uri, $target)

            # Unzip
            Write-Verbose "Extracting $target to $Dest"
            Expand-Archive -Path $target -DestinationPath $Dest -Force
        }
        finally {
            if (Test-Path $target) { Remove-Item -Path $target }
        }
    }
}

#endregion

#region Configuration

function Install-Profile {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        # Path of PSDotfiles
        [string]$Path = $Env:PSDOTFILES,

        [string]$PSProfile = $PROFILE.CurrentUserAllHosts,

        # Replace existing profile
        [switch]$Force
    )

    if ($Force -and (Test-Path $PSProfile)) {
        Remove-Item -Path $PSProfile -Force
    }

    if (-not (Test-Path $PSProfile)) {
        Write-Output 'Install PowerShell profile'
        New-Item -Path $PSProfile -ItemType File -Force
        $dotfilesProfile = (Join-Path $Path -ChildPath profile.ps1)
        Set-Content -Path $PSProfile -Value ". $dotfilesProfile"
    }
}

function Install-Vimrc {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        # Path of PSDotfiles
        [string]$Path = $Env:PSDOTFILES,

        # Replace existing vimrc
        [switch]$Force
    )
    # Vim profile
    $vimrc = Join-Path -Path $env:USERPROFILE -ChildPath _vimrc
    if ($Force) { Remove-Item -Path $vimrc -Force }
    if (-not (Test-Path -Path $vimrc)) {
        Write-Output 'Install vimrc'
        New-Item -Path $vimrc -ItemType File -Force
        $dotfilesVimrc = (Join-Path $Path -ChildPath conf\vimrc)
        Set-Content -Path $vimrc -Value "source $dotfilesVimrc"
    }
}

#endregion

#region Powershell modules

function Update-PowerShellModules {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Replace existing modules
        [switch]$Force
    )
    foreach ($m in @(
            'Microsoft.PowerShell.ConsoleGuiTools',
            'posh-git',
            'PSScriptAnalyzer',
            'WslInterop'
        )) {
        try {
            if (-not (Find-Module -Name $m -ErrorAction SilentlyContinue)) { throw "Module $m is not available" }

            if ($Force -and (Get-Module -Name $m)) {
                Write-Output "Removing $m"
                Uninstall-Module -Name $m -Force
            }

            if (-not (Get-Module -Name $m)) {
                Write-Output "Installing $m"
                Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -AllowPrerelease -AcceptLicense
            }
            else {
                Write-Output "Updating $m"
                Update-Module -Name $m -Scope CurrentUser -Force -AllowPrerelease -AcceptLicense
            }
        }
        catch {
            Write-Warning $_
        }
    }
}

#endregion

#region System

function Install-SSH() {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Enable OpenSSH Agent
        [switch]$EnableAgent
    )

    # Install OpenSSH
    # https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
    Invoke-Administrator -Command { Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 }
    Invoke-Administrator -Command { Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 }

    # Start sshd service
    Invoke-Administrator -Command {
        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'
    }
    Get-Service sshd

    if ($EnableAgent) {
        # Start ssh-agent service
        Invoke-Administrator -Command {
            Start-Service ssh-agent
            Set-Service -Name ssh-agent -StartupType 'Automatic'
        }
    }

    # Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
    if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
        Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
        Invoke-Administrator -Command {
            New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
        }
    } else {
        Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
    }

    # Configure default shell
    Invoke-Administrator -Command {
        Set-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value $Env:ProgramFiles\PowerShell\7\pwsh.exe
    }
}

function Enable-1PasswordSSH() {
    # Check if user is admin
    # if (true) {
        $keyfile = "$Env:ProgramData\ssh\administrators_authorized_keys"
        $keydata = @(ssh-add -L) -join "`r`n"

        Write-Output "Generating $keyfile"

        Invoke-Administrator -Command "& {
            Set-Content -Force -Path $keyfile -Value '$keydata'
            Get-Acl $ENV:ProgramData\ssh\ssh_host_dsa_key | Set-Acl $keyfile
        }"

        #icacls.exe '$keyfile' /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
        #icacls.exe '$keyfile' /remove 'Authenticated Users:F'

        #     # Set ACL's for users
        #     $users = @('Administrators', 'System')

        #     # Permissions: rights, inherit, propogation, rule type
        #     $permissions = @('FullControl', 'None', 'None', 'Allow')
        #     foreach ($u in $users) {
        #         $acl = Get-Acl $keyfile
        #         $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($u) + $permissions
        #         $acl.SetAccessRule($rule)
        #         $acl | Set-Acl -Path $keyfile
        #     }

        #     # Remove authenticated users
        #     $acl = Get-Acl $keyfile
        #     $rules = $acl.Access | where IsInherited -eq $false
        #     $targetRule = $rules | where IdentityReference -eq 'Authenticated Users'
        #     $acl.RemoveAccessRule($targetRule)
        #     $acl | Set-Acl -Path $keyfile
        # }"
    # }
    # else {
        # New-Item -Force -ItemType Directory -Path $Env:USERPROFILE\.ssh
        # Add-Content -Force -Path $Env:USERPROFILE\.ssh\authorized_keys -Value (ssh-add -L)
    # }
}

function Install-Remoting() {
    <#
    .SYNOPSIS
        Enable WS-Man remoting
    #>
    Write-Output 'Enable PowerShell Remoting'
    Invoke-Administrator -Core -Command {
        Install-PowerShellRemoting.ps1
        Enable-PSRemoting
    }
}

#endregion

#region Tools

function Install-Bin {
    <#
    .SYNOPSIS
        Create system root bin for adding tools (like /usr/local/bin on Unix)
    #>
    param()

    $usrbin = Join-Path -Path $Env:SystemDrive -ChildPath bin
    if (!(Test-Path -Path $usrbin)) {
        Write-Output "Creating $usrbin"
        New-Item -Path $usrbin -ItemType Directory
    }

    # Add to path so WSL can see it
    Update-Path @($usrbin) -SetEnv
}

function Install-CLI() {
    <#
    .SYNOPSIS
        Install CLI to ProgramFiles
    .PARAMETER Uri
        URI of zip file for CLI
    .PARAMETER Dest
        Directory to install to in Program Files
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter()]
        [string]$Uri,
        [string]$Dest
    )
    process {
        $destDir = Join-Path -Path $Env:ProgramFiles -ChildPath $Dest
        Invoke-Administrator -Command "& { Install-Zip -Uri '$Uri' -Dest '$destDir' }" -Core
        # Add CLI to path
        Update-Path @($destDir) -SetEnv
    }
}

function Install-SpeedtestCLI() {
    <#
    .SYNOPSIS
        Install speedtest cli
    #>
    $ver = "1.2.0"
    $uri = "https://install.speedtest.net/app/cli/ookla-speedtest-$($ver)-win64.zip"
    Install-CLI -Uri $uri -Dest 'Speedtest CLI'
}

function Install-1PasswordCLI() {
    <#
    .SYNOPSIS
        Install 1Password CLI
    #>
    $arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    switch ($arch) {
        '64-bit' { $opArch = 'amd64'; break }
        '32-bit' { $opArch = '386'; break }
        Default { Write-Error "Unsupported architecture '$arch'" -ErrorAction Stop }
    }
    $ver = "v2.4.1"
    $uri = "https://cache.agilebits.com/dist/1P/op2/pkg/$($ver)/op_windows_$($opArch)_$($ver).zip"
    Install-CLI -URI $uri -Dest '1Password CLI'
}
#endregion
