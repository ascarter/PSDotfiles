# PSDotfiles

> This project is archived. It has been merged with [dotfiles](https://github.com/ascarter/dotfiles).


PSDotfiles is a PowerShell module for configuring the user environment. It is inspired by how dotfiles work in POSIX operating systems but adapted for Windows and PowerShell.

## Layout

* `conf` - Configuration files for utilities like Vim
* `Modules` - PowerShell modules

An optional install script is available to provision PSDotfiles.

## Requirements

PSDotfiles requires:

* Windows 10 or Windows 11
* PowerShell 7.0 or later

### Pre-requisites

Enable [Developer mode](https://www.hanselman.com/blog/Windows10DeveloperMode.aspx):

> *Settings* -> *Privacy & security* -> *For Developers*

Additional requirements:

* [git](https://git-scm.com/download/win)
* [OpenSSH](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview)
* [PowerShell Core](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-windows?view=powershell-7)
* [Windows Package Manager](https://github.com/microsoft/winget-cli)
* [Windows Subsystem for Linux 2](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install)

To run the provided install script:

```powershell
Set-ExecutionPolicy Bypass -Scope Process; Invoke-WebRequest https://raw.githubusercontent.com/ascarter/PSDotfiles/main/install.ps1 -UseBasicParsing | Invoke-Expression
```

#### Alternate Install

If directly executing powershell script is not desired, clone into a location (recommend `%USERPROFILE%\.config\PSDotfiles`).

```powershell
git clone git@github.com:ascarter/PSDotfiles.git $env:USERPROFILE\.config\PSDotfiles
cd $env:USERPROFILE\.config\PSDotfiles
.\install.ps1
```

### Update Developer Tools

`PSDotfiles` is implemented as a PowerShell module. The module should be configured to be enabled in the user profile. A convenience cmdlet `Update-DevTools` is available to quickly update a useful set of Windows developer tools.

```powershell
PS> Update-DevTools
```

### Uninstall

Run uninstall PowerShell script to remove links:

```powershell
cd $env:USERPROFILE\.config\PSDotfiles
.\uninstall.ps1
```
