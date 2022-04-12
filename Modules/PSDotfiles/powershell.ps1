# Enable winget completion
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Register-ArgumentCompleter -Native -CommandName winget -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)

        [Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.Utf8Encoding]::new()
        $Local:word = $wordToComplete.Replace('"', '""')
        $Local:ast = $commandAst.ToString().Replace('"', '""')
        winget complete --word="$Local:word" --commandline "$Local:ast" --position $cursorPosition | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}

function Get-CmdletAlias ($cmdletname) {
    <#
        .SYNOPSIS
            List aliases for any cmdlet
    #>
    Get-Alias |
    Where-Object -FilterScript { $_.Definition -like "$cmdletname" } |
    Format-Table -Property Definition, Name -AutoSize
}

function Get-Uname {
    <#
    .SYNOPSIS
    Emulate Unix uname
    #>
    Get-CimInstance Win32_OperatingSystem | Select-Object 'Caption', 'CSName', 'Version', 'BuildType', 'OSArchitecture' | Format-Table
}

function Invoke-SSHWithPassword {
    <#
        .SYNOPSIS
            Execute SSH using password authentication
    #>
    [CmdletBinding()]
    param (
        [string[]]
        [Parameter(Position=1, ValueFromRemainingArguments)]
        $Remaining
    )
    ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no $Remaining
}

# Unix aliases
Set-Alias -Name uname -Value Get-Uname
Set-Alias -Name ll -Value Get-ChildItem
Set-Alias -Name which -Value Get-Command

# macOS aliases
Set-Alias -Name pbcopy -Value Set-Clipboard
Set-Alias -Name pbpaste -Value Get-Clipboard

Set-Alias -Name fal -Value Get-CmdletAlias

Set-Alias -Name sshpw -Value Invoke-SSHWithPassword
