function Get-VSCodePSSnippetFile {

    <#
    .SYNOPSIS
        Determine the path to the PowerShell snippets file for VS Code/Windsurf/Cursor/Zed based on operating system.

    .DESCRIPTION
        Detects the operating system and checks for existing snippet paths in order of preference.
        Returns the first valid path found, or creates the directory structure for the preferred editor.

        [LOGIC]
        1. Detects operating system (Windows, Unix, macOS)
        2. Checks existing snippet paths in order: VS Code > VSCodium > Windsurf > Cursor > Zed > VS Code Insiders
        3. Returns first valid path found, or creates directory for VS Code (fallback)

    .OUTPUTS
        System.String - Full path to the PowerShell snippets JSON file
    #>

    $platform = $PSVersionTable.Platform
    $isWindowsOS = $platform -eq 'Win32NT' -or $null -eq $platform
    
    # Define editor snippet paths by platform
    $editorPaths = @{
        Windows = @{
            'VS Code'  = "$env:APPDATA\Code\User\snippets\powershell.json"
            'VSCodium' = "$env:APPDATA\VSCodium\User\snippets\powershell.json"
            'Windsurf' = "$env:APPDATA\Windsurf\User\snippets\powershell.json"
            'Cursor'   = "$env:APPDATA\Cursor\User\snippets\powershell.json"
            'Zed'      = "$env:APPDATA\Zed\User\snippets\powershell.json"
            'VSCode-I' = "$env:APPDATA\Code - Insiders\User\snippets\powershell.json"
        }
        
        Unix = @{
            'VS Code'  = "$HOME/.config/Code/User/snippets/powershell.json"
            'VSCodium' = "$HOME/.config/VSCodium/User/snippets/powershell.json"
            'Windsurf' = "$HOME/.config/windsurf/User/snippets/powershell.json"
            'Cursor'   = "$HOME/.config/cursor/User/snippets/powershell.json"
            'Zed'      = "$HOME/.config/zed/User/snippets/powershell.json"
        }
        
        MacOS = @{
            'VS Code'  = "$HOME/Library/Application Support/Code/User/snippets/powershell.json"
            'VSCodium' = "$HOME/Library/Application Support/VSCodium/User/snippets/powershell.json"
            'Windsurf' = "$HOME/Library/Application Support/windsurf/User/snippets/powershell.json"
            'Cursor'   = "$HOME/Library/Application Support/cursor/User/snippets/powershell.json"
            'Zed'      = "$HOME/Library/Application Support/zed/User/snippets/powershell.json"
        }
    }

    # Get paths for current platform
    $platformKey = if ($isWindowsOS) { 'Windows' } elseif ($platform -eq 'Unix') { 'Unix' } else { 'MacOS' }
    $possiblePaths = $editorPaths[$platformKey].Values

    # Return the first existing path (more efficient than foreach)
    $existingPath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($existingPath) {
        return "$env:APPDATA\Windsurf\User\snippets\powershell.json"
    }

    # If no existing path found, return the first valid option and create directory
    $fallbackPath = $possiblePaths[0]
    $directory = Split-Path $fallbackPath -Parent
    
    if (-not (Test-Path $directory)) {
        try {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
            Write-Host "Created snippets directory: $directory" -ForegroundColor Green
        } catch {
            Write-Warning "Could not create snippets directory: $directory"
        }
    }
    
    return $fallbackPath
}

function Convert-ToVSCodeSnippet {

    <#
    .SYNOPSIS
        Convert PowerShell code to VS Code snippets.

    .DESCRIPTION
        Converts PowerShell code into VS Code snippet format and adds it to the PowerShell snippets file.
        Supports ScriptBlock, Code (here-strings), and FilePath input methods using switch statement logic.

    .PARAMETER Name
        The name of the snippet (used as the snippet key).

    .PARAMETER Prefix
        The prefix that triggers the snippet. Defaults to the Name if not specified.

    .PARAMETER Code
        PowerShell code as string (here-strings).

    .PARAMETER ScriptBlock
        PowerShell scriptblock containing the code. Recommended for testable snippets.

    .PARAMETER FilePath
        Path to a PowerShell file containing the code to convert.

    .PARAMETER Description
        Description of the snippet for VS Code hover help.

    .PARAMETER PowershellJsonPath
        Path to the PowerShell snippets JSON file. Uses "Dynamic" to auto-detect based on installed editors.

    .OUTPUTS
        None. Creates or updates the VS Code snippets file.

    .EXAMPLE 1 - ScriptBlock (Recommended)
        $scriptBlock = {
            param([string]$Message)
            Write-Host "Hello $Message"
        }
        Convert-ToVSCodeSnippet -Name "Greet" -ScriptBlock $scriptBlock -Description "Simple greeting function"

    .EXAMPLE 2 - Here-String
        $snippet = @'
        param($Path)
        Get-ChildItem $Path | Where-Object { $_.Extension -eq ".ps1" }
        '@
        Convert-ToVSCodeSnippet -Name "Get-PSFiles" -Code $snippet -Description "Get PowerShell files"

    .NOTES
        Requires Get-VSCodePSSnippetFile function for dynamic path detection
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter()][string]$Prefix = $null,
        [Parameter()][string]$Code,
        [Parameter()][string]$FilePath,
        [Parameter()][scriptblock]$ScriptBlock,
        [Parameter()][string]$Description,
        [Parameter()][string]$PowershellJsonPath = "Dynamic"
    )

    # Process input based on provided parameter
    switch ($true) {
        { $ScriptBlock } {
            Write-Host "Processing ScriptBlock parameter"
            $scriptLines = $ScriptBlock.ToString() -split "`r?`n"
            Write-Host "ScriptBlock converted to $($scriptLines.Count) lines"
        }
        { $Code } {
            Write-Host "Processing Code parameter"
            $scriptLines = $Code -split "`r?`n"
            Write-Host "Code converted to $($scriptLines.Count) lines"
        }
        { $FilePath } {
            if (-Not (Test-Path $FilePath)) { Throw "File '$FilePath' does not exist." }
            $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
            $scriptLines = $content -split "`r?`n"
            Write-Host "File content converted to $($scriptLines.Count) lines"
        }
        default {
            Throw "No script content provided via -Code, -ScriptBlock, or -FilePath."
        }
    }
    
    # Validate script content and line count
    if (-not $scriptLines -or $scriptLines.Count -eq 0) { 
        Throw "No script content provided via -Code, -ScriptBlock, or -FilePath."
    } else {
        Write-Host "Total scriptLines count: $($scriptLines.Count)"
    }

    # Build the new snippet as an ordered hashtable to preserve key order
    $newSnippet = [ordered]@{
        ($Name) = [ordered]@{
            prefix =  if ($Prefix) { $Prefix } else { $Name }
            description = $Description
            body        = $scriptLines
        }
    }

    # Determine path for powershell.json
    if ($PowershellJsonPath -eq "Dynamic") { $PowershellJsonPath = Get-VSCodePSSnippetFile }

    # Load existing snippets or create empty ordered hashtable
    if (Test-Path $PowershellJsonPath) {
        $existingJson = Get-Content $PowershellJsonPath -Raw | ConvertFrom-Json
        $existingSnippets = [ordered]@{}
        foreach ($k in $existingJson.psobject.Properties.Name) {
            $existingSnippets[$k] = $existingJson.$k
        }
    } else {
        $existingSnippets = [ordered]@{}
    }

    # Add the new snippet only if it doesn't exist
    if (-not $existingSnippets.Contains($Name)) {
        $existingSnippets[$Name] = $newSnippet[$Name]
        Write-Host "Snippet '$Name' added to $PowershellJsonPath"
    } else {
        Write-Warning "Snippet '$Name' already exists. Skipping."
    }

    # Convert to JSON for VS Code
    $json = $existingSnippets | ConvertTo-Json -Depth 5

    # Escape $ for VS Code snippet placeholders (single backslash)
    $json = $json -replace '(?<!\\)\$', '\\$'

    # Save JSON to file
    $json | Set-Content -Path $PowershellJsonPath -Encoding UTF8
}

<#
# Example 1: ScriptBlock
$TestScriptBlock = {
    param([string]$Message)
    Write-Host "Test function says: $Message"
}
Convert-ToVSCodeSnippet -Name "Test-Function" -ScriptBlock $TestScriptBlock -Description "A simple test function"

# Example 2: Here-String
$TestHereString = @'
param($Path)
Get-ChildItem $Path | Where-Object { $_.Extension -eq ".ps1" } | Select-Object Name, Length
'@
Convert-ToVSCodeSnippet -Name "Get-PSFiles" -Code $TestHereString -Description "Get all PowerShell files with details"
#>