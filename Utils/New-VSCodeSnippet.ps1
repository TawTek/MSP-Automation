function Get-VSCodePSSnippetFile {

    #region LOGIC -----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Determine the path to the PowerShell snippets file for VS Code/Windsurf/Cursor/Zed based on the operating system and editor.

    [LOGIC]
    1. Detects editor (VS Code, Windsurf, VSCodium, Cursor, Zed) and operating system
    2. Checks for existing snippet paths in order of preference
    3. Returns the first valid path found, or creates the directory structure
    #>
    #endregion -------------------------------------------------------------------------------------------------------------

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
        return $existingPath
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

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter()][string]$Prefix = $null,
        [Parameter(ValueFromPipeline=$true)][string[]]$Code,
        [Parameter()][string]$FilePath,
        [Parameter()][string]$Description,
        [Parameter()][string]$PowershellJsonPath = "Dynamic"
    )

    begin { $scriptLines = @() }

    process {
        if ($Code) {
            foreach ($b in $Code) {
                # Split here-string or multi-line string into individual lines
                $lines = $b -split "`r?`n"
                $scriptLines += $lines
            }
        }
    }

    end {
        # Read script from file if specified
        if ($FilePath) {
            if (-Not (Test-Path $FilePath)) { Throw "File '$FilePath' does not exist." }
            $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
            $scriptLines = $content -split "`r?`n"
        }

        if (-not $scriptLines) { Throw "No script content provided via -Body, pipeline, or -FilePath." }

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
}

#Convert-ToVSCodeSnippet -Name "" -Prefix "" -Description "" -Code @''@