function Get-VSCodePSSnippetFile {

    #region LOGIC -----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Determine the path to the PowerShell snippets file for VS Code based on the operating system.

    [LOGIC]
    1. Initializes $BasePath variable for VS Code user snippets based on OS:
       - Linux: ~/.config/Code/User/snippets
       - macOS: ~/Library/Application Support/Code/User/snippets
       - Windows: %APPDATA%\Code\User\snippets (default)
    2. Combines the $BasePath with 'powershell.json' and returns the full path
    #>
    #endregion -------------------------------------------------------------------------------------------------------------

    $BasePath = switch ($true) {
        { $PSVersionTable.Platform -eq 'Unix' } { Join-Path $HOME '.config/Code/User/snippets'; break }
        { $PSVersionTable.Platform -eq 'MacOS' } { Join-Path $HOME 'Library/Application Support/Code/User/snippets'; break }
        default { Join-Path $env:APPDATA 'Windsurf\User\snippets' }
    }
    return Join-Path $BasePath 'powershell.json'
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