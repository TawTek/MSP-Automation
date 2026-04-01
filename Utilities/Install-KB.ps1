param(
    [string]$ID        = 'KB5007651',
    [switch]$NoRestart = $( & { if ($env:noRestart -eq 'False') { $false } else { $true } } )
)

#-Variables [Global]
$TempDir   = "C:\Temp\WU\$ID"

<#-----------------------------------------------------------------------------------------------------------
SCRIPT:FUNCTIONS
-----------------------------------------------------------------------------------------------------------#>

function Get-KB {
    param(
        [string]$ID
    )

    $KB = @{
        KB5002623 = @{
            URL = 'https://download.microsoft.com/download/95c52cad-d981-49da-abf3-cafb6806cd9/msodll202016-kb5002623-fullfile-x86-glb.exe'
        }
        KB5007651 = @{
            URL = 'https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/defu/2025/04/securityhealthsetup_1528aebc5e90a333bf0f8a3f0d98b458311581fa.exe'
        }
        KB5051987 = @{
            URL = 'https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/d94b06df-34e8-42be-9e62-afe448c65da8/public/windows11.0-kb5051987-x64_199ed7806a74fe78e3b0ef4f2073760000f71972.msu'
        }
        KB5052000 = @{
            URL = 'https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/02/windows10.0-kb5052000-x64_4d5c653ed24d769894ed1a2855d1c59fa70135af.msu'
        }
        KB5065426 = @{
            URL = 'https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/7342fa97-e584-4465-9b3d-71e771c9db5b/public/windows11.0-kb5065426-x64_32b5f85e0f4f08e5d6eabec6586014a02d3b6224.msu'
        }
        KB5054156 = @{
            URL = 'https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/fa84cc49-18b2-4c26-b389-90c96e6ae0d2/public/windows11.0-kb5054156-x64_a0c1638cbcf4cf33dbe9a5bef69db374b4786974.msu'
            PRE = 'KB5074105'
        }
        KB5074105 = @{
            URL = 'https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/1f3ba14b-3831-4dd8-8839-b63b795497e4/public/windows11.0-kb5074105-x64_74e1f93136eef7114e2bed8ff032b049ec62992a.msu'
        }
    }

    if ($KB.ContainsKey($ID)) {
        return [PSCustomObject]@{
            ID  = $ID
            URL = $KB[$ID].URL
            PRE = if ($KB[$ID].ContainsKey('PRE')) { $KB[$ID].PRE } else { $null }
        }
    } else {
        Write-Output "No matching KB found for ID: $ID"
    }
}

function Install-KB {

    param (
        [string]$ID,
        [string]$URL
    )

    if ($URL) {

        $KBFile = [System.IO.Path]::GetFileName($URL)
        $KBPath = Join-Path -Path $TempDir -ChildPath $KBFile

         if (-not (Test-Path $KBPath)) {
            Get-File -URL $URL -Path $KBPath
        }

        try {
            Write-Host "[INFO] Installing $ID."
            $Arguments = "/quiet $(if ($NoRestart) { '/norestart' })"
            $Process = Start-Process -FilePath $KBPath -ArgumentList $Arguments -Wait -PassThru
            if ($Process.ExitCode -ne 0) {
                Get-ExitCode -Code $Process.ExitCode
            } else {
                Write-Host "[PASS] $ID has been installed."
            }
        } catch {
            Write-Host "[FAIL] An unexpected error occurred: $($_.Exception.Message)"
        }
    } else {
        Write-Host "[FAIL] Could not retrieve a valid URL for $ID"
    }

    exit
}

function Get-ExitCode {
    param (
        [int]$Code
    )

    switch ($Code) {
        1058        { Write-Host '[FAIL] WUAUSERV cannot be started. Try to start WUAUSERV service, if it cannot run then will need to reset Windows Update Components.' }
        1618        { Write-Host '[INFO] Another installation is already in progress.' }
        1641        { Write-Host '[INFO] System will now reboot.' }
        3010        { Write-Host '[INFO] System requires a reboot to finalize installation.' }
        2359302     { Write-Host '[INFO] Update is already installed, terminating script.' }
        -2145124329 { Write-Host '[INFO] Update is not applicable for this device, skipping.' }
        default      { Write-Host "[FAIL] Wusa.exe Process failed with exit code $Code." }
    }
}

function Get-File {

    <#
    [SUMMARY]
    Downloads a file from a specified URL/UNC path and saves it to a specified destination.

    [PARAMETERS]
    - $UNC : If declared, copy the file from a UNC path.
    - $URL : The URL of the file to download.
    - $Path: The path to save the file to.

    [LOGIC]
    1. Set the $ProgressPreference variable to 'SilentlyContinue'.
    2. Set an array of download methods.
    3. Set the Security Protocols.
    4. Check if $UNC is declared, otherwise skip that download method.
    5. Try each download method, if successful, break out of the loop.
    6. If the file extension is .zip, extract the archive to the Path directory.
    7. If all download methods fail, throw an error.
    #>

    [CmdletBinding()]
    param(
        # Download sources
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$URL,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$UNC,

        # Destination
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Path
    )

    $ProgressPreference = 'SilentlyContinue'

    if (Test-Path $Path) { Write-Log -Info "$Path exists." ; return }

    # Set array for download methods
    $DownloadMethods = @(
        @{ Name = "copying from UNC Path"; Action = { Copy-Item -Path $UNC -Destination $Path -Force -EA Stop }},
        @{ Name = "Invoke-WebRequest"; Action = { Invoke-WebRequest -Uri $URL -OutFile $Path -EA Stop }},
        @{ Name = "Start-BitsTransfer"; Action = { Start-BitsTransfer -Source $URL -Destination $Path -EA Stop }},
        @{ Name = "WebClient"; Action = { (New-Object System.Net.WebClient).DownloadFile($URL, $Path) }}
    )

    # Set Security Protocols
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Loop through each download method
    foreach ($Method in $DownloadMethods) {
        if ($Method.Name -eq "copying from UNC Path") {if (-not $UNC -or -not (Test-Path -Path $UNC -EA SilentlyContinue)) { continue } }
        try {
            Write-Log -Info "Attempting to download by $($Method.Name)."
            & $Method.Action
            Write-Log -Pass "Download completed by $($Method.Name)."
            $Downloaded = $true
            #----Extract archive if file extension ends in .zip
            if ($Path -like "*.zip") {
                Write-Log -Info "Extracting $Path."
                Expand-Archive -LiteralPath $Path -DestinationPath (Split-Path -Path $Path -Parent) -Force
                Write-Log -Pass "Extraction complete."
            }
            break
        } catch {
            Write-Log -Fail "Failed to download by $($Method.Name). $($_.Exception.Message)"
        }
    }

    # Terminate script if all $DownloadMethods fail
    if (-not $Downloaded) { Write-Log -Fail "All download methods failed, terminating script." ; exit 1 }
}

function Set-Dir {

    #region LOGIC -----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Creates or deletes a directory at a specified path.

    [PARAMETERS]
    - $Path: The path to create or delete the directory at.
    - $Create: If declared, create the directory.
    - $Remove: If declared, delete the directory.

    [LOGIC]
    1. Check if both $Create and $Remove switches are not declared, if so, throw an error.
    2. Create or delete the directory based on the switches and whether the directory exists.
    3. Throw an error if the directory cannot be created or deleted.
    #>
    #endregion -------------------------------------------------------------------------------------------------------------

    param (
        [string]$Path,
        [switch]$Create,
        [switch]$Remove
    )

    if (-not $Create.IsPresent -and -not $Remove.IsPresent) {
        Write-Host "[FAIL] Must declare -Create or -Remove switch with Set-Dir function." ; exit
    }

    switch ($true) {
        { $Create.IsPresent } {
            if (-not (Test-Path -Path $Path)) {
                try {
                    Write-Host "[INFO] Creating directory at $Path"
                    New-Item -Path $Path -ItemType "Directory" | Out-Null
                    Write-Host "[PASS] Created directory at $Path."
                } catch {
                    Write-Host "[FAIL] Failed to create directory. $($_.Exception.Message)"
                }
            } else {
                Write-Host "[INFO] Directory exists at $Path"
            }
        }
        { $Remove.IsPresent } {
            try {
                Write-Host "[INFO] Deleting directory."
                Remove-Item -Path $Path -Recurse -Force @EA_Stop
                Write-Host "[PASS] Directory deleted."
            } catch {
                Write-Host "[FAIL] Failed to remove directory. $($_.Exception.Message)"
            }
        }
    }
}

function Test-Prereq {
    
    param(
        [string]$ID
    )

    $CurrentVersion = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $CurrentBuild   = [double]("$($CurrentVersion.CurrentBuildNumber).$($CurrentVersion.UBR)")

    switch ($ID) {
        'KB5054156' {
            $MinimumBuild = 26100.5074
            return $CurrentBuild -ge $MinimumBuild
        }
        default {
            return $false
        }
    }
}

<#-----------------------------------------------------------------------------------------------------------
SCRIPT:EXECUTIONS
-----------------------------------------------------------------------------------------------------------#>

Set-Dir -Path $TempDir -Create

if ($ID -eq 'KB5054156') {
    if (Test-Prereq -ID $ID) {
        Write-Host "[WARN] Prerequisites not met for $ID"
        Write-Host "[WARN] $((Get-KB -ID $ID).PRE) required before installing $ID."
        Install-KB -ID (Get-KB -ID $ID).PRE -URL $URL
    }
}

Install-KB -ID $ID -URL (Get-KB $ID).URL