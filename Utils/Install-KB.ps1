param(
    [string]$ID        = 'KB5051974',
    [switch]$NoRestart = $( & { if ($env:noRestart -eq 'False') { $false } else { $true } } )
)

#-Variables [Global]
$EA_Silent = @{ErrorAction = "SilentlyContinue"}
$TempDir   = "C:\Temp\WU\$ID"
$MSU       = "$ID.msu"

<#-----------------------------------------------------------------------------------------------------------
SCRIPT:FUNCTIONS
-----------------------------------------------------------------------------------------------------------#>

function Get-KB {

    $KB = @{
        KB5051974 = @{
            URL = 'https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/02/windows10.0-kb5051974-x64_74aa601c3966a9e1ad4efe6287550c0f0bdea59d.msu'
        }
        KB5052000 = @{
            URL = 'https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/02/windows10.0-kb5052000-x64_4d5c653ed24d769894ed1a2855d1c59fa70135af.msu'
        }
    }

    if ($KB.ContainsKey($ID)) {
        return $KB[$ID].URL
    } else {
        Write-Output "No matching KB found for ID: $ID"
    }
}

function Install-KB {
    Set-Dir -Path $TempDir -Create
    if (-not (Test-Path $TempDir\$MSU)) { 
        Get-File -URL (Get-KB) -Destination $TempDir\$MSU 
    }

    try {
        Write-Host "[INFO] Installing $ID."
        $Process = Start-Process -FilePath "wusa.exe" -ArgumentList "$TempDir\$MSU /quiet $(if ($NoRestart) { '/norestart' })" -Wait -PassThru -NoNewWindow
        if ($Process.ExitCode -ne 0) { Get-ExitCode -Code $Process.ExitCode }
        else { Write-Host "[PASS] $ID has been installed." }
    } catch {
        Write-Host "[FAIL] An unexpected error occurred: $($_.Exception.Message)"
    }
    exit
}

function Get-ExitCode {
    param (
        [int]$Code
    )

    switch ($Code) {
        1058        { Write-Host "[FAIL] WUAUSERV cannot be started. Try to start WUAUSERV service, if it cannot run then will need to reset Windows Update Components." }
        1641        { Write-Host "[INFO] System will now reboot." }
        2359302     { Write-Host "[INFO] Update is already installed, terminating script." ; Set-Dir -Path $TempDir -Remove }
        -2145124329 { Write-Host "[INFO] Update is not applicable for this device, skipping." }
        default     { Write-Host "[FAIL] Wusa.exe Process failed with exit code $Code." }
    }
}

function Get-File {

    #region LOGIC -----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Downloads a file from a specified URL/UNC path and saves it to a specified destination.

    [PARAMETERS]
    - $UNC: If declared, copy the file from a UNC path.
    - $URL: The URL of the file to download.
    - $Destination: The path to save the file to.

    [LOGIC]     
    1. Set the $ProgressPreference variable to 'SilentlyContinue'.
    2. Set an array of download methods.
    3. Set the Security Protocols.
    4. Check if $UNC is declared, otherwise skip that download method.
    5. Try each download method, if successful, break out of the loop.
    6. If the file extension is .zip, extract the archive to the Destination directory.
    7. If all download methods fail, throw an error.
    #>
    #endregion -------------------------------------------------------------------------------------------------------------    

    param (
        [string]$UNC,
        [string]$URL,
        [string]$Destination
    )
    
    $ProgressPreference = 'SilentlyContinue'
    
    # Set array for download methods
    $DownloadMethods = @(
        @{ Name = "copying from UNC Path"; Action = { Copy-Item -Path $UNC -Destination $Destination -Force @EA_Stop }},
        @{ Name = "Invoke-WebRequest"; Action = { Invoke-WebRequest -Uri $URL -OutFile $Destination @EA_Stop }},
        @{ Name = "Start-BitsTransfer"; Action = { Start-BitsTransfer -Source $URL -Destination $Destination @EA_Stop }},
        @{ Name = "WebClient"; Action = { (New-Object System.Net.WebClient).DownloadFile($URL, $Destination) }}
    )

    # Set Security Protocols
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor
                                                  [Net.SecurityProtocolType]::Tls11 -bor
                                                  [Net.SecurityProtocolType]::Tls

    # Loop through each download method
    foreach ($Method in $DownloadMethods) {
        if ($Method.Name -eq "copying from UNC Path") {if (-not $UNC -or -not (Test-Path -Path $UNC @EA_Silent)) { continue } }
        try {
            Write-Host "[INFO] Attempting to download by $($Method.Name)."
            & $Method.Action
            Write-Host "[PASS] Download completed by $($Method.Name)."
            $Downloaded = $true
            #----Extract archive if file extension ends in .zip
            if ($Destination -like "*.zip") {
                Write-Host "[INFO] Extracting $Destination."
                Expand-Archive -LiteralPath $Destination -DestinationPath $TempDir -Force @EA_Stop
                Write-Host "[PASS] Extraction complete."
            }
            break
        } catch {
            Write-Host "[FAIL] Failed to download by $($Method.Name). $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Terminate script if all $DownloadMethods fail
    if (-not $Downloaded) { throw "[FAIL] All download methods failed, terminating script." }
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

<#-----------------------------------------------------------------------------------------------------------
SCRIPT:EXECUTIONS
-----------------------------------------------------------------------------------------------------------#>

Install-KB