<#
.SYNOPSIS
    Automates the deployment of the Aline eMAR application suite and its dependencies.

.DESCRIPTION
    This script performs a fully automated installation of the Aline eMAR suite, including all required drivers and supporting applications. 
    It executes the following steps:
    1. Creates a temporary working directory for installation files.
    2. Downloads the Aline eMAR installation package (ZIP archive) from a specified URL.
    3. Extracts the package contents.
    4. Imports required registry settings for the eMAR environment.
    5. Installs the following components in order:
        - Microsoft ODBC Driver for SQL Server
        - Microsoft SQL Command Line Utilities
        - ACCUflo
        - ACCUDrug
        - ACCULogin
        - ACCUsummary
        - ACCUSync
        - ACUUfloUpdaterClient
    6. Provides detailed logging for each step and error handling.
    7. Cleans up the temporary installation directory after completion.

.NOTES
    Developer  : Tawhid Chowdhury [Proactive Services Manager]
    Contributor: Eugene Saladaga [NOC Engineer]
    Created    : 2025-08-19
    Updated    : 2025-08-26
    Version    : 6.0
#>

#region PARAM_VAR ----------------------------------------------------------------------------------------------------------

$Path    = "C:\Temp\eMAR"
$PathZip = "$Path\Aline_eMAR_6.12.11.zip"
$URL     = "https://transfer.hostmyit.com/ninja/EL/Aline_eMAR_v6.12.11.zip"

#endregion -----------------------------------------------------------------------------------------------------------------	

#region FUNCTIONS ----------------------------------------------------------------------------------------------------------

function Install-eMAR {

    #region LOGIC -----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Downloads and installs the Aline eMAR application suite and its dependencies.

    [LOGIC]
    1. Define the URL, temporary directory, and zip path.
    2. Define an array of applications to install with their names, paths, and arguments.
    3. Create the temporary directory if it doesn't exist.
    4. Download the zip file if it doesn't exist.
    5. Import the registry file.
    6. Loop through each application and install it using msiexec.exe with the specified arguments.
    7. Handle any errors that occur during the installation process.
    #>
    #endregion -------------------------------------------------------------------------------------------------------------

    $Apps = @(
        # MSI Installers
        [PSCustomObject]@{
            Name = "ODBC Driver"
            Path = "$Path\msodbcsql_*.msi"
            Args = @(
                "/qn"
                "IACCEPTMSODBCSQLLICENSETERMS=YES"
                "ADDLOCAL=ALL"
            )
        },
        [PSCustomObject]@{
            Name = "SQLCMD Utilities"
            Path = "$Path\MsSqlCmdLnUtils*.msi"
            Args = @(
                "/qn"
                "IACCEPTMSSQLCMDLNUTILSLICENSETERMS=YES"
            )
        },

        # EXE Installer (separated EXE and MSI args)
        [PSCustomObject]@{
            Name = "ACCUflo"
            Path = "$Path\Accuflo_Setup_x64_*.exe"
            Args = @{
                ArgsEXE = @("/s")
                ArgsMSI = @(
                    "/qn"
                    "CS_SERVICE_PASSWORD_IS_VALID=1"
                    "REGISTRY_ACCUSYNC_HOSTNAME=https://accusync-a.creativestrategiesus.com"
                    "REGISTRY_AUTH_TOKEN=/"
                    "ADDLOCAL=ACCUTask,Reports,Maintenance,ACCUflo,eMARWebAPI,Database,ACCUfloCache,ACCUfloConfig,ACCUfloConfigx64Reg,AccuTaskx64Reg,AccufloCachex64Reg,Accuflox64Reg,Common,Commonx64Reg,Databasex64Reg"
                )
            }
        },
        [PSCustomObject]@{
            Name = "ACCUDrug"
            Path = "$Path\ACCUDrug_Setup_x64_*.exe"
            Args = @{
                ArgsEXE = @("/clone_wait", "/s")
                ArgsMSI = @("/qn")
            }
        },
        [PSCustomObject]@{
            Name = "ACCULogin"
            Path = "$Path\ACCULogin_Setup_x64_*.exe"
            Args = @{
                ArgsEXE = @("/clone_wait", "/s")
                ArgsMSI = @("/qn")
            }
        },
        [PSCustomObject]@{
            Name = "ACCUsummary"
            Path = "$Path\ACCUsummary_Setup_x64_*.exe"
            Args = @{
                ArgsEXE = @("/clone_wait", "/s")
                ArgsMSI = @("/qn")
            }
        },
        [PSCustomObject]@{
            Name = "ACCUSync"
            Path = "$Path\ACCUSync_Setup_x64_*.exe"
            Args = @{
                ArgsEXE = @("/clone_wait", "/s")
                ArgsMSI = @("/qn")
            }
        },
        [PSCustomObject]@{
            Name = "ACCUfloUpdaterClient"
            Path = "$Path\UpdaterClient_Setup_x64_*.exe"
            Args = @{
                ArgsEXE = @("/clone_wait", "/s")
                ArgsMSI = @("/qn")
            }
        }
    )

    try {
        Write-Host "[INFO] Importing registry."
        reg import "$Path\accuflo6x.reg" > $null 2>&1
        Write-Host "[PASS] Registry imported successfully."

        # Loop through each application and install
        foreach ($App in $Apps) {
            $Log = "$Path\Log_$($App.Name).log"
            Write-Host "[INFO] Installing $($App.Name)."
            switch (Get-ChildItem -Path $App.Path | Select-Object -First 1 -ExpandProperty FullName) {
                { $_ -like "*.exe" } {
                    $ArgsList = $App.Args.ArgsEXE + "/v`"$($App.Args.ArgsMSI -join ' ') /l*v `"$Log`"`"" # Combine ArgsEXE + ArgsMSI arguments into one string and add dynamic logging path
                    $Process  = Start-Process -FilePath $_ -ArgumentList $ArgsList -Wait -NoNewWindow -PassThru -EA Stop
                    if ($Process.ExitCode -ne 0) { throw "[FAIL] $($App.Name) installation failed with exit code $($Process.ExitCode). See $Log" }
                }
                { $_ -like "*.msi" } {
                    $ArgList = @("/i", "`"$_`"") + $App.Args + @("/l*v", "`"$Log`"") # Create msiexec arguments array with proper quoting for paths with spaces if they exist and add dynamic logging path
                    $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $ArgList -Wait -NoNewWindow -PassThru -EA Stop
                    if ($Process.ExitCode -ne 0) { throw "[FAIL] $($App.Name) installation failed with exit code $($Process.ExitCode). See $Log" }
                } default { throw "Unknown installer type for $($App.Name)" }
            }
        }
        Write-Host "[PASS] All components have attempted install." ; $Global:Attempted = $true
    } catch {
        Write-Host "[FAIL] $($_.Exception.Message)" ; throw
    }
}

#endregion -----------------------------------------------------------------------------------------------------------------

#region ANCILLARY_FUNCTIONS ------------------------------------------------------------------------------------------------

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
        @{ Name = "copying from UNC Path"; Action = { Copy-Item -Path $UNC -Destination $Destination -Force -EA Stop }},
        @{ Name = "Invoke-WebRequest"; Action = { Invoke-WebRequest -Uri $URL -OutFile $Destination -EA Stop }},
        @{ Name = "Start-BitsTransfer"; Action = { Start-BitsTransfer -Source $URL -Destination $Destination -EA Stop }},
        @{ Name = "WebClient"; Action = { (New-Object System.Net.WebClient).DownloadFile($URL, $Destination) }}
    )

    # Set Security Protocols
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor
                                                  [Net.SecurityProtocolType]::Tls11 -bor
                                                  [Net.SecurityProtocolType]::Tls

    # Loop through each download method
    foreach ($Method in $DownloadMethods) {
        if ($Method.Name -eq "copying from UNC Path") {if (-not $UNC -or -not (Test-Path -Path $UNC -EA SilentlyContinue)) { continue } }
        try {
            Write-Host "[INFO] Attempting to download by $($Method.Name)."
            & $Method.Action
            Write-Host "[PASS] Download completed by $($Method.Name)."
            $Downloaded = $true
            #----Extract archive if file extension ends in .zip
            if ($Destination -like "*.zip") {
                Write-Host "[INFO] Extracting $Destination."
                Expand-Archive -LiteralPath $Destination -DestinationPath (Split-Path -Path $Destination -Parent) -Force
                Write-Host "[PASS] Extraction complete."
            }
            break
        } catch {
            Write-Host "[FAIL] Failed to download by $($Method.Name). $($_.Exception.Message)"
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
                    Write-Host "[INFO] Creating directory at $Path."
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
                Remove-Item -Path $Path -Recurse -Force -EA Stop
                Write-Host "[PASS] Directory deleted."
            } catch {
                Write-Host "[FAIL] Failed to remove directory. $($_.Exception.Message)"
            }
        }
    }
}

#endregion -----------------------------------------------------------------------------------------------------------------	

#region EXECUTIONS ---------------------------------------------------------------------------------------------------------

try {
    Write-Host "[INFO] Preparing environment."
    if (!(Test-Path $Path)) { Set-Dir -Path $Path -Create }
    Write-Host "[INFO] Downloading package."
    if (!(Test-Path $PathZip)) { Get-File -URL $URL -Destination $PathZip }
} catch { Write-Host "[FAIL] $($_.Exception.Message)" ; throw }

Install-eMAR
if ($Global:Attempted) { Set-Dir -Path $Path -Remove }

#endregion -----------------------------------------------------------------------------------------------------------------
