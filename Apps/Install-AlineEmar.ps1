<#
.SYNOPSIS
    Automates the deployment of the Aline eMAR application suite and its dependencies.

.DESCRIPTION
    This script performs a fully automated/unattended installation of the Aline eMAR suite including all prerequisite
    drivers and supporting applications with comprehensive error handling and detailed logging.

    EXECUTION WORKFLOW:
    1. ENVIRONMENT PREPARATION:
       - Creates temporary working directory for installation files
       - Downloads the complete installation package (ZIP archive) from specified URL
       - Extracts package contents preserving directory structure
       - Creates persistent log directory when -KeepLog parameter is specified

    2. REGISTRY CONFIGURATION:
       - Imports essential registry settings (accuflo6x.reg) required for eMAR environment
       
    3. COMPONENT INSTALLATION SEQUENCE:
       The script installs components in this specific order to ensure dependencies are met:
       a) Microsoft ODBC Driver for SQL Server (prerequisite for database connectivity)
       b) Microsoft SQL Command Line Utilities (required for database operations)
       c) Core eMAR Applications (installed sequentially via pipeline processing):
          - ACCUflo (main medication management application)
          - ACCUDrug (drug database and reference)
          - ACCULogin (authentication and user management)
          - ACCUsummary (reporting and analytics)
          - ACCUSync (data synchronization service)
          - ACCUfloUpdaterClient (automatic update mechanism)

    4. INSTALLATION METHODOLOGY:
       - MSI Installers: Uses msiexec.exe with quiet mode (/qn) and verbose logging (/l*v)
       - EXE Installers: Handles wrapper executables that contain embedded MSI packages
         using /v"MSI_ARGS" syntax to pass through installation parameters
       - Pipeline-enabled Install-App function processes application objects directly
       - Each installation generates detailed log files with automatic path generation

    5. ERROR HANDLING & LOGGING:
       - Comprehensive try/catch blocks throughout execution flow
       - Individual log files for each application installation (Log_ApplicationName.log)
       - Exit code validation for all installation processes with specific error messages
       - Clear success/failure messaging with log file references for troubleshooting
       - Optional log preservation: When -KeepLog switch is used, logs are copied to 
         SystemDrive\Logs directory before temporary directory cleanup

    6. CLEANUP OPERATIONS:
       - Automatic removal of temporary installation directory upon successful completion
       - Conditional log preservation based on -KeepLog parameter

.PARAMETER Path
Root installation directory where temporary files are stored during installation.

.PARAMETER PathZip
Full path to the downloaded ZIP package.

.PARAMETER URL
Download source URL for the eMAR installation package.

.PARAMETER KeepLog
Optional switch to preserve installation log files by copying to SystemDrive\Logs directory before cleanup.

.NOTES
    Developer  : Tawhid Chowdhury [Proactive Services Manager]
    Contributor: Eugene Saladaga [NOC Engineer]
    Created    : 2025-08-19
    Updated    : 2025-08-26
    Version    : 10.0
#>

#region PARAM_VAR ----------------------------------------------------------------------------------------------------------

param (
    [string]$Path    = "C:\Temp\eMAR",
    [string]$PathZip = "$Path\Aline_eMAR_6.12.11.zip",
    [string]$URL     = "https://transfer.hostmyit.com/ninja/EL/Aline_eMAR_v6.12.11.zip",
    [switch]$KeepLog
)

$Apps = @( 
    [PSCustomObject]@{
        Name = "ODBC Driver"
        Path = "$Path\msodbcsql_*.msi"
        EXE  = @()
        MSI  = @(
            "/qn"
            "IACCEPTMSODBCSQLLICENSETERMS=YES"
            "ADDLOCAL=ALL"
        )
    },
    [PSCustomObject]@{
        Name = "SQLCMD Utilities"
        Path = "$Path\MsSqlCmdLnUtils*.msi"
        EXE  = @()
        MSI  = @(
            "/qn"
            "IACCEPTMSSQLCMDLNUTILSLICENSETERMS=YES"
        )
    },
    [PSCustomObject]@{
        Name = "ACCUflo"
        Path = "$Path\Accuflo_Setup_x64_*.exe"
        EXE  = @("/s")
        MSI  = @(
            "/qn"
            "CS_SERVICE_PASSWORD_IS_VALID=1"
            "REGISTRY_ACCUSYNC_HOSTNAME=https://accusync-a.creativestrategiesus.com"
            "REGISTRY_AUTH_TOKEN=/"
            "ADDLOCAL=ACCUTask,Reports,Maintenance,ACCUflo,eMARWebAPI,Database,ACCUfloCache,ACCUfloConfig,ACCUfloConfigx64Reg,AccuTaskx64Reg,AccufloCachex64Reg,Accuflox64Reg,Common,Commonx64Reg,Databasex64Reg"
        )
    },
    [PSCustomObject]@{
        Name = "ACCUDrug"
        Path = "$Path\ACCUDrug_Setup_x64_*.exe"
        EXE  = @("/clone_wait", "/s")
        MSI  = @("/qn")
    },
    [PSCustomObject]@{
        Name = "ACCULogin"
        Path = "$Path\ACCULogin_Setup_x64_*.exe"
        EXE  = @("/clone_wait", "/s")
        MSI  = @("/qn")
    },
    [PSCustomObject]@{
        Name = "ACCUsummary"
        Path = "$Path\ACCUsummary_Setup_x64_*.exe"
        EXE  = @("/clone_wait", "/s")
        MSI  = @("/qn")
    },
    [PSCustomObject]@{
        Name = "ACCUSync"
        Path = "$Path\ACCUSync_Setup_x64_*.exe"
        EXE  = @("/clone_wait", "/s")
        MSI  = @("/qn")
    },
    [PSCustomObject]@{
        Name = "ACCUfloUpdaterClient"
        Path = "$Path\UpdaterClient_Setup_x64_*.exe"
        EXE  = @("/clone_wait", "/s")
        MSI  = @("/qn")
    }
)

#endregion -----------------------------------------------------------------------------------------------------------------

#region FUNCTIONS ----------------------------------------------------------------------------------------------------------

function Get-File {

    #region LOGIC -----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Downloads a file from a specified URL/UNC path and saves it to a specified destination.

    [PARAMETERS]
    - $UNC        : If declared, copy the file from a UNC path.
    - $URL        : The URL of the file to download.
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

function Install-App {

    #region LOGIC -----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Installs an application from a specified installer (MSI or EXE), validates required arguments,
    and logs the installation process.

    [PARAMETERS]
    - $Name   : The name of the application to install.
    - $Path   : The path to the installer file.
    - $EXE    : Arguments specific to EXE installers.
    - $MSI    : Arguments specific to MSI installers.
    - $LogPath: Automatically generated log file path for the installation.

    [LOGIC]
    1. Validates installer path and ensures the file exists.
    2. Checks the file extension to determine if the installer is MSI or EXE.
    3. Validates that required arguments ($EXE or $MSI) are provided for the given installer type.
    4. Builds the appropriate argument list for the installer:
        - MSI: Creates an array of arguments and appends logging.
        - EXE: Uses EXE arguments, and if MSI arguments are provided, combines them with /v"..." syntax.
    5. Launches the installation using Start-Process and waits for completion.
    6. Evaluates the exit code to determine success or failure:
        - 0 = Success
        - Any other code = Failure, error is thrown with log reference.
    7. Catches and logs any exceptions during installation.
    #>
    #endregion -------------------------------------------------------------------------------------------------------------

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)][string]$Name,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)][string]$Path,
        [Parameter(ValueFromPipelineByPropertyName)][string[]]$EXE,
        [Parameter(ValueFromPipelineByPropertyName)][string[]]$MSI
    )

    process {
        $Installer = (Get-ChildItem -Path $Path | Select-Object -First 1 -ExpandProperty FullName)
        $LogPath   = Join-Path -Path (Split-Path -Path $Installer -Parent) -ChildPath "Log_$Name.log"

        try {
            Write-Host "[INFO] Installing $Name..."
            switch -Wildcard ($Path) {
                "*.msi" {
                    $ArgList = @("/i", "`"$Installer`"") + $MSI + @("/l*v", "`"$LogPath`"") # Create array for MSI arguments
                    $Process = Start-Process msiexec.exe -ArgumentList $ArgList -Wait -NoNewWindow -PassThru
                }
                "*.exe" {
                    $ArgList = $EXE + " /v`"$($MSI -join ' ') /l*v `"$LogPath`"`"" # Combine EXE and MSI arguments into single string
                    $Process = Start-Process $Installer -ArgumentList $ArgList -Wait -NoNewWindow -PassThru
                }
                default { throw "[FAIL] Unknown installer type for $Name (`$Path`)" }
            }
            if ($null -eq $Process.ExitCode) {
                Write-Host "[WARN] $Name did not return an exit code. Assuming success."
            }
            else {
                switch ($Process.ExitCode) {
                    0       { }
                    default { throw "[FAIL] $Name failed with exit code $($Process.ExitCode). See $LogPath" }
                }
            }
        }
        catch {
            Write-Host "[FAIL] $Name installation failed: $($_.Exception.Message)"
            throw
        }
    }
}

function Set-Dir {

    #region LOGIC -----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Creates or deletes a directory at a specified path.

    [PARAMETERS]
    - $Path  : The path to create or delete the directory at.
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

try { # Prepare environment and download package
    Write-Host "[INFO] Preparing environment."
    if (!(Test-Path $Path)) { Set-Dir -Path $Path -Create }
    Write-Host "[INFO] Downloading package."
    if (!(Test-Path $PathZip)) { Get-File -URL $URL -Destination $PathZip }
    if ($KeepLog) { Set-Dir -Path "$env:SystemDrive\Logs" -Create }
} catch { Write-Host "[FAIL] $($_.Exception.Message)" ; throw }

try { # Execute installation and post install cleanup
    $Apps | Install-App
    if ($KeepLog) { Get-ChildItem "$Path\Log_*.log" | Copy-Item -Destination "$env:SystemDrive\Logs" -Force }
    Set-Dir -Path $Path -Remove
} catch { Write-Host "[FAIL] $($_.Exception.Message)" ; throw }

#endregion -----------------------------------------------------------------------------------------------------------------
