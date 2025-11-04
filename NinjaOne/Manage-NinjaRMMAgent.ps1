<#
.SYNOPSIS
    Deploys, removes, or cleans up NinjaRMM agent with comprehensive logging and error handling.

.DESCRIPTION
    ===EXECUTION WORKFLOW===

    [PHASE 1 - INITIALIZATION]
    1. Environment Setup
       - Creates C:\Temp directory if missing
       - Initializes logging system with timestamped entries
       - Captures system information (OS, memory, disk space, PowerShell version)

    2. Application Configuration
       - Defines NinjaRMM deployment parameters
       - Sets up architecture-aware registry paths (32/64-bit)
       - Configures installer arguments and cleanup targets

    [PHASE 2 - RESOURCE ACQUISITION]
    3. Installer Download
       - Downloads MSI from NinjaRMM CDN using multiple fallback methods
       - Validates file existence before proceeding

    [PHASE 3 - UNINSTALLATION (if defined)]
    4. Agent Removal
       - Scans registry for existing installation GUID
       - Uses msiexec /x with GUID for clean uninstall
       - Falls back to file-based uninstall if GUID not found
       - Disables uninstall prevention before removal

    [PHASE 4 - CLEANUP (if defined)]
    5. Component Removal
       - Stops and removes NinjaRMM services
       - Terminates related processes
       - Deletes installation directories and program data
       - Removes registry entries across multiple locations:
         * Vendor registry keys
         * Uninstall entries
         * Windows Installer product registration
         * EXE to MSI wrapper tracking
       - Detects and reports orphaned registry keys

    [PHASE 5 - INSTALLATION (if defined)]
    6. Agent Deployment
       - Executes msiexec /i with TOKENID parameter
       - Uses silent installation with verbose logging
       - Monitors installation process and validates exit codes

    [PHASE 6 - VALIDATION (if defined)]
    7. Installation Verification
       - Validates service binary path matches expected location
       - Confirms service is running after installation
       - Provides installation success/failure status

    ===WORKFLOW MODES (if defined)===
    - Migration: Complete uninstall, cleanup, and reinstall with new token
    - Reinstallation: Full removal and fresh installation
    - $null: Specify the actions to take in $Config.Action

    ===PROCESS ISOLATION===
    - For migration/reinstallation workflows, script spawns child process
    - Prevents premature script termination during uninstall process
    - Parent process exits while child completes the operation

    ===ARCHITECTURE===
    - Pipeline-enabled design using ValueFromPipelineByPropertyName
    - Dynamic log path generation (Log_AppName-Action.log)
    - Multi-method download system (WebRequest, BITS, WebClient, UNC)
    - 32/64-bit architecture detection for registry operations
    - Modular function design for reusability
    - Dynamic directory discovery

    ===ERROR HANDLING===
    - Comprehensive try/catch blocks throughout execution
    - Exit code validation with specific failure messages
    - Multiple uninstall methods for reliable removal
    - Download retry logic with method fallback
    - Graceful degradation when components not found
    - Orphaned registry key detection and reporting

.PARAMETER Action
    Required. Specifies deployment action: 'Initialize', 'Uninstall', 'Cleanup', 'Install', or 'Validate'

.PARAMETER TokenID
    Required for installation. Site TokenID is found in the NinjaRMM platform.

.NOTES
    Developer: TawTek
    Created  : 2023-01-01
    Updated  : 2025-11-02
    Version  : 12.0

    [Reference]
    > https://ninjarmm.zendesk.com/hc/en-us/articles/36038775278349-Custom-Script-NinjaOne-Agent-Removal-Windows
    > https://ninjarmm.zendesk.com/hc/en-us/community/posts/33499433890573-Reinstall-or-Migrate-NinjaOne-Agent
    - Base scripts referenced that have been enhanced with:
        * Dynamic GUID detection, pipeline support, multi-method downloads
        * Comprehensive logging, parameterization, edge case error handling
        * Process isolation for migration workflows
        * Installation validation and service path verification
#>

#region ══════════════════════════════════════════ { FUNCTION.MAIN } ══════════════════════════════════════════════════

function Invoke-AppInstaller {

    <#
    [SUMMARY]
    Executes application installation or uninstallation.

    [PARAMETERS]
    - $Name        : Required. Name of the application.
    - $Action      : Required. Action to perform ('Install' or 'Uninstall').
    - $Path        : Path to the installer file (MSI or EXE).
    - $MsiInstall  : Array of custom MSI installation arguments.
    - $MsiUninstall: Array of custom MSI uninstallation arguments.
    - $ExeInstall  : Array of custom EXE installation arguments.
    - $ExeUninstall: Array of custom EXE uninstallation arguments.

    [LOGIC]
    1. Dynamic Log Path Generation:
       - Generate log path: Log_AppName-Action.log in installer directory or TEMP.
       - Validate installer file existence before proceeding.

    2. Install Action Processing:
       - MSI: Build msiexec /i arguments with silent flags and verbose logging.
       - EXE: Build silent installation arguments with quiet mode and logging.
       - Use custom argument arrays if provided, with log path templating.

    3. Uninstall Action Processing:
       - Primary Method: Retrieve application GUID via registry search for GUID-based uninstall.
       - Fallback Method: Use provided installer file path for file-based uninstall.
       - MSI: Build msiexec /x arguments with GUID or file path.
       - EXE: Build uninstall arguments with silent flags.
       - Custom argument support with GUID/file path substitution.

    4. Process Execution:
       - Start installer process (msiexec.exe or direct EXE) with built argument list.
       - Wait for process completion with -Wait and -PassThru parameters.
       - Implement 2-second cooldown period after execution.

    5. Exit Code Analysis:
       - Handle null exit codes with success assumption.
       - Interpret standard Windows Installer exit codes.
    #>

    [CmdletBinding()]
    param(
        # App & Action
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Action,

        # Installer file
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Path,

        # MSI arguments
        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$MsiInstall,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$MsiUninstall,

        # EXE arguments
        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$ExeInstall,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$ExeUninstall
    )

    process {
        try {
            Write-Log -Info "Starting $Action task for $Name."

            # Generate log path
            $LogPath = if ($Path -and (Test-Path $Path)) {
                Join-Path -Path (Split-Path -Path $Path -Parent) -ChildPath "Log_$Name-$Action.log"
            } else {
                Join-Path -Path $env:TEMP -ChildPath "Log_$Name-$Action.log"
            }

            # Determine installer type and build arguments
            $ArgList = @()
            $ProcessExe = $null

            switch -Wildcard ($Action) {
                "Install" {
                    if (-not $Path -or -not (Test-Path $Path)) {
                        Write-Log -Fail "Installer path not found for $Name."
                        exit 1
                    }
                    switch -Wildcard ($Path) {
                        "*.msi" {
                            $ProcessExe = "msiexec.exe"
                            $ArgList = if ($MsiInstall) {
                                ($MsiInstall -join " ") -replace "{{LogPath}}", $LogPath
                            } else {
                                (@("/i", "`"$Path`"", "/qn", "/norestart", "/L*V", "`"$LogPath`"")) -join " "
                            }
                        }
                        "*.exe" {
                            $ProcessExe = $Path
                            $ArgList = if ($ExeInstall) {
                                ($ExeInstall -join " ") -replace "{{LogPath}}", $LogPath -split " "
                            } else {
                                @("/quiet", "/norestart", "/log", "`"$LogPath`"")
                            }
                        }
                        default {
                            Write-Log -Fail "Unknown installer type for $Name."
                            exit 1
                        }
                    }
                }
                "Uninstall" {
                    $GUID = Get-GUID -App $Name
                    switch ($true) {
                        {$GUID} {
                            # GUID based uninstall
                            Write-Log -Pass "Found GUID: $GUID"
                            $ProcessExe = "msiexec.exe"
                            $ArgList    = if ($MsiUninstall) {
                                ($MsiUninstall -join " ") -replace "`"[^`"]*\.msi`"", $GUID -replace "{{LogPath}}", $LogPath
                            } else {
                                (@("/x", $GUID, "/qn", "/norestart", "/L*V", "`"$LogPath`"")) -join " "
                            }
                            break
                        }
                        {$Path -and (Test-Path $Path)} {
                            # File based uninstall
                            Write-Log -Info "Using installer: $Path"
                            switch -Wildcard ($Path) {
                                "*.msi" {
                                    $ProcessExe = "msiexec.exe"
                                    $ArgList    = if ($MsiUninstall) {
                                        ($MsiUninstall -join " ") -replace "{{LogPath}}", $LogPath
                                    } else {
                                        (@("/x", "`"$Path`"", "/qn", "/norestart", "/L*V", "`"$LogPath`"")) -join " "
                                    }
                                }
                                "*.exe" {
                                    $ProcessExe = $Path
                                    $ArgList    = if ($ExeUninstall) {
                                        ($ExeUninstall -join " ") -replace "{{LogPath}}", $LogPath -split " "
                                    } else {
                                        @("/uninstall", "/quiet", "/norestart", "/log", "`"$LogPath`"")
                                    }
                                }
                                default {
                                    Write-Log -Fail "Unknown uninstaller type for $Name."
                                    throw "Unknown uninstaller type for $Name."
                                }
                            }
                            break
                        }
                        default {
                            Write-Log -Fail "No GUID found or uninstall file path provided for $Name."
                            exit 1
                        }
                    }
                }
            }

            Write-Log -Info "$ArgList"
            Write-Log -Info "Logfile location: $LogPath"
            Write-Log -Info "Attempting to $Action $Name."
            $Process = Start-Process -FilePath $ProcessExe -ArgumentList $ArgList -Wait -NoNewWindow -PassThru
            Start-Sleep -Seconds 2
            # Evaluate result
            if ($null -eq $Process.ExitCode) {
                Write-Log -Warn "$Name $Action did not return an exit code, assuming success."
            } else {
                switch ($Process.ExitCode) {
                    0      { Write-Log -Pass "$Name $Action completed successfully." }
                    3010   { Write-Log -Pass "$Name $Action completed successfully (reboot required)." }
                    default { Write-Log -Fail "$Name $Action failed with exit code $($Process.ExitCode)." ; exit 1 }
                }
            }
        } catch {
            Write-Log -Fail "$Name $Action failed: $($_.Exception.Message)"
            exit 1
        }
    }
}

function Clear-AppRemnants {

    <#
    [SUMMARY]
    Removes leftover application components including services, processes, directories, and registry entries.

    [PARAMETERS]
    - $Name              : Required. Name of the application being cleaned up.
    - $CleanupServices   : Array of service names to stop and remove.
    - $CleanupProcesses  : Array of process names to terminate.
    - $CleanupDirectories: Array of directory paths to delete.
    - $RegPathExact      : Array of specific registry paths to remove.
    - $RegSearch         : Array of registry search patterns to find and remove keys.

    [LOGIC]
    1. Initialize tracking objects for each cleanup category.
    2. Process services: Stop each service and remove via sc.exe DELETE.
    3. Process processes: Terminate each running process by name.
    4. Process directories: Force delete directories using cmd.exe rd /s /q.
    5. Process registry:
       - Remove exact registry paths specified in $RegPathExact.
       - Search and remove registry keys based on patterns in $RegSearch.
       - Detect orphaned registry keys with missing ProductName property.
    6. Generate comprehensive status reports for each cleanup category.
    7. Report orphaned registry keys that may prevent reinstallation.
    8. Return final success/warning status based on cleanup results.

    [OUTPUT]
    - Detailed status reports showing removed, not found, and failed items.
    - Warnings for orphaned registry keys that require manual attention.
    - Success message if all components removed, warning if some remain.
    #>

    [CmdletBinding()]
    param(
        # App
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name,

        # Service, Process, Directory cleanup
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$CleanupServices = @(),

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$CleanupProcesses = @(),

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$CleanupDirectories = @(),

        # Registry cleanup
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$RegPathExact = @(),

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$RegSearch = @()
    )

    process {
        $ServicesResult = [PSCustomObject]@{
            Removed  = @()
            NotFound = @()
            Failed   = @()
        }

        $ProcessesResult = [PSCustomObject]@{
            Removed  = @()
            NotFound = @()
            Failed   = @()
        }

        $DirectoriesResult = [PSCustomObject]@{
            Removed  = @()
            NotFound = @()
            Failed   = @()
        }

        $RegistryResult = [PSCustomObject]@{
            Removed     = @()
            NotFound    = @()
            Failed      = @()
            NoKeysFound = @()
            Orphaned    = @()
        }

        Write-Log -Info "Attempting to remove leftover services, processes, directories, and registry keys.`n"

        # Process services
        foreach ($ServiceName in $CleanupServices) {
            $Service = Get-Service -Name $ServiceName -EA SilentlyContinue
            if ($Service) {
                try {
                    Stop-Service $Service -Force -EA SilentlyContinue
                    & sc.exe DELETE $ServiceName 2>$null
                    $ServicesResult.Removed += $ServiceName
                } catch {
                    $ServicesResult.Failed += $ServiceName
                }
            } else {
                $ServicesResult.NotFound += $ServiceName
            }
        }

        # Process processes
        foreach ($ProcessName in $CleanupProcesses) {
            $Process = Get-Process -Name $ProcessName -EA SilentlyContinue
            if ($Process) {
                try {
                    Stop-Process $Process -Force -EA SilentlyContinue
                    $ProcessesResult.Removed += $ProcessName
                } catch {
                    $ProcessesResult.Failed += $ProcessName
                }
            } else {
                $ProcessesResult.NotFound += $ProcessName
            }
        }

        # Process directories
        foreach ($Directory in $CleanupDirectories) {
            if ($Directory -and (Test-Path $Directory)) {
                try {
                    # Capture both stdout and stderr
                    $Result = & cmd.exe /c "rd /s /q `"$Directory`"" 2>&1
                    if (Test-Path $Directory) {
                        $DirectoriesResult.Failed += $Directory
                    } else {
                        $DirectoriesResult.Removed += $Directory
                    }
                } catch {
                    $DirectoriesResult.Failed += $Directory
                }
            } else {
                $DirectoriesResult.NotFound += $Directory
            }
        }

       # REGISTRY CLEANUP
        # 1. Direct registry paths
        foreach ($regPath in $RegPathExact) {
            if (-not $regPath) { continue }
            if (Test-Path $regPath) {
                try {
                    Remove-Item -Path $regPath -Recurse -Force -EA SilentlyContinue
                    $RegistryResult.Removed += $regPath
                } catch {
                    $RegistryResult.Failed += $regPath
                }
            } else {
                $RegistryResult.NotFound += $regPath
            }
        }
        # 2. Registry search patterns
        foreach ($search in $RegSearch) {
            if (-not $search.Path) { continue }

            if (-not (Test-Path $search.Path)) {
                $RegistryResult.NoKeysFound += $search.Path
                continue
            }
            $foundKeys = switch ($search.SearchType) {
                'NamePattern' {
                    Get-ChildItem $search.Path -EA SilentlyContinue |
                    Where-Object Name -CLike $search.Pattern
                }
                'PropertyValue' {
                    Get-ChildItem $search.Path -EA SilentlyContinue |
                    Where-Object {
                        $checkPath = $_.PSPath
                        # SPECIAL CASE HANDLED HERE: If SubKey is specified, drill down into subfolder
                        if ($search.SubKey) {
                            $checkPath = Join-Path $_.PSPath $search.SubKey
                        }
                        # Check if the path (or subpath) exists and property matches expected value
                        (Test-Path $checkPath) -and
                        ((Get-ItemProperty -Path $checkPath -Name $search.Property -EA SilentlyContinue).$($search.Property) -like $search.ExpectedValue)
                    }
                }
            }
            foreach ($key in $foundKeys) {
                try {
                    Remove-Item -LiteralPath $key.PSPath -Recurse -Force -EA SilentlyContinue
                    $RegistryResult.Removed += "$($search.Path):$($key.PSChildName)"
                } catch {
                    $RegistryResult.Failed += "$($search.Path):$($key.PSChildName)"
                }
            }
            if ($foundKeys.Count -eq 0) {
                $RegistryResult.NoKeysFound += $search.Path
            }
        }
        # 3. Check for orphaned registry keys with missing ProductName
        $orphanedRegPath = 'HKLM:\Software\Classes\Installer\Products'
        if (Test-Path $orphanedRegPath) {
            $childKeys = Get-ChildItem $orphanedRegPath -EA SilentlyContinue
            foreach ($key in $childKeys) {
                # Skip known Windows Common GUID
                if ($key.Name -match '99E80CA9B0328e74791254777B1F42AE') { continue }

                try {
                    $null = Get-ItemPropertyValue -LiteralPath $key.PSPath -Name 'ProductName' -EA Stop
                } catch {
                    # Key exists but ProductName is missing - potential orphan
                    $RegistryResult.Orphaned += $key.PSPath
                }
            }
        }
        # Services summary
        $properties = @('Removed', 'NotFound', 'Failed')
        $data = foreach ($property in $properties) {
            foreach ($item in $ServicesResult.$property) {
                [PSCustomObject]@{ Status = $property; Name = $item }
            }
        }
        if ($data) {
            Write-Log -Info "Service Status`n"
            Write-Log -View (($data | Sort-Object Status -Descending | Format-Table -AutoSize | Out-String).Trim() + "`n")
        }

        # Processes summary
        $properties = @('Removed', 'NotFound', 'Failed')
        $data = foreach ($property in $properties) {
            foreach ($item in $ProcessesResult.$property) {
                [PSCustomObject]@{ Status = $property; Name = $item }
            }
        }
        if ($data) {
            Write-Log -Info "Process Status`n"
            Write-Log -View (($data | Sort-Object Status -Descending | Format-Table -AutoSize | Out-String).Trim() + "`n")
        }

        # Directories summary
        $properties = @('Removed', 'NotFound', 'Failed')
        $data = foreach ($property in $properties) {
            foreach ($item in $DirectoriesResult.$property) {
                [PSCustomObject]@{ Status = $property; Path = $item }
            }
        }
        if ($data) {
            Write-Log -Info "Directories Status`n"
            Write-Log -View (($data | Sort-Object Status -Descending | Format-Table -AutoSize | Out-String).Trim() + "`n")
        }

        # Registry summary
        $properties = @('Removed', 'NotFound', 'Failed', 'NoKeysFound', 'Orphaned')
        $data = foreach ($property in $properties) {
            foreach ($item in $RegistryResult.$property) {
                [PSCustomObject]@{ Status = $property; Path = $item }
            }
        }
        if ($data) {
            Write-Log -Info "Registry Status`n"
            Write-Log -View (($data | Sort-Object Status -Descending | Format-Table -AutoSize | Out-String).Trim() + "`n")
        }
        if ($RegistryResult.Orphaned.Count -gt 0) {
            Write-Log -Warn "Found orphaned registry keys with missing ProductName property"
            Write-Log -Warn "These may be from corrupt Ninja installations and could prevent reinstallation`n$(
                             $RegistryResult.Orphaned | ForEach-Object { "[RKEY] $_" } -join "`n" )"
        }
        # Final success message if no failures
        $totalFailures = (
            $ServicesResult.Failed.Count +
            $ProcessesResult.Failed.Count +
            $DirectoriesResult.Failed.Count +
            $RegistryResult.Failed.Count +
            $RegistryResult.Orphaned.Count
        )

        if ($totalFailures -eq 0) {
            Write-Log -Pass "All existing components successfully removed."
        } else {
            Write-Log -Warn "Some components could not be removed (see above)."
            if (Test-Path $Directory) { Write-Log -Warn "Folder removal error: $($Result -join '; ')" }
        }
    }
}

#endregion ════════════════════════════════════════════════════════════════════════════════════════════════════════════


#region ═══════════════════════════════════════ { FUNCTION.ANCILLARY } ════════════════════════════════════════════════

function Get-AppDirectory {

    <#
    [SUMMARY]
    Discovers the installation directory of an application.

    [PARAMETERS]
    - $AppObject: Required. PSCustomObject containing application configuration with:
        * Name: Application name
        * Vendor: Application vendor
        * RegPathExact: Array of registry paths to search
        * Service: Service name for service-based discovery
        * AgentExe: Expected executable name for validation

    [LOGIC]
    1. Registry Discovery:
       - Use RegPathExact from AppObject or generate fallback registry paths.
       - Check common installation location properties.
       - Validate discovered path by checking for AgentExe existence.

    2. Service Discovery:
       - Query Win32_Service for the application service.
       - Extract service binary path and get parent directory.
       - Validate directory by checking for AgentExe existence.

    3. Validation:
       - All discovered paths are validated by testing for AgentExe presence.
       - Paths are cleaned (normalized slashes, trimmed trailing backslashes).

    4. Fallback:
       - If no valid directory found, log warning and return $null.

    [OUTPUT]
    - Returns clean, validated installation directory path if found.
    - Returns $null if no valid installation directory discovered.
    - Logs discovery method and success/failure status.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [PSCustomObject]$AppObject
    )

    process {
        # Use RegPathExact from the object for discovery
        if ($AppObject.RegPathExact) {
            $RegistryKeys = $AppObject.RegPathExact
        } else {
            # Fallback to generic discovery if RegPathExact doesn't exist
            $RegKeyArch = if ([System.Environment]::Is64BitOperatingSystem) { 'WOW6432Node' } else { '' }
            $RegistryKeys = @(
                "HKLM:\SOFTWARE\$RegKeyArch\$($AppObject.Vendor)\$($AppObject.Name)",
                "HKLM:\SOFTWARE\$RegKeyArch\Microsoft\Windows\CurrentVersion\Uninstall\$($AppObject.Name)"
            )
        }

        foreach ($RegKey in $RegistryKeys) {
            if (Test-Path $RegKey) {

                $LocationProperties = @('InstallLocation', 'Location', 'InstallDir', 'Path', 'BaseDir')

                foreach ($Property in $LocationProperties) {
                    try {
                        $RegValue = Get-ItemPropertyValue -Path $RegKey -Name $Property -EA SilentlyContinue
                        if ($RegValue -and (Test-Path (Join-Path $RegValue $AppObject.AgentExe))) {
                            $CleanPath = $RegValue.Replace('/', '\').TrimEnd('\')
                            Write-Log -Pass "Found directory via registry ($Property)."
                            return $CleanPath
                        }
                    } catch {}
                }
            }
        }

        # Service-based discovery
        if ($AppObject.Service) {
            $Service = Get-CimInstance -ClassName Win32_Service -Filter "Name LIKE '$($AppObject.Service)%'" |
                       Select-Object -First 1
            if ($Service -and $Service.PathName) {
                $ServicePath = $Service.PathName -replace '^"([^"]+)".*$', '$1'
                $ServiceDir = Split-Path $ServicePath -Parent
                if (Test-Path (Join-Path $ServiceDir $AppObject.AgentExe)) {
                    $CleanPath = $ServiceDir.Replace('/', '\')
                    Write-Log -Pass "Found directory via service."
                    return $CleanPath
                }
            }
        }
        Write-Log -Info "Unable to locate directory for $($AppObject.Name)"
        return $null
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

function Get-GUID {

    <#
    [SUMMARY]
    Retrieves the Windows Installer GUID for an application from registry entries.

    [PARAMETERS]
    - $App: Required. Name of the application to search for.

    [LOGIC]
    1. Registry Path Configuration:
       - Detect system architecture (32/64-bit) for correct registry hive.
       - Define registry paths for uninstall entries and installer user data.

    2. Primary Search Method - Uninstall Registry:
       - Search HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall.
       - Include WOW6432Node path for 32-bit applications on 64-bit systems.
       - Filter for display names containing application name with msiexec uninstall strings.

    3. Secondary Search Method - Installer User Data:
       - Search HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData.
       - Navigate to S-1-5-18 (Local System context) products.
       - Examine InstallProperties subkeys for matching display names.

    4. GUID Extraction:
       - Parse uninstall string using regex pattern for GUID format.
       - Extract the first GUID match in {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} format.
       - Return null if no matching uninstall string found.

    [OUTPUT]
    - Returns application GUID in registry format if found.
    - Returns $null if no GUID can be located for the application.
    #>

    param (
        [string]$App
    )

    # Define registry key paths based on system architecture
    $RegKeyArch      = if ([System.Environment]::Is64BitOperatingSystem) { 'WOW6432Node' } else { '' }
    $RegKeySystem    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    $RegKeyUninstall = "HKLM:\SOFTWARE\$RegKeyArch\Microsoft\Windows\CurrentVersion\Uninstall"

    # Method 1: Try standard uninstall registry path
    $UninstallString = Get-ItemProperty -Path "$RegKeyUninstall\*" -EA SilentlyContinue |
                       Where-Object { $_.DisplayName -like "*$App*" -and $_.UninstallString -match 'msiexec' } |
                       Select-Object -ExpandProperty UninstallString -EA SilentlyContinue | Select-Object -First 1

    # Method 2: If not found, try the system installer registry path
    if (-not $UninstallString) {
        $UninstallString = Get-ChildItem -Path $RegKeySystem -EA SilentlyContinue |
            ForEach-Object {
                $InstallPropsPath = Join-Path $_.PSPath "InstallProperties"
                $Props = Get-ItemProperty -Path $InstallPropsPath -EA SilentlyContinue
                if ($Props.DisplayName -like "*$App*") { $Props.UninstallString }
            } | Select-Object -First 1
    }

    # Extract and return the GUID from the uninstall string if found
    if ($UninstallString) {
        return [regex]::Match($UninstallString, "\{[A-F0-9\-]+\}").Value
    } else {
        return $null
    }
}

function Set-Dir {

    <#
    [SUMMARY]
    Creates or deletes a directory at a specified path.

    [PARAMETERS]
    - $Path  : The path to create or delete the directory at.
    - $Create: If declared, create the directory.
    - $Remove: If declared, delete the directory.
    - $Silent: If declared, suppress all output messages.

    [LOGIC]
    1. Check if both $Create and $Remove switches are not declared, if so, throw an error.
    2. Create or delete the directory based on the switches and whether the directory exists.
    3. Throw an error if the directory cannot be created or deleted.
    #>

    param (
        [string]$Path,
        [switch]$Create,
        [switch]$Remove,
        [switch]$Silent
    )

    if (-not $Create.IsPresent -and -not $Remove.IsPresent) {
        if (-not $Silent) { Write-Host "[FAIL] Must declare -Create or -Remove switch with Set-Dir function." }
        exit 1
    }

    switch ($true) {
        { $Create.IsPresent } {
            if (-not (Test-Path -Path $Path)) {
                try {
                    New-Item -Path $Path -ItemType "Directory" | Out-Null
                    if (-not $Silent) { Write-Log -Pass "Created directory at $Path." }
                } catch {
                    if (-not $Silent) { Write-Log -Fail "Failed to create directory. $($_.Exception.Message)" }
                }
            } else {
                if (-not $Silent) { Write-Log -Info "Directory exists at $Path" }
            }
        }
        { $Remove.IsPresent } {
            try {
                Remove-Item -Path $Path -Recurse -Force -EA Stop
                if (-not $Silent) { Write-Log -Pass "Directory deleted at $Path." }
            } catch {
                if (-not $Silent) { Write-Log -Fail "Failed to remove directory. $($_.Exception.Message)" }
            }
        }
    }
}

function Test-ServicePath {

    <#
    [SUMMARY]
    Validates that a service's actual binary path matches the expected path from application configuration.

    [PARAMETERS]
    - $AppObject: Required. PSCustomObject containing application configuration with:
        * Service: Service name to validate
        * SvcExe: Expected full path to service executable

    [LOGIC]
    1. Service Binary Path Retrieval:
       - Execute 'sc.exe qc' command to query service configuration.
       - Parse BINARY_PATH_NAME field from service control manager output.
       - Extract executable path, removing surrounding quotes if present.

    2. Path Comparison:
       - Compare actual service binary path with expected SvcExe path.
       - Perform exact string comparison between the two paths.

    [OUTPUT]
    - Success log entry when service path matches expected configuration.
    - Warning with path details when mismatch detected.
    - Error logging if service query fails to execute.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [PSCustomObject]$AppObject
    )

    try {
        $ActualPath = (
            & sc.exe qc $($AppObject.Service) |
            Select-String 'BINARY_PATH_NAME\s+:\s+(.+)'
        ).Matches.Groups[1].Value.Trim('"')

        if ($AppObject.SvcExe -eq $ActualPath) {
            Write-Log -Pass "Service path successfully validated."
        } else {
            Write-Log -Warn "Service path mismatch."
            Write-Log -Warn "Expected: $($AppObject.SvcExe)"
            Write-Log -Warn "Found: $ActualPath"
        }
    } catch {
        Write-Log -Warn "Service path validation failed: $($_.Exception.Message)"
    }
}

function Write-Log {

    <#
    [SUMMARY]
    Logging function with multiple output types, colors, and formatting options.

    [PARAMETERS]
    - $Info, $Pass, $Warn, $Fail: Switch parameters for different log levels with colored output.
    - $View: Switch for raw message output without prefixes or coloring.
    - $Header, $HeaderEnd: Switches for section header formatting with decoration.
    - $SystemInfo: Switch for comprehensive system information block.
    - $Message: The log message text (position 0 for most parameter sets).
    - $LogPath: Path to log file (defaults to $LogFile).
    - $Decoration: Character used for header decoration lines (default: "-").
    - $HeaderWidth: Width of header lines in characters (default: 120).

    [LOGIC]
    1. Parameter Set Routing:
       - Use PowerShell parameter sets to handle mutually exclusive log types.
       - SystemInfo: Output pre-formatted system information block with hardware details.
       - Header: Create centered text with decoration characters for section headers.
       - HeaderEnd: Create full-width decoration lines for section endings.
       - View: Use for Format-Table and List to write to log as well as view in console.

    2. Message Formatting:
       - Standard messages: Apply timestamp and type prefix ([INFO], [PASS], etc.).
       - Color coding: White (Info), DarkCyan (Pass), Yellow (Warn), Red (Fail).
       - Header centering: Calculate padding for centered text with dynamic width.

    3. Output Handling:
       - Console: Write colored output appropriate for each log level.
       - File: Write timestamped entries with UTF8 encoding.
       - Error resilience: Continue console output if file writing fails.

    4. System Information:
       - Capture execution context, system specs, and environment details.
       - Include memory, disk space, PowerShell version, and process information.
       - Output as pre-formatted multi-line block with border decoration.

    [OUTPUT]
    - Console: Colored output based on log level with appropriate prefixes.
    - File: Timestamped log entries with consistent formatting.
    - Headers: Centered text with decorative borders for section organization.
    - System Info: Comprehensive environment snapshot for troubleshooting.
    #>

    [CmdletBinding()]
    param(
        # Log type switches
        [Parameter(ParameterSetName = "Info")][switch]$Info,
        [Parameter(ParameterSetName = "Pass")][switch]$Pass,
        [Parameter(ParameterSetName = "Warn")][switch]$Warn,
        [Parameter(ParameterSetName = "Fail")][switch]$Fail,
        [Parameter(ParameterSetName = "View")][switch]$View,
        [Parameter(ParameterSetName = "Header")][switch]$Header,
        [Parameter(ParameterSetName = "HeaderEnd")][switch]$HeaderEnd,
        [Parameter(ParameterSetName = "SystemInfo")][switch]$SystemInfo,

        # Message parameter with multiple parameter sets
        [Parameter(Position = 0, ParameterSetName = "Info")]
        [Parameter(Position = 0, ParameterSetName = "Pass")]
        [Parameter(Position = 0, ParameterSetName = "Warn")]
        [Parameter(Position = 0, ParameterSetName = "Fail")]
        [Parameter(Position = 0, ParameterSetName = "View")]
        [Parameter(Position = 0, ParameterSetName = "Header")]
        [string]$Message,

        # Log configuration
        [string]$LogPath = $LogFile,
        [string]$Decoration = "-",
        [int]$HeaderWidth = 120
    )

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if ($SystemInfo) {
        $SystemInfoContent = @"
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> SYSTEM INFORMATION <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
Execution Time:   $($TimeStamp)
Executed By:      $($env:USERDOMAIN)\$($env:USERNAME)
Host Computer:    $($env:COMPUTERNAME)
PS Version:       $($PSVersionTable.PSVersion)
Process ID:       $PID
C: Drive Free:    $(try { [math]::Round((Get-PSDrive C).Free / 1GB, 2) } catch { "N/A" }) GB
Total Memory:     $(try { [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2) } catch { "N/A" }) GB
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
"@
        Write-Host $SystemInfoContent -ForegroundColor "DarkGray"
        $SystemInfoContent | Out-File -FilePath $LogPath -Encoding UTF8
        return
    }

    if ($Header) {
        $ActualWidth    = $HeaderWidth - 1 # VSCode displays character position, PowerShell counts string length from 0
        $Text           = $Message.Trim()
        $TextWithSpaces = " $Text "
        $TotalPadding   = $ActualWidth - $TextWithSpaces.Length

        # Truncate headers that are too long and add ellipsis
        if ($TotalPadding -lt 0) {
            $Text           = $Text.Substring(0, $ActualWidth - 5) + "..." # -5 accounts for '...' and spacing
            $TextWithSpaces = " $Text "
            $TotalPadding   = $ActualWidth - $TextWithSpaces.Length
        }

        $LeftPadding  = [math]::Floor($TotalPadding / 2)
        $RightPadding = $TotalPadding - $LeftPadding
        $HeaderText = "`r`n$($Decoration * $LeftPadding)$TextWithSpaces$($Decoration * $RightPadding)"

        Write-Host $HeaderText -ForegroundColor "DarkGray"
        $HeaderText | Out-File -FilePath $LogPath -Append -Encoding UTF8
        return
    }

    # Handle HeaderEnd - full line with decoration only
    if ($HeaderEnd) {
        $FullLine = $Decoration * ($HeaderWidth - 1)
        Write-Host $FullLine -ForegroundColor "DarkGray"
        $FullLine | Out-File -FilePath $LogPath -Append -Encoding UTF8
        return
    }

    # Handle Display parameter to write to console and log file without prefix
    if ($View) {
        Write-Host $Message
        try {
            $Message | Out-File -FilePath $LogPath -Append -Encoding UTF8
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
        return
    }

    # Determine log type and formatting for regular messages
    switch ($PSCmdlet.ParameterSetName) {
        "Info" {
            $ConsoleColor = "White"
            $FilePrefix = "[INFO]"
        }
        "Pass" {
            $ConsoleColor = "DarkCyan"
            $FilePrefix = "[PASS]"
        }
        "Warn" {
            $ConsoleColor = "Yellow"
            $FilePrefix = "[WARN]"
        }
        "Fail" {
            $ConsoleColor = "Red"
            $FilePrefix = "[FAIL]"
        }
    }

    $ConsoleOutput = "$FilePrefix $Message"
    $FileOutput    = "$Timestamp $FilePrefix $Message"

    Write-Host $ConsoleOutput -ForegroundColor $ConsoleColor

     try {
        $FileOutput | Out-File -FilePath $LogPath -Append -Encoding UTF8
    } catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

#endregion ════════════════════════════════════════════════════════════════════════════════════════════════════════════


#region ═════════════════════════════════════════ { VARIABLE.GLOBAL } ═════════════════════════════════════════════════

$DirTemp = 'C:\Temp'
$LogFile = Join-Path -Path $DirTemp -ChildPath 'Log_DeployNinja.log'

# Configuration for application deployment
$Config  = @{
    Action           = @()
    Name             = 'NinjaRMM'
    RemoteTool       = $env:remoteTool
    RemoteToolURL    = $env:remoteToolUrl
    RemoteToolBypass = $env:remoteToolBypass
    Workflow         = $env:workflow          # Set to 'Migration', 'Reinstallation', 'Installation', 'Uninstallation', or $null
    TokenID          = $env:tokenId
}

#region ───────────────────────────────────────────── [ VAR.App ] ─────────────────────────────────────────────────────

$NinjaRMM = {
    param($Action)

    $Installer  = Join-Path -Path $DirTemp -ChildPath 'NinjaOneAgent-x86.msi'
    $RegKeyArch = if ([System.Environment]::Is64BitOperatingSystem) { 'WOW6432Node' } else { '' }

    [PSCustomObject]@{
        # App Properties
        Name   = 'NinjaRMMAgent'
        Action = $Action
        Vendor = 'NinjaRMM LLC'

        # Installer Properties
        Path    = $Installer
        Service = 'NinjaRMMAgent'
        URL     = 'https://app.ninjarmm.com/ws/api/v2/generic-installer/NinjaOneAgent-x86.msi'

        # Installer Arguments
        MsiInstall = @(
            "/i",
            "`"$Installer`"",
            $(if ($Config.TokenID) { "TOKENID=`"$($Config.TokenID)`"" }),
            "/qn",
            "/L*V",
            "`"{{LogPath}}`""
        ) | Where-Object { $_ }  # Remove empty TokenID if not present

        MsiUninstall = @(
            "/uninstall",
            "`"$Installer`"",
            "/quiet",
            "/norestart",
            "/L*V",
            "`"{{LogPath}}`"",
            "WRAPPED_ARGUMENTS=`"--mode unattended`""
        )

        # Directory Discovery
        AgentExe = "NinjaRMMAgent.exe" # For finding installation directory
        SvcExe   = "NinjaRMMAgentPatcher.exe" # For service path validation

        # Cleanup Properties
        CleanupServices    = @('NinjaRMMAgent', 'nmsmanager')
        CleanupProcesses   = @('NinjaRMMProxyProcess64', 'lockhart')
        CleanupDirectories = @()

        # Direct registry paths to remove
        RegPathExact = @(
            "HKLM:\SOFTWARE\$RegKeyArch\NinjaRMM LLC\NinjaRMMAgent",
            "HKLM:\SOFTWARE\$RegKeyArch\NinjaRMM LLC",
            "HKLM:\SOFTWARE\WOW6432Node\WOW6432Node\NinjaRMM LLC" # Mistaken key present in some installs
        )

        # Registry cleanup targets - common installation registry locations
        RegSearch = @(
            @{ # Control Panel uninstall registry entry
                Path          = "HKLM:\SOFTWARE\$RegKeyArch\Microsoft\Windows\CurrentVersion\Uninstall"
                SearchType    = 'PropertyValue'
                Property      = 'DisplayName'
                ExpectedValue = 'NinjaRMMAgent'
            },
            @{ # Windows Installer product registration (HKLM)
                Path          = "HKLM:\SOFTWARE\$RegKeyArch\Classes\Installer\Products"
                SearchType    = 'PropertyValue'
                Property      = 'ProductName'
                ExpectedValue = 'NinjaRMMAgent'
            },
            @{ # System-wide installed applications (LOCAL SYSTEM context)
                Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
                SearchType    = 'PropertyValue'
                Property      = 'DisplayName'
                ExpectedValue = 'NinjaRMMAgent'
                SubKey        = 'InstallProperties'
            },
            @{ # EXE to MSI wrapper installation tracking
                Path       = "HKLM:\SOFTWARE\$RegKeyArch\EXEMSI.COM\MSI Wrapper\Installed"
                SearchType = 'NamePattern'
                Pattern    = '*NinjaRMMAgent*'
            }
        )
    }
}

$ScreenConnect = {
    param($Action)

    $Installer  = Join-Path -Path $DirTemp -ChildPath 'ScreenConnectClient.msi'

    [PSCustomObject]@{
        # App Properties
        Name   = 'ScreenConnect'
        Action = $Action

        # Installer Properties
        Path    = $Installer
        Service = 'ScreenConnect Client'
        URL     = $Config.RemoteToolURL

        # Installer Arguments
        MsiInstall = @(
            "/i",
            "`"$Installer`"",
            "/qn",
            "/norestart",
            "ENABLEQUICKLAUNCH=0",
            "ENABLEAUTOUPDATE=0",
            "/L*V",
            "`"{{LogPath}}`""
        ) -join " "
    }
}

#endregion ────────────────────────────────────────────────────────────────────────────────────────────────────────────

#endregion ════════════════════════════════════════════════════════════════════════════════════════════════════════════


#region ════════════════════════════════════════ { SCRIPT.EXECUTION } ═════════════════════════════════════════════════

#region ──────────────────────────────────────── [ SCRIPT.Preflight ] ─────────────────────────────────────────────────

if (-not (Test-Path $DirTemp)) {
    try {
        Set-Dir -Path $DirTemp -Create -Silent
    } catch {
        Write-Host "[FAIL] Could not create temporary directory, terminating script."
        Write-Host "[FAIL] Error: $($_.Exception.Message)"
        exit 1
    }
}

# Lookup table for actions tied to workflow
$WorkflowActions = @{
    Migration      = @('Initialize', 'Uninstall', 'Cleanup', 'Install', 'Validate')
    Reinstallation = @('Initialize', 'Uninstall', 'Cleanup', 'Install', 'Validate')
    Installation   = @('Initialize', 'Install', 'Validate')
    Uninstallation = @('Initialize', 'Uninstall', 'Cleanup')
}

# Dynamically assign actions based on workflow lookup and validate all required parameters
switch ($true) {
    { $Config.Workflow -and -not $WorkflowActions.ContainsKey($Config.Workflow) } {
        Write-Host "[FAIL] Invalid workflow: $($Config.Workflow)"
        exit 1
    }
    { $Config.Workflow -in @('Migration', 'Reinstallation', 'Installation') -and [string]::IsNullOrEmpty($Config.TokenID) } {
        Write-Host "[FAIL] TokenID required for $($Config.Workflow)"
        exit 1
    }
    { -not $Config.Workflow -and $Config.Action.Count -eq 0 } {
        Write-Host '[FAIL] Custom workflow requires actions'
        exit 1
    }
    { $WorkflowActions.ContainsKey($Config.Workflow) } {
        $Config.Action = $WorkflowActions[$Config.Workflow]
    }
}

if (Config.Workflow -eq 'Migration' -or $Config.Workflow -eq 'Reinstallation') {
    if ($Config.RemoteToolBypass -eq 'True') {
        Write-Log -Info 'RemoteToolBypass parameter switch declared, skipping remote tool backup.'
    }
}

if ($Config.RemoteTool -eq 'True') {
    if (-not $Config.RemoteToolURL) {
        Write-Log -Fail 'RemoteToolURL is missing/invalid, must be passed when RemoteTool is set.'
        exit 1
    }
    Write-Log -Header 'BACKUP REMOTE TOOL' -HeaderWidth '100'
    try {
        Write-Log -Info 'RemoteTool parameter switch declared, starting processs.'
        $ScreenConnectApp = & $ScreenConnect -Action 'install'
        Get-File -URL $ScreenConnectApp.URL -Path $ScreenConnectApp.Path
        $ScreenConnectApp | Invoke-AppInstaller
        Write-Log -HeaderEnd -HeaderWidth '100'
    } catch {
        Write-Log -Fail "ScreenConnect installation failed: $($_.Exception.Message)"
        exit 1
    }
}

if (-not $env:IS_CHILD_PROCESS -and $Config.Workflow) {
    Write-Log -Header 'PROCESS ISOLATION CHECK' -HeaderWidth '100'
    Write-Host "[INFO] Starting $($Config.Name) $($Config.Workflow.ToLower()) procedure."
    Write-Host "[INFO] Process isolation required to complete $($Config.Name) $($Config.Workflow.ToLower())."

    # Set environment variable so child process knows it's already a child
    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-Command", "`$env:IS_CHILD_PROCESS='1'; & `"$PSCommandPath`""
    ) -WindowStyle Hidden

    Write-Host "[PASS] $($Config.Name) $($Config.Workflow.ToLower()) handed off to child process, closing parent context."
    Write-Host "[INFO] $($Config.Name) $($Config.Workflow.ToLower()) may take up to 10 minutes to complete."
    Write-Host "[INFO] Refer to logfile for $($Config.Name) $($Config.Workflow.ToLower()) progress and results."
    Write-Host "[INFO] Logfile location: $LogFile"
    Write-Log -HeaderEnd -HeaderWidth '100'
    exit 0
}

Write-Log -SystemInfo
Write-Log -Header 'PREFLIGHT'
Write-Log -Info "$($Config.Name) $($Config.Workflow.ToLower()) is running in protected execution context (PID: $PID)."
Write-Log -Pass "Temporary directory: $DirTemp"
Write-Log -Pass "Logfile location: $LogFile"
Write-Log -HeaderEnd

#endregion ────────────────────────────────────────────────────────────────────────────────────────────────────────────

#region ─────────────────────────────────────────── [ SCRIPT.Main ] ───────────────────────────────────────────────────

foreach ($Action in $Config.Action) {
    Write-Log -Header $Action.ToUpper()
    switch ($Action) {
        'Initialize' {
            # Initialize app object
            try {
                $NinjaApp = & $NinjaRMM -Action 'Initialize'
                Write-Log -Pass "$($Config.Name) PSCustomObject initialized."
            } catch {
                Write-Log -Fail "Could not initilize $($Config.Name) PSCustomObject, terminating script."
                exit 1
            }
            # If 'Cleanup' action is defined, discover program folder dynamically and add to CleanupDirectories
            if ('Cleanup' -in $Config.Action) {
                Write-Log -Info "Locating installation directory."
                $NinjaApp.CleanupDirectories += ($NinjaApp | Get-AppDirectory)
                Write-Log -Pass "$($NinjaApp.CleanupDirectories)"
            }
            Write-Log -Info "Downloading $($Config.Name) installer."
            Get-File -URL $NinjaApp.URL -Path $NinjaApp.Path
        }
        'Uninstall' {
            $NinjaApp | Invoke-AppInstaller -Action 'uninstall'
            Start-Sleep -Seconds 10
        }
        'Cleanup' {
            $NinjaApp | Clear-AppRemnants
        }
        'Install' {
            $NinjaApp | Invoke-AppInstaller -Action 'install'
            Start-Sleep -Seconds 5
        }
        'Validate' {
            # Update SvcExe property to full path and validate service binary
            try {
                $NinjaDir = $NinjaApp | Get-AppDirectory
                $NinjaApp | Add-Member -MemberType NoteProperty -Name 'SvcExe' -Value (Join-Path $NinjaDir $NinjaApp.SvcExe ) -Force
                Write-Log -Pass "Updated $($Config.Name) PSCustomObject's SvcExe property to full path."
                Write-Log -Pass "$($NinjaApp.SvcExe)"
                Test-ServicePath -AppObject $NinjaApp
            } catch {
                Write-Log -Warn "Service path update/validation failed: $($_.Exception.Message)"
                exit 1
            }
            if ((Get-Service $NinjaApp.Service).Status -eq 'Running') {
                Write-Log -Pass "$($NinjaApp.Service) service is running."
            } else {
                Write-Log -Fail"$($NinjaApp.Service) service is not running."
                exit 1
            }
        }
    }
    Write-Log -HeaderEnd
}

#endregion ────────────────────────────────────────────────────────────────────────────────────────────────────────────

#endregion ════════════════════════════════════════════════════════════════════════════════════════════════════════════