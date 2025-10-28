<#
.SYNOPSIS
    Deploys, removes, or cleans up NinjaRMM agent with comprehensive logging and error handling.

.DESCRIPTION
    ===EXECUTION WORKFLOW:===
    
    [PHASE - BOOTSTRAP]
    1. Environment Preparation
       - Creates C:\Temp directory if missing
       - Initializes logging system $LogFile
       - Captures system information (OS, memory, disk space, PowerShell version)
       - Downloads installer
       - Validates MSI file exists before proceeding

    [PHASE - UNINSTALLATION]
    2. Agent Removal (GUID-based priority)
       - Scans registry for existing NinjaRMM installation GUID
       - Uses msiexec /x with GUID for clean uninstall
       - Falls back to file-based uninstall if GUID not found
       - Applies silent uninstall parameters (/qn, /norestart)

    [PHASE - INSTALLATION] 
    3. Agent Deployment
       - Executes msiexec /i with TOKENID parameter for authentication
       - Uses silent installation mode (/qn) with verbose logging (/L*V)
       - Monitors installation process and validates exit codes

    [PHASE - CLEANUP]
    4. Comprehensive Removal (when -Cleanup specified)
       - Stops and removes NinjaRMMAgent and nmsmanager services
       - Terminates NinjaRMMProxyProcess64 if running
       - Deletes installation directories and program data
       - Removes registry entries across multiple hives
       - Verifies complete removal of all components

    ===ARCHITECTURE===
    - Pipeline-enabled design using ValueFromPipelineByPropertyName
    - Dynamic log path generation (Log_AppName-Action.log)  
    - Multi-method download system with automatic fallback
    - 32/64-bit architecture detection for registry operations
    - MSI/EXE installer support with extensible framework

    ===ERROR HANDLING===
    - Comprehensive try/catch blocks throughout execution
    - Exit code validation with specific failure messages
    - Multiple uninstall methods for reliable removal
    - Download retry logic with method fallback

.PARAMETER Action
    Required. Specifies deployment action: 'install' or 'uninstall'

.PARAMETER TokenID  
    Required for installation. Authentication token provided by NinjaRMM platform.

.PARAMETER Cleanup
    Optional switch. Performs deep cleanup of all NinjaRMM components including registry.

.LINK
    https://ninjarmm.zendesk.com/hc/en-us/articles/36038775278349-Custom-Script-NinjaOne-Agent-Removal-Windows

.NOTES
    Developer: TawTek
    Created  : 2023-01-01
    Updated  : 2025-10-28
    Version  : 10.5
    
    [Reference]
    > https://ninjarmm.zendesk.com/hc/en-us/articles/36038775278349-Custom-Script-NinjaOne-Agent-Removal-Windows
    > https://ninjarmm.zendesk.com/hc/en-us/community/posts/33499433890573-Reinstall-or-Migrate-NinjaOne-Agent
    - Base scripts referenced that have been enhanced with:
        * Dynamic GUID detection, pipeline support, multi-method downloads
        * Comprehensive logging, parameterization, edge case error handling
#>

#region ═════════════════════════════════════════ { VARIABLE.GLOBAL } ═════════════════════════════════════════════════

$DirTemp = 'C:\Temp'; if (-not (Test-Path $DirTemp)) { New-Item -Path $DirTemp -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path -Path $DirTemp -ChildPath 'Log_DeployNinja.log'

#region ───────────────────────────────────────────── [ VAR.App ] ─────────────────────────────────────────────────────

$NinjaRMM = {
    param($Action, $TokenID)
    $Installer = Join-Path -Path $DirTemp -ChildPath 'NinjaOneAgent-x86.msi'
    
    # Use RegKeyArch for consistent architecture handling
    $RegKeyArch = if ([System.Environment]::Is64BitOperatingSystem) { 'WOW6432Node' } else { '' }

    [PSCustomObject]@{
        # Core Identification
        Name    = 'NinjaRMMAgent'
        Action  = $Action
        Vendor  = 'NinjaRMM LLC'
        
        # App Installer Properties
        Path       = $Installer
        Service    = 'NinjaRMMAgent'
        URL        = 'https://app.ninjarmm.com/ws/api/v2/generic-installer/NinjaOneAgent-x86.msi'
        
        # MSI arguments
        MsiInstall = @(
            "/i", "`"$Installer`"", "TOKENID=`"{{TokenID}}`"", "/qn", "/L*V", "`"{{LogPath}}`""
        )
        MsiUninstall = @(
            "/uninstall", "`"$Installer`"", "/quiet", "/norestart", "/L*V", "`"{{LogPath}}`"", 
            "WRAPPED_ARGUMENTS=`"--mode unattended`""
        )
        
        # Directory Discovery
        DiscoveryExeName = "NinjaRMMAgent.exe"
        
        # Cleanup Properties
        CleanupServices    = @('NinjaRMMAgent', 'nmsmanager')
        CleanupProcesses   = @('NinjaRMMProxyProcess64')
        CleanupDirectories = @("$env:ProgramData\NinjaRMMAgent")
        
        # Direct registry paths to remove (using RegKeyArch)
        DirectRegistryPaths = @(
            "HKLM:\SOFTWARE\$RegKeyArch\NinjaRMM LLC",
            "HKLM:\SOFTWARE\$RegKeyArch\NinjaRMM LLC\NinjaRMMAgent",
            "HKLM:\SOFTWARE\WOW6432Node\WOW6432Node\NinjaRMM LLC" # Mistaken key
        )
        
        # Consolidated registry search patterns (using RegKeyArch)
        RegistrySearchPatterns = @(
            # Uninstall key search
            @{
                Path = "HKLM:\SOFTWARE\$RegKeyArch\Microsoft\Windows\CurrentVersion\Uninstall"
                SearchType = 'PropertyValue'
                Property = 'DisplayName'
                ExpectedValue = 'NinjaRMMAgent'
            },
            # Installer Products search  
            @{
                Path = "HKLM:\SOFTWARE\$RegKeyArch\Classes\Installer\Products"
                SearchType = 'PropertyValue'
                Property = 'ProductName'
                ExpectedValue = 'NinjaRMMAgent'
            },
            # Installer UserData search (with subkey) - this one doesn't use RegKeyArch
            @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
                SearchType = 'PropertyValue'
                Property = 'DisplayName'
                ExpectedValue = 'NinjaRMMAgent'
                SubKey = 'InstallProperties'
            },
            # EXE to MSI wrapper search (pattern-based)
            @{
                Path = "HKLM:\SOFTWARE\$RegKeyArch\EXEMSI.COM\MSI Wrapper\Installed"
                SearchType = 'NamePattern'
                Pattern = '*NinjaRMMAgent*'
            }
        )
    }
}

#endregion ────────────────────────────────────────────────────────────────────────────────────────────────────────────

#endregion ════════════════════════════════════════════════════════════════════════════════════════════════════════════


#region ══════════════════════════════════════════ { FUNCTION.MAIN } ══════════════════════════════════════════════════

function Invoke-AppInstaller {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$Name,
        [Parameter(ValueFromPipelineByPropertyName)][string]$Path,
        [Parameter(ValueFromPipelineByPropertyName)][array]$MsiInstall,
        [Parameter(ValueFromPipelineByPropertyName)][array]$MsiUninstall,
        [Parameter(ValueFromPipelineByPropertyName)][array]$ExeInstall,
        [Parameter(ValueFromPipelineByPropertyName)][array]$ExeUninstall,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$Action
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
                                @("/quiet", "/norestart". "/log", "`"$LogPath`"")
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

function Remove-ApplicationComponents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$CleanupServices = @(),

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$CleanupProcesses = @(),

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$CleanupDirectories = @(),

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$DirectRegistryPaths = @(),

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$RegistrySearchPatterns = @()
    )

    process {
        # Create result objects for each component type
        $ServicesResult = [PSCustomObject]@{
            Removed = @()
            NotFound = @()
            Failed = @()
        }

        $ProcessesResult = [PSCustomObject]@{
            Removed = @()
            NotFound = @()
            Failed = @()
        }

        $DirectoriesResult = [PSCustomObject]@{
            Removed = @()
            NotFound = @()
            Failed = @()
        }

        $RegistryResult = [PSCustomObject]@{
            Removed = @()
            NotFound = @()
            Failed = @()
            NoKeysFound = @()
        }

        Write-Log -Info "Attempting to remove leftover services, processes, directories, and registry keys."

        # Process services (REMOVED individual logging)
        foreach ($ServiceName in $CleanupServices) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($Service) {
                try {
                    Stop-Service $Service -Force -ErrorAction SilentlyContinue
                    & sc.exe DELETE $ServiceName 2>$null
                    $ServicesResult.Removed += $ServiceName
                } catch {
                    $ServicesResult.Failed += $ServiceName
                }
            } else {
                $ServicesResult.NotFound += $ServiceName
            }
        }

        # Process processes (REMOVED individual logging)
        foreach ($ProcessName in $CleanupProcesses) {
            $Process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
            if ($Process) {
                try {
                    Stop-Process $Process -Force -ErrorAction SilentlyContinue
                    $ProcessesResult.Removed += $ProcessName
                } catch {
                    $ProcessesResult.Failed += $ProcessName
                }
            } else {
                $ProcessesResult.NotFound += $ProcessName
            }
        }
        
        # Process directories (REMOVED individual logging)
        foreach ($Directory in $CleanupDirectories) {
            if ($Directory -and (Test-Path $Directory)) {
                try {
                    & cmd.exe /c "rd /s /q `"$Directory`"" 2>$null
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

        # REGISTRY CLEANUP (REMOVED individual logging)
        # 1. Direct registry paths
        foreach ($regPath in $DirectRegistryPaths) {
            if ($regPath -and (Test-Path $regPath)) {
                try {
                    Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                    $RegistryResult.Removed += $regPath
                } catch {
                    $RegistryResult.Failed += $regPath
                }
            } else {
                $RegistryResult.NotFound += $regPath
            }
        }

        # 2. Consolidated registry search patterns
        foreach ($search in $RegistrySearchPatterns) {
            if (-not $search.Path) {
                continue
            }

            if (-not (Test-Path $search.Path)) {
                $RegistryResult.NoKeysFound += $search.Path
                continue
            }
            
            $foundCount = 0
            switch ($search.SearchType) {
                'NamePattern' {
                    $foundKeys = Get-ChildItem $search.Path -ErrorAction SilentlyContinue | 
                                Where-Object -Property Name -CLike $search.Pattern
                    foreach ($key in $foundKeys) {
                        try {
                            Remove-Item -LiteralPath $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                            $RegistryResult.Removed += "$($search.Path):$($key.PSChildName)"
                            $foundCount++
                        } catch {
                            $RegistryResult.Failed += "$($search.Path):$($key.PSChildName)"
                        }
                    }
                }
                'PropertyValue' {
                    $childKeys = Get-ChildItem $search.Path -ErrorAction SilentlyContinue
                    foreach ($key in $childKeys) {
                        $checkPath = $key.PSPath
                        if ($search.SubKey) {
                            $checkPath = Join-Path $key.PSPath $search.SubKey
                        }
                        
                        if (Test-Path $checkPath) {
                            $propValue = (Get-ItemProperty -Path $checkPath -Name $search.Property -ErrorAction SilentlyContinue).$($search.Property)
                            if ($propValue -eq $search.ExpectedValue) {
                                try {
                                    Remove-Item -LiteralPath $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                                    $RegistryResult.Removed += "$($search.Path):$($key.PSChildName)"
                                    $foundCount++
                                } catch {
                                    $RegistryResult.Failed += "$($search.Path):$($key.PSChildName)"
                                }
                            }
                        }
                    }
                }
            }
            
            if ($foundCount -eq 0) {
                $RegistryResult.NoKeysFound += $search.Path
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
            Write-Host (($data | Sort-Object Status -Descending | Format-Table -AutoSize | Out-String).Trim() + "`n")
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
            Write-Host (($data | Sort-Object Status -Descending | Format-Table -AutoSize | Out-String).Trim() + "`n")
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
            Write-Host (($data | Sort-Object Status -Descending | Format-Table -AutoSize | Out-String).Trim() + "`n")
        }

        # Registry summary
        $properties = @('Removed', 'NotFound', 'Failed', 'NoKeysFound')
        $data = foreach ($property in $properties) {
            foreach ($item in $RegistryResult.$property) {
                [PSCustomObject]@{ Status = $property; Path = $item }
            }
        }
        if ($data) { 
            Write-Log -Info "Registry Status`n"
            Write-Host (($data | Sort-Object Status -Descending | Format-Table -AutoSize | Out-String).Trim())
        }
    }
}

#endregion ════════════════════════════════════════════════════════════════════════════════════════════════════════════


#region ═══════════════════════════════════════ { FUNCTION.ANCILLARY } ════════════════════════════════════════════════

function Get-ApplicationDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$ApplicationObject
    )

    process {
        # Use DirectRegistryPaths from the object for discovery
        if ($ApplicationObject.DirectRegistryPaths) {
            $RegistryKeys = $ApplicationObject.DirectRegistryPaths
            Write-Log -Info "Querying installation directory using DirectRegistryPaths for $($ApplicationObject.Name)."
        } else {
            # Fallback to generic discovery if DirectRegistryPaths doesn't exist
            $RegKeyArch = if ([System.Environment]::Is64BitOperatingSystem) { 'WOW6432Node' } else { '' }
            $RegistryKeys = @(
                "HKLM:\SOFTWARE\$RegKeyArch\$($ApplicationObject.Vendor)\$($ApplicationObject.Name)",
                "HKLM:\SOFTWARE\$RegKeyArch\Microsoft\Windows\CurrentVersion\Uninstall\$($ApplicationObject.Name)",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($ApplicationObject.Name)"
            )
            Write-Log -Info "Querying installation direcotry using generic registry paths for $($ApplicationObject.Name)."
        }

        foreach ($RegKey in $RegistryKeys) {
            if (Test-Path $RegKey) {
                Write-Log -Info "Checking: $RegKey"
                
                $LocationProperties = @('InstallLocation', 'Location', 'InstallDir', 'Path', 'BaseDir')
                
                foreach ($Property in $LocationProperties) {
                    try {
                        $RegValue = Get-ItemPropertyValue -Path $RegKey -Name $Property -EA SilentlyContinue
                        if ($RegValue -and (Test-Path (Join-Path $RegValue $ApplicationObject.DiscoveryExeName))) {
                            $CleanPath = $RegValue.Replace('/', '\').TrimEnd('\')
                            Write-Log -Pass "Found directory via registry ($Property)."
                            Write-Log -Pass "$CleanPath"
                            return $CleanPath
                        }
                    } catch {
                        # Continue to next property
                    }
                }
            }
        }

        # Service-based discovery
        if ($ApplicationObject.Service) {
            Write-Log -Info "Attempting service-based discovery: $($ApplicationObject.Service)"
            $Service = Get-CimInstance -ClassName Win32_Service -Filter "Name LIKE '$($ApplicationObject.Service)%'" |
                       Select-Object -First 1
            if ($Service -and $Service.PathName) {
                $ServicePath = $Service.PathName -replace '^"([^"]+)".*$', '$1'
                $ServiceDir = Split-Path $ServicePath -Parent
                if (Test-Path (Join-Path $ServiceDir $ApplicationObject.DiscoveryExeName)) {
                    $CleanPath = $ServiceDir.Replace('/', '\')
                    Write-Log -Pass "Found directory via service."
                    Write-Log -Pass "$CleanPath"
                    return $CleanPath
                }
            }
        }

        Write-Log -Info "Unable to locate installation directory for $($ApplicationObject.Name)"
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
        [Parameter(ValueFromPipelineByPropertyName)][string]$URL,
        [Parameter(ValueFromPipelineByPropertyName)][string]$Path,
        [Parameter(ValueFromPipelineByPropertyName)][string]$UNC
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

    [LOGIC]
    1. Check if both $Create and $Remove switches are not declared, if so, throw an error.
    2. Create or delete the directory based on the switches and whether the directory exists.
    3. Throw an error if the directory cannot be created or deleted.
    #>

    param (
        [string]$Path,
        [switch]$Create,
        [switch]$Remove
    )

    if (-not $Create.IsPresent -and -not $Remove.IsPresent) {
        Write-Log -Fail "Must declare -Create or -Remove switch with Set-Dir function." 
        exit 1
    }

    switch ($true) {
        { $Create.IsPresent } {
            if (-not (Test-Path -Path $Path)) {
                try {
                    Write-Log -Info "Creating directory at $Path."
                    New-Item -Path $Path -ItemType "Directory" | Out-Null
                    Write-Log -Pass "Created directory at $Path."
                } catch {
                    Write-Log -Fail "Failed to create directory. $($_.Exception.Message)"
                }
            } else {
                Write-Log -Info "Directory exists at $Path"
            }
        }
        { $Remove.IsPresent } {
            try {
                Write-Log -Info "Deleting directory at $Path."
                Remove-Item -Path $Path -Recurse -Force -EA Stop
                Write-Log -Pass "Directory deleted at $Path."
            } catch {
                Write-Log -Fail "Failed to remove directory. $($_.Exception.Message)"
            }
        }
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = "Info")][switch]$Info,
        [Parameter(ParameterSetName = "Pass")][switch]$Pass,
        [Parameter(ParameterSetName = "Warn")][switch]$Warn,
        [Parameter(ParameterSetName = "Fail")][switch]$Fail,
        [Parameter(ParameterSetName = "Header")][switch]$Header,
        [Parameter(ParameterSetName = "HeaderEnd")][switch]$HeaderEnd,
        [Parameter(ParameterSetName = "SystemInfo")][switch]$SystemInfo,
        [Parameter(Position = 0, ParameterSetName = "Info")]
        [Parameter(Position = 0, ParameterSetName = "Pass")]
        [Parameter(Position = 0, ParameterSetName = "Warn")] 
        [Parameter(Position = 0, ParameterSetName = "Fail")]
        [Parameter(Position = 0, ParameterSetName = "Header")]
        [string]$Message,
        [string]$LogPath    = $LogFile,
        [string]$Decoration = "-",
        [int]$HeaderWidth   = 120
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


#region ════════════════════════════════════════ { SCRIPT.EXECUTION } ═════════════════════════════════════════════════

$DeployConfig = @{
    Name     = 'NinjaRMM'
    TokenID  = ''
    Action   = @('Initialize', 'Uninstall', 'Cleanup', 'Install')
    LogFile  = $LogFile
}

Write-Log -SystemInfo

foreach ($Action in $DeployConfig.Action) {
    Write-Log -Header $Action.ToUpper()
    switch ($Action) {
        'Initialize' {
            if (Test-Path $DirTemp) { Write-Log -Pass "Temporary directory initialized." }
            else { Write-Log -Fail "Temporary directory initialization failed, terminating script." ; exit 1 }
            Write-Log -Info "Writing logs to $($DeployConfig.LogFile)"
            # Create the app config once
            try { $NinjaApp = & $NinjaRMM -Action 'Initialize' ; Write-Log -Pass "$($DeployConfig.Name) PSCustomObject initialized." } catch { Write-Log -Fail "Could not initilize object, terminating script." ; exit 1 }
            # If Cleanup is in the actions, discover and add the program folder
            if ('Cleanup' -in $DeployConfig.Action) {
                $DiscoveredDir = $NinjaApp | Get-ApplicationDirectory
                if ($DiscoveredDir -and ($DiscoveredDir -notin $NinjaApp.CleanupDirectories)) {
                    $NinjaApp.CleanupDirectories += $DiscoveredDir
                }
            }
            Write-Log -Info "Downloading $($DeployConfig.Name) installer."
            Get-File -URL $NinjaApp.URL -Path $NinjaApp.Path
        }
        'Uninstall' {
            if ($DiscoveredDir -and (Test-Path (Join-Path $DiscoveredDir "NinjaRMMAgent.exe"))) {
                Write-Log -Info "Disabling uninstall prevention."
                try {
                    Start-Process -FilePath (Join-Path $DiscoveredDir "NinjaRMMAgent.exe") -ArgumentList "-disableUninstallPrevention NOUI" -Wait -EA SilentlyContinue
                    Write-Log -Pass "Uninstall prevention disabled."
                    Start-Sleep -Seconds 2
                } catch {
                    Write-Log -Warn "Could not disable uninstall prevention: $($_.Exception.Message)"
                }
            }
            $NinjaApp | Invoke-AppInstaller -Action 'uninstall'
        }
        'Cleanup' {
            $NinjaApp | Remove-ApplicationComponents
        }
        'Install' {
            # Modify the existing object for installation
            $NinjaApp.MsiInstall = $NinjaApp.MsiInstall | ForEach-Object { 
                $_ -replace "{{TokenID}}", $DeployConfig.TokenID 
            }
            $NinjaApp | Invoke-AppInstaller -Action 'install'
        }
    }
    Write-Log -HeaderEnd
}

#endregion ════════════════════════════════════════════════════════════════════════════════════════════════════════════