#region ═════════════════════════════════════════════ {VARIABLES} ═════════════════════════════════════════════════════

#region ────────────────────────────────────────────── [VAR.App] ──────────────────────────────────────────────────────

$App = @(
    [PSCustomObject]@{
        Name       = "NinjaRMM"
        Path       = $PathTempFile
        MsiInstall = {
            return @(
                "/i"
                "`"$PathTempFile`""
                "TOKENID=$TokenID"
                "/qn"
                "/L*V"
                "`"$(Join-Path $DirTemp "$Name-$Operation.log")`""
            )
        }
        MsiUninstall = {
            return @(
                "/x"
                if ($GUID) { $GUID } else { "`"$PathTempFile`"" }
                "/qn"
                "/norestart" 
                "/L*V"
                "`"$(Join-Path $DirTemp "$Name-$Operation.log")`""
                "WRAPPED_ARGUMENTS=`"--mode unattended`""
            )
        }
    }
)

#endregion ─────────────────────────────────────────── [VAR.App] ──────────────────────────────────────────────────────

#region ──────────────────────────────────────────── [VAR.Install] ────────────────────────────────────────────────────

$DirTemp      = "C:\Temp\NinjaOne"
$PathTempFile = Join-Path -Path $DirTemp -ChildPath $MSI
$DownloadApp  = "https://app.ninjarmm.com/ws/api/v2/generic-installer/NinjaOneAgent-x86.msi"
$MSI          = "NinjaOneAgent-x86.msi"
#$Service      = “NinjaRMMAgent”
#$TokenID      = $(Ninja-Property-Get ninjaTokenId)

#endregion ───────────────────────────────────────── [VAR.Install] ────────────────────────────────────────────────────

#region ─────────────────────────────────────────── [VAR.Uninstall] ───────────────────────────────────────────────────

if ($Operation -eq "Cleanup") {
    & {
        # Define regkey paths based on system architecture
        $RegKeyArch     = if ([System.Environment]::Is64BitOperatingSystem) { 'WOW6432Node' } else { '' }
        $RegKeySoftware = "HKLM:\SOFTWARE\$RegKeyArch\NinjaRMM LLC\NinjaRMMAgent"
        $RegKeyExeMsi   = "HKLM:\SOFTWARE\$RegKeyArch\EXEMSI.COM\MSI Wrapper\Installed"

        # Define Ninja installation directory
        $DirNinjaData = Join-Path -Path $env:ProgramData -ChildPath "NinjaRMMAgent"

        # Get Ninja directory via registry or fallback to service path
        $DirNinja = & {
            # [Primary] Registry path lookup
            if ($DirNinjaReg = Get-ItemPropertyValue -Path $RegKeySoftware -Name Location | 
                           Where-Object { Test-Path (Join-Path $_ "NinjaRMMAgent.exe") }) {
                return $DirNinjaReg.Replace('/', '\')
            }
            # [Fallback] Service path lookup
            $DirNinjaService = Get-CimInstance -ClassName Win32_Service -Filter 'Name LIKE "NinjaRMMAgent"' |
                               Select-Object -First 1      
            if ($DirNinjaService -and $DirNinjaService.PathName) {
                $DirNinjaServicePath = ($DirNinjaService.PathName | Split-Path).Replace('"', '')
                if (Test-Path (Join-Path $DirNinjaServicePath "NinjaRMMAgent.exe")) {
                    return $DirNinjaServicePath.Replace('/', '\')
                }
            }
        }
    }
}

#endregion ──────────────────────────────────────── [VAR.Uninstall] ───────────────────────────────────────────────────

#endregion ══════════════════════════════════════════ {VARIABLES} ═════════════════════════════════════════════════════


#region ══════════════════════════════════════════ {MAIN.FUNCTIONS} ═══════════════════════════════════════════════════

function Invoke-AppInstaller {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$Name,
        [Parameter(ValueFromPipelineByPropertyName)][string]$Path,
        [Parameter(ValueFromPipelineByPropertyName)][scriptblock]$MsiInstall,
        [Parameter(ValueFromPipelineByPropertyName)][scriptblock]$MsiUninstall,
        [Parameter(ValueFromPipelineByPropertyName)][scriptblock]$ExeInstall,
        [Parameter(ValueFromPipelineByPropertyName)][scriptblock]$ExeUninstall,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet("Install", "Uninstall", "Repair")]
        [string]$Operation
    )

    process {
        try {
            Write-Host "[INFO] Performing $Operation operation for $Name..."

            # Generate log path
            $LogPath = if ($Path -and (Test-Path $Path)) {
                Join-Path -Path (Split-Path -Path $Path -Parent) -ChildPath "$Name-$Operation.log"
            } else {
                Join-Path -Path $env:TEMP -ChildPath "$Name-$Operation.log"
            }

            # Determine installer type and build arguments
            $ArgList = @()
            $ProcessExe = $null

            switch -Wildcard ($Operation) {
                "Install" {
                    if (-not $Path -or -not (Test-Path $Path)) { throw "[FAIL] Installer path not found for $Name" }
                    $Installer = (Get-ChildItem -Path $Path | Select-Object -First 1 -ExpandProperty FullName)
                    switch -Wildcard ($Installer) {
                        "*.msi" {
                            $ProcessExe = "msiexec.exe"
                            $ArgList = if ($MsiInstall) { 
                                (& $MsiInstall) -join " "
                            } else {
                                (@("/i", "`"$Installer`"", "/qn", "/norestart", "/L*V", "`"$LogPath`"")) -join " "
                            }
                        }
                        "*.exe" {
                            $ProcessExe = $Installer
                            $ArgList = if ($ExeInstall) { 
                                & $ExeInstall
                            } else {
                                @("/quiet", "/norestart")
                            }
                        }
                        default { throw "[FAIL] Unknown installer type for $Name" }
                    }
                }
                "Uninstall" {
                    # Try GUID based uninstall first
                    Write-Host "[INFO] Attempting to find GUID for $Name..."
                    $GUID = Get-GUID -App $Name
    
                    switch ($true) {
                        {$GUID} {
                            # GUID based uninstall
                            $ProcessExe = "msiexec.exe"
                            $ArgList    = if ($MsiUninstall) { 
                                (& $MsiUninstall) -join " "
                            } else {
                                (@("/x", $GUID, "/qn", "/norestart", "/L*V", "`"$LogPath`"")) -join " "
                            }
                            Write-Host "[INFO] Found GUID: $GUID"
                            break
                        }
                        {$Path -and (Test-Path $Path)} {
                            # File based uninstall
                            $Installer = (Get-ChildItem -Path $Path | Select-Object -First 1 -ExpandProperty FullName)
                            switch -Wildcard ($Installer) {
                                "*.msi" {
                                    $ProcessExe = "msiexec.exe"
                                    $ArgList    = if ($MsiUninstall) { 
                                        (& $MsiUninstall) -join " "
                                    } else {
                                        (@("/x", "`"$Installer`"", "/qn", "/norestart", "/L*V", "`"$LogPath`"")) -join " "
                                    }
                                }
                                "*.exe" {
                                    $ProcessExe = $Installer
                                    $ArgList    = if ($ExeUninstall) { 
                                        & $ExeUninstall 
                                    } else {
                                        @("/uninstall", "/quiet", "/norestart")
                                    }
                                }
                                default { throw "[FAIL] Unknown uninstaller type for $Name" }
                            }
                        }
                        default {
                            throw "[FAIL] No GUID found and no uninstall file path provided for $Name"
                        }
                    }
                }
            }
            # Execute the process
            Write-Host "[INFO] Executing: $ProcessExe $($ArgList -join ' ')"
            $Process = Start-Process -FilePath $ProcessExe -ArgumentList $ArgList -Wait -NoNewWindow -PassThru

            # Evaluate result
            if ($null -eq $Process.ExitCode) {
                Write-Host "[WARN] $Name $Operation did not return an exit code. Assuming success."
            } else {
                switch ($Process.ExitCode) {
                    0       { Write-Host "[SUCCESS] $Name $Operation completed successfully" }
                    3010    { Write-Host "[SUCCESS] $Name $Operation completed successfully (reboot required)" }
                    default { throw "[FAIL] $Name $Operation failed with exit code $($Process.ExitCode). See $LogPath" }
                }
            }
        }
        catch {
            Write-Host "[FAIL] $Name $Operation failed: $($_.Exception.Message)"
            throw
        }
    }
}

function Clear-NinjaRMM {
     if ($Cleanup) {
        # Stop and remove services
        $servicesToRemove = @("NinjaRMMAgent", "nmsmanager")
        foreach ($ServiceName in $servicesToRemove) {
            $Service = Get-Service -Name $ServiceName -EA SilentlyContinue
            if ($Service) {
                Stop-Service -InputObject $Service -Force
                sc.exe DELETE $ServiceName
            }
        }

        # Stop Ninja Proxy Process
        $ProxyProcess = Get-Process -Name "NinjaRMMProxyProcess64" -EA SilentlyContinue
        if ($ProxyProcess) { Stop-Process -InputObject $ProxyProcess -Force }

        # Remove installation directories
        $DirsToRemove = @($DirNinja, $DirNinjaData)
        foreach ($Dir in $DirsToRemove) {
            if (Test-Path $Dir) {
                Remove-Item -Path $Dir -Recurse -Force -EA SilentlyContinue
            }
        }

        # Remove registry keys
        $RegistryKeys = @(
            $RegKeyUninstall,
            'HKLM:\SOFTWARE\Classes\Installer\Products',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products',
            $RegKeyExeMsi,
            (Split-Path $RegKeySoftware),
            "HKLM:\SOFTWARE\WOW6432Node\WOW6432Node\NinjaRMM LLC"
            )
        
        foreach ($KeyPath in $RegistryKeys) {
            if (Test-Path $KeyPath) {
                # Remove matching child keys when applicable
                Get-ChildItem -Path $KeyPath -EA SilentlyContinue | ForEach-Object {
                    $KeyProps = Get-ItemProperty -Path $_.PSPath -EA SilentlyContinue
                    if ($KeyProps.PSObject.Properties.Name -contains 'DisplayName') {
                        if ($KeyProps.DisplayName -eq 'NinjaRMMAgent') { Remove-Item -LiteralPath $_.PSPath -Recurse -Force }
                    } elseif ($KeyProps.PSObject.Properties.Name -contains 'ProductName') {
                        if ($KeyProps.ProductName -eq 'NinjaRMMAgent') { Remove-Item -LiteralPath $_.PSPath -Recurse -Force }
                    } else {
                        Remove-Item -LiteralPath $_.PSPath -Recurse -Force
                    }
                }
            }
        }
    }

    # Verify removal
    $FailedChecks = @()

    if (Test-Path (Split-Path $RegKeySoftware)) { $FailedChecks += "Failed to remove NinjaRMMAgent registry keys: $((Split-Path $RegKeySoftware))" }
    if (Get-Service -Name "NinjaRMMAgent" -EA SilentlyContinue) { $FailedChecks += "Failed to remove NinjaRMMAgent service" }
    if ($DirNinja -and (Test-Path $DirNinja)) {
        $FailedChecks += "Failed to remove NinjaRMMAgent program folder: $DirNinja"
        if (Test-Path (Join-Path $DirNinja "NinjaRMMAgent.exe")) { $FailedChecks += "Failed to remove NinjaRMMAgent.exe" }
        if (Test-Path (Join-Path $DirNinja "NinjaRMMAgentPatcher.exe")) { $FailedChecks += "Failed to remove NinjaRMMAgentPatcher.exe" }
    }

    foreach ($Check in $FailedChecks) { Write-Host $Check -ForegroundColor Red }

}

#endregion ═══════════════════════════════════════ {MAIN.FUNCTIONS} ═══════════════════════════════════════════════════


#region ════════════════════════════════════════ {ANCILLARY.FUNCTIONS} ════════════════════════════════════════════════

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

#endregion ═════════════════════════════════════ {ANCILLARY.FUNCTIONS} ════════════════════════════════════════════════


#region ═════════════════════════════════════════ {SCRIPT.EXECUTIONS} ═════════════════════════════════════════════════

$App | Invoke-AppInstaller -Operation "Uninstall"

#endregion ══════════════════════════════════════ {SCRIPT.EXECUTIONS} ═════════════════════════════════════════════════