param (
    [string]$ClientCode
)
$Info = {
**********************************************************************************************************
*  Synopsis: Reinstall NinjaOne
*  Description:

    > Uses parameter to pass $ClientCode
    > Runs Ninjas own script for complete removal
    > Afterwards starts process to reinstall
    > Checks for temporary directory and if missing, creates one in C:\Temp
    > Checks if installer exists, skips if it does
    > Adds regkey to disable IE first run setup (prevents downloads if it was never run before)
    > Checks PowerShell version and executes correct cmdlet for downloading app installer
    > Downloads app installer
    > Runs msi installer with arguments defined
    > Checks if service exists after attempted install
    > Deletes temporary folder after verification that installation is complete

*  Created: 23-06-16 | TawTek
*  Updated: 23-08-29 | TawTek
*  Version: 2.0

*  CHANGELOG:

    > 23-06-16  First iteration of script developed
**********************************************************************************************************
}
$Uninstall = $true
$Cleanup = $true

###################################################################################################
# Remove NinjaOne #
###################################################################################################

function Remove-NinjaRMM {
    Write-Progress -Activity "Running Ninja Removal Script" -PercentComplete 0

    # Define registry key paths based on system architecture
    $RegKeyArch      = if ([System.Environment]::Is64BitOperatingSystem) { 'WOW6432Node' } else { '' }
    $RegKeySoftware  = Join-Path "HKLM:\SOFTWARE\$RegKeyArch\NinjaRMM LLC" "NinjaRMMAgent"
    $RegKeyUninstall = Join-Path "HKLM:\SOFTWARE\$RegKeyArch\Microsoft\Windows\CurrentVersion\Uninstall"
    $RegKeyExeMsi    = Join-Path "HKLM:\SOFTWARE\$RegKeyArch\EXEMSI.COM\MSI Wrapper\Installed"

    $DirNinjaData = Join-Path -Path $env:ProgramData -ChildPath "NinjaRMMAgent"

    # Attempt to locate Ninja directory via registry
    try {
        $DirNinja = Get-ItemPropertyValue -Path $RegKeySoftware -Name Location -EA Stop | Where-Object { Test-Path (Join-Path $_ "NinjaRMMAgent.exe") }
    } catch {
        $DirNinja = $null
    }

    # Attempt to locate Ninja directory via service path if registry check fails
    if (-not $DirNinja) {
        $ServiceNinja = Get-CimInstance -ClassName Win32_Service -Filter 'Name LIKE "NinjaRMMAgent"' | Select-Object -First 1
        if ($ServiceNinja) {
            $ServicePath = ($ServiceNinja.PathName | Split-Path).Replace('"','')
            if (Test-Path (Join-Path $ServicePath "NinjaRMMAgentPatcher.exe")) {
                $DirNinja = $ServicePath
            }
        }
    }

    # Normalize path slashes
    if ($DirNinja) { $DirNinja = $DirNinja.Replace('/', '\') }

    Write-Progress -Activity "Running Ninja Removal Script" -PercentComplete 10
    
    if ($Uninstall) {
        # Disable uninstall prevention measures in the agent
        # Get the MSI product code for NinjaRMMAgent

        Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Uninstall" -PercentComplete 25

        Start-Process -FilePath (Join-Path $DirNinja "NinjaRMMAgent.exe") -ArgumentList "-disableUninstallPrevention NOUI" -NoNewWindow -Wait

        $Arguments = @(
            "/uninstall"
            (Get-CimInstance -ClassName Win32_Product -Filter "Name='NinjaRMMAgent'" | Select-Object -First 1).IdentifyingNumber
            "/quiet"
            "/log"
            "NinjaRMMAgent_uninstall.log"
            "/L*v"
            'WRAPPED_ARGUMENTS="--mode unattended"'
            )

        Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Verb RunAs -Wait -NoNewWindow -WhatIf

        } else {
            Write-Warning "NinjaRMMAgent product not found in MSI database."
        }

        Write-Progress -Activity "Running Ninja Removal Script" -Status "Uninstall Completed" -PercentComplete 40
        Start-Sleep -Seconds 1

    if ($Cleanup) {
        Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Cleanup" -PercentComplete 50

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

        Write-Progress -Activity "Running Ninja Removal Script" -Status "Cleanup Completed" -PercentComplete 75
        Start-Sleep -Seconds 1
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

    Write-Progress -Activity "Running Ninja Removal Script" -Status "Completed" -PercentComplete 100
    Start-Sleep -Seconds 1

    # Export any errors to a file
    $error | Out-File -FilePath "C:\Windows\Temp\NinjaRemovalScriptError.txt"
}

###################################################################################################
# Reinstall NinjaOne #
###################################################################################################

$VerbosePreference = "Continue"
$TempDirectory = "C:\Temp\NinjaOne"
$PowerShellVersion = $PSVersionTable.PSVersion
$App = "NinjaOne"
$DownloadApp = "URL-TO-FILE/$ClientCode-ninjaone.msi"
$TempFileName = "$ClientCode-ninjaone.msi"
$TempFilePath = Join-Path -Path $TempDirectory -ChildPath $TempFileName
$ServiceName_NinjaOne = “NinjaRMMAgent”
$Arg = "/qn /norestart"

###---Checks if service exists---###
function Confirm-Service {
    Write-Verbose "Checking if $ServiceName_NinjaOne exists."
    if (Get-Service $ServiceName_NinjaOne -EA SilentlyContinue) {
        Write-Verbose "$ServiceName_NinjaOne exists, $App is already installed. Terminating script."
        exit
    } else {
        Write-Verbose "$ServiceName_NinjaOne does not exist, continuing script."
    }
}

###---Creates temporary directory---###
function Confirm-TempPath {
    Write-Verbose "Checking if $TempDirectory exists."
    if(Test-Path -Path $TempDirectory) {
        Write-Verbose "$TempDirectory exists."
    } else {
        Write-Verbose "Creating $TempDirectory."
        New-Item -Path $TempDirectory -ItemType "directory" > $null
        Write-Verbose "$TempDirectory created."
    }
}

###---Checks if installer exists---###
function Confirm-Installer {
    Write-Verbose "Checking if $App installer already exists."
    if (Test-Path -LiteralPath $TempFilePath) {
        Write-Verbose "$App installer exists, skipping download"
        Write-Verbose "Installing $App."
        Start-Process -FilePath $TempFilePath -ArgumentList $Arg -wait
    } else {
        Write-Verbose "$App installer does not exist, continuing to download installer."
        Get-NinjaOne
    }
}

###---Downloads and Installs--###
function Get-NinjaOne {
    Write-Verbose "Downloading $App installer to $TempDirectory."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
    if($PowerShellVersion -lt "3.0") {
        Import-Module BitsTransfer
        Start-BitsTransfer -Source $DownloadApp -Destination $TempFilePath -EA Stop
    } else {
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        Invoke-WebRequest -Uri $DownloadApp -UseBasicParsing -OutFile $TempFilePath -EA Stop
    }
    Write-Verbose "$App has finished downloading."
    Write-Verbose "Installing $App."
}

###---Checks if service exists after attempted install---###
function Confirm-AppInstall {
    Start-Process -FilePath $TempFilePath -ArgumentList $Arg -wait
    if (Get-Service $ServiceName_NinjaOne -EA SilentlyContinue) {
        Write-Verbose "$ServiceName_NinjaOne exists, $App has been installed."
        Write-Verbose "Deleting temporary directory folder."
        Remove-Item $TempDirectory -recurse -force
        Write-Verbose "Temporary directory has been deleted."
    } else {
        if (Test-PendingReboot) {
            Write-Verbose "Reboot is required before proceeding with installation. Please reboot then run script again."
        } else {
            Write-Verbose "$App has not been installed due to an error. Please attempt manual installation."
        }
    }
}

###---Ancillary function to check for pending reboots---###
function Test-PendingReboot {
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true}
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true}
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true}
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($status -ne $null) -and $status.RebootPending) {
            return $true
        }
    }
    catch { }
    return $false
}

Confirm-TempPath
Get-NinjaOne
Remove-NinjaRMM
Confirm-Service
Confirm-TempPath
Confirm-Installer
Confirm-AppInstall