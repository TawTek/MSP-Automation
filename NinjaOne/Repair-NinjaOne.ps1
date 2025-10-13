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
    $ErrorActionPreference = 'SilentlyContinue'
    Write-Progress -Activity "Running Ninja Removal Script" -PercentComplete 0

    #Set-PSDebug -Trace 2
    if([system.environment]::Is64BitOperatingSystem){
        $ninjaPreSoftKey = 'HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC'
        $uninstallKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        $exetomsiKey = 'HKLM:\SOFTWARE\WOW6432Node\EXEMSI.COM\MSI Wrapper\Installed'
    } else {
        $ninjaPreSoftKey = 'HKLM:\SOFTWARE\NinjaRMM LLC'
        $uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        $exetomsiKey = 'HKLM:\SOFTWARE\EXEMSI.COM\MSI Wrapper\Installed'
    }

    $ninjaSoftKey = Join-Path $ninjaPreSoftKey -ChildPath 'NinjaRMMAgent'
    $ninjaDir = [string]::Empty
    $ninjaDataDir = Join-Path -Path $env:ProgramData -ChildPath "NinjaRMMAgent"

    #Locate Ninja
    $ninjaDirRegLocation = $(Get-ItemPropertyValue $ninjaSoftKey -Name Location) 
    if($ninjaDirRegLocation){
        if(Join-Path -Path $ninjaDirRegLocation -ChildPath "NinjaRMMAgent.exe" | Test-Path){
            #location confirmed from registry location
            $ninjaDir = $ninjaDirRegLocation
        }
    }

    Write-Progress -Activity "Running Ninja Removal Script" -PercentComplete 10

    if(!$ninjaDir){
        #attempt to get the path from service
        $ss = Get-WmiObject win32_service -Filter 'Name Like "NinjaRMMAgent"'
        if($ss){
            $ninjaDirService = ($(Get-WmiObject win32_service -Filter 'Name Like "NinjaRMMAgent"').PathName | Split-Path).Replace("`"", "")
            if(Join-Path -Path $ninjaDirService -ChildPath "NinjaRMMAgentPatcher.exe" | Test-Path){
                #location confirmed from service location
                $ninjaDir = $ninjaDirService
            }
        }
    }
    if($ninjaDir){
        $ninjaDir.Replace('/','\')
    }
    if($Uninstall){
        Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Uninstall" -PercentComplete 25
        #there are few measures agent takes to prevent accidental uninstllation
        #disable those measures now
        #it automatically takes care if those measures are already removed
        #it is not possible to check those measures outside of the agent since agent's development comes parralel to this script
        Start "$ninjaDir\NinjaRMMAgent.exe" -disableUninstallPrevention NOUI
        # Executes uninstall.exe in Ninja install directory
        $Arguments = @(
            "/uninstall"
            $(Get-WmiObject -Class win32_product -Filter "Name='NinjaRMMAgent'").IdentifyingNumber
            "/quiet"
            "/log"
            "NinjaRMMAgent_uninstall.log"
            "/L*v"
            "WRAPPED_ARGUMENTS=`"--mode unattended`""
        )
        Start-Process -FilePath "msiexec.exe"  -Verb RunAs -Wait -NoNewWindow -WhatIf -ArgumentList $Arguments
        Write-Progress -Activity "Running Ninja Removal Script" -Status "Uninstall Completed" -PercentComplete 40
        sleep 1
    }

    if($Cleanup){
        Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Cleanup" -PercentComplete 50
        $service=Get-Service "NinjaRMMAgent"
        if($service){
            Stop-Service $service -Force
            & sc.exe DELETE NinjaRMMAgent
            #Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NinjaRMMAgent
        }
        $proxyservice=Get-Process "NinjaRMMProxyProcess64"
        if($proxyservice){
            Stop-Process $proxyservice -Force
        }
        $nmsservice=Get-Service "nmsmanager"
        if($nmsservice){
            Stop-Service $nmsservice -Force
            & sc.exe DELETE nmsmanager
        }
        # Delete Ninja install directory and all contents
        if(Test-Path $ninjaDir){
            & cmd.exe /c rd /s /q $ninjaDir
        }
        if(Test-Path $ninjaDataDir){
            & cmd.exe /c rd /s /q $ninjaDataDir
        }

        #Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent
        Remove-Item -Path  -Recurse -Force

        # Will search registry locations for NinjaRMMAgent value and delete parent key
        # Search $uninstallKey
        $keys = Get-ChildItem $uninstallKey | Get-ItemProperty -name 'DisplayName'
        foreach ($key in $keys) {
            if ($key.'DisplayName' -eq 'NinjaRMMAgent'){
                Remove-Item $key.PSPath -Recurse -Force
                }
            }

        #Search $installerKey
        $keys = Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' | Get-ItemProperty -name 'ProductName'
        foreach ($key in $keys) {
            if ($key.'ProductName' -eq 'NinjaRMMAgent'){
                Remove-Item $key.PSPath -Recurse -Force
            }
        }
        # Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\A0313090625DD2B4F824C1EAE0958B08\InstallProperties
        $keys = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
        foreach ($key in $keys) {
            $kn = $key.Name -replace 'HKEY_LOCAL_MACHINE' , 'HKLM:'; 
            $k1 = Join-Path $kn -ChildPath 'InstallProperties';
            if( $(Get-ItemProperty -Path $k1 -Name DisplayName).DisplayName -eq 'NinjaRMMAgent'){
                $toremove = 
                Get-Item -LiteralPath $kn | Remove-Item -Recurse -Force
            }
        }

        #Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\EXEMSI.COM\MSI Wrapper\Installed\NinjaRMMAgent 5.3.3681
        Get-ChildItem $exetomsiKey | Where-Object -Property Name -CLike '*NinjaRMMAgent*'  | Remove-Item -Recurse -Force

        #HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC
        Get-Item -Path $ninjaPreSoftKey | Remove-Item -Recurse -Force

        # agent creates this key by mistake but we delete it here
        Get-Item -Path "HKLM:\SOFTWARE\WOW6432Node\WOW6432Node\NinjaRMM LLC" | Remove-Item -Recurse -Force
        
        Write-Progress -Activity "Running Ninja Removal Script" -Status "Cleanup Completed" -PercentComplete 75
        sleep 1
    }

    if(Get-Item -Path $ninjaPreSoftKey){
        echo "Failed to remove NinjaRMMAgent reg keys ", $ninjaPreSoftKey
    }
    if(Get-Service "NinjaRMMAgent"){
        echo "Failed to remove NinjaRMMAgent service"
    }
    if($ninjaDir){
        if(Test-Path $ninjaDir){
            echo "Failed to remove NinjaRMMAgent program folder"
            if(Join-Path -Path $ninjaDir -ChildPath "NinjaRMMAgent.exe" | Test-Path){
                echo "Failed to remove NinjaRMMAgent.exe"
            }
            if(Join-Path -Path $ninjaDir -ChildPath "NinjaRMMAgentPatcher.exe" | Test-Path){
                echo "Failed to remove NinjaRMMAgentPatcher.exe"
            }
        }
    }

    Write-Progress -Activity "Running Ninja Removal Script" -Status "Completed" -PercentComplete 100
    sleep 1
    $error | out-file C:\Windows\Temp\NinjaRemovalScriptError.txt
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
    if (Get-Service $ServiceName_NinjaOne -ErrorAction SilentlyContinue) {
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
        Start-BitsTransfer -Source $DownloadApp -Destination $TempFilePath -ErrorAction Stop
    } else {
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        Invoke-WebRequest -Uri $DownloadApp -UseBasicParsing -OutFile $TempFilePath -ErrorAction Stop
    }
    Write-Verbose "$App has finished downloading."
    Write-Verbose "Installing $App."
}

###---Checks if service exists after attempted install---###
function Confirm-AppInstall {
    Start-Process -FilePath $TempFilePath -ArgumentList $Arg -wait
    if (Get-Service $ServiceName_NinjaOne -ErrorAction SilentlyContinue) {
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
