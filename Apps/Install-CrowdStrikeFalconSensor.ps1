<#
.SYNOPSIS
    Install CrowdStrike
.DESCRIPTION
    Copies installer file from fileserver or remote URL and attempts installation, returns error upon failure
.NOTES
    AUTHOR : TawTek
    CREATED: 2024-09-29
#>

<#--------------------------------------------------------------------------------------------------------------------------
SCRIPT:PARAM_VAR
--------------------------------------------------------------------------------------------------------------------------#>

param(
    [string]$UNC,
    [string]$URL,
    [string]$ID
)

#-Variables [Global]
$VerbosePreference = "Continue"
$EA_Silent         = @{ErrorAction = "SilentlyContinue"}
$EA_Stop           = @{ErrorAction = "Stop"}
$TempDir           = "C:\Temp\CrowdStrike"

#-Variables [App]
$App     = "CrowdStrike Falcon"
$EXE     = "$TempDir\CSFalconSensor.exe"
$Arg     = "/install /quiet CID=$ID"
$Service = "CSFalconService"

<#--------------------------------------------------------------------------------------------------------------------------
SCRIPT:FUNCTIONS
--------------------------------------------------------------------------------------------------------------------------#>

#--Checks if $Service exists
function Test-Service {
    if ($script:InstallAttempted) {
        if (Get-Service $Service @EA_Silent) {
            Write-Verbose "$App has been installed."
        } else {
            Write-Verbose "$App has not been installed, please attempt manual installation."
            exitv
        }
    } elseif (Get-Service $Service @EA_Silent) {
        Write-Verbose "$App is already installed, terminating script"
        exit
    }
}

#--Creates temporary directory
function Set-TempDir {
    if (Test-Path -Path $TempDir) {
        Write-Verbose "$TempDir exists."
    } else {
        Write-Verbose "Creating $TempDir."
        New-Item -Path $TempDir -ItemType "Directory" > $null
        Write-Verbose "$TempDir created."
    }
}

#--Checks if installer exists, downloads if not
function Get-App {
    if (Test-Path -Path $EXE) {
        Write-Verbose "$App installer exists, skipping download."
    } else {
        Write-Verbose "Downloading installer."
        Get-File -URL $URL -UNC $UNC -Destination $EXE
    }
}

#--Installs app
function Install-App {
    Write-Verbose "Installing $App."
    Start-Process -FilePath $EXE -ArgumentList $Arg -wait
    $script:InstallAttempted = $true
}

#--Removes temporary directory
function Remove-TempDir {
    Write-Verbose "Deleting temporary directory."
    Remove-Item $TempDir -recurse -force
    Write-Verbose "Temporary directory has been deleted."
}

<#--------------------------------------------------------------------------------------------------------------------------
SCRIPT:ANCILLARY_FUNCTIONS
--------------------------------------------------------------------------------------------------------------------------#>

function Get-File {
    param (
        [string]$UNC,
        [string]$URL,
        [string]$Destination
    )

    #---Set array for download methods
    $DownloadMethods = @(
        @{ Name = "copying from UNC Path"; Action = { Copy-Item -Path $UNC -Destination $Destination -Force @EA_Stop }},
        @{ Name = "Invoke-WebRequest"; Action = { Invoke-WebRequest -Uri $URL -OutFile $Destination @EA_Stop }},
        @{ Name = "Start-BitsTransfer"; Action = { Start-BitsTransfer -Source $URL -Destination $Destination @EA_Stop }},
        @{ Name = "WebClient"; Action = { (New-Object System.Net.WebClient).DownloadFile($URL, $Destination) }}
    )

    #---Security Protocols
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12 -bor `
        [Net.SecurityProtocolType]::Tls11 -bor `
        [Net.SecurityProtocolType]::Tls -bor `
        [Net.SecurityProtocolType]::Ssl3

    #---Loop through each download method
    foreach ($Method in $DownloadMethods) {
        try {
            Write-Verbose "Attempting to download by $($Method.Name)."
            & $Method.Action
            Write-Verbose "Download completed by $($Method.Name)."
            $Downloaded = $true
            #----Extract archive if file extension ends in .zip
            if ($Destination -like "*.zip") {
                Write-Verbose "Extracting $Destination."
                Expand-Archive -LiteralPath $Destination -DestinationPath $TempDir -Force @EA_Stop
                Write-Verbose "Extraction complete."
            }
            break
        } catch {
            Write-Host "ERROR: Failed to download by $($Method.Name). $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    #---Terminate script if all $DownloadMethods fail
    if (-not $Downloaded) {
        throw "ERROR: All download methods failed, terminating script."
    }
}

<#--------------------------------------------------------------------------------------------------------------------------
SCRIPT:EXECUTIONS
--------------------------------------------------------------------------------------------------------------------------#>

Test-Service
Set-TempDir
Get-App
Install-App
Test-Service
Remove-TempDir