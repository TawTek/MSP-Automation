<#
.SYNOPSIS
    Move endpoints to correct location in Ninja via API based on Public IP using imported CSV with list of all locations
    with their Public IPs.

.DESCRIPTION
    This script retrieves an authorization token, fetches detailed device information from Ninja, and imports a CSV file 
    containing Public IPs and their corresponding locations. It compares each device's public IP with the CSV import.
    
    Requirements:
    - The CSV being imported must be named: `ninjapublicips.csv`. (edit script if different name)
    - The CSV should be located in the specified directory (Dir).
    - Must contain the columns: `PublicIP`, `OrgID`, `Location`, `LocationID`.
    - Make sure regional URL is set correctly in $NinjaURL
    - 'client_id' & 'client_secret' must be set in Get-NinjaToken function, created fst in 

    Executions:
    1. Retrieves the authorization token needed for API calls.
    2. Fetches detailed device information for all devices using the API.
    3. Compares each device's public IP with the CSV import with a graphical progress bar:
        - If match found AND LocationID matches, skips.
        - If match found BUT LocationID doesn't match, updates via the -PATCH API call.
        - If match found AND LocationID doesn't match BUT errors during move, adds to $Failed_Array.        
        - If no match found, adds to $Unmatched_Array.
    4. Compiles three lists:
        - Devices successfully moved to the correct location.
        - Devices that did not match any Public IPs in CSV.
        - Devices that encountered errors during the move.
    5. Prints to screen and exports the results to CSV files for further analysis/records.

.PARAMETER Dir
    The directory where the CSV files are located and where the output files will be saved.

.PARAMETER OrgID
    The Organization ID used to filter devices by Ninja Organization. If undefined, all devices will be processed.

.EXAMPLE
    Get-NinjaDevices -Dir 'C:/Temp' -OrgID '000'

.NOTES
    Author : TawTek
    Date   : 2024-11-04
    Version: 1.0
#>

<#--------------------------------------------------------------------------------------------------------------------------
SCRIPT:PARAM_VAR
--------------------------------------------------------------------------------------------------------------------------#>

$NinjaURL = 'https://app.ninjarmm.com'

<#--------------------------------------------------------------------------------------------------------------------------
SCRIPT:FUNCTIONS
--------------------------------------------------------------------------------------------------------------------------#>

function Get-NinjaToken {
    $AuthBody = @{
        'grant_type'    = 'client_credentials'
        'client_id'     = ''
        'client_secret' = ''
        'scope'         = 'monitoring management'
    }
    return @{
        'Authorization' = "Bearer $(Invoke-WebRequest -Uri "$($NinjaURL)/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded' |
                          Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty access_token)"
        'Content-Type'  = 'application/json'
    }
}

function Get-NinjaDevices {

    [CmdletBinding()]
    param(
        [string]$Dir,
        [int]$OrgID
    )
    
    $CsvLocations    = @()
    $Devices_Array   = @()
    $Failed_Array    = @()
    $Unmatched_Array = @()
    $Count_Matched   = 0
    $Count_Unmatched = 0

    Write-Host "INFO: Importing locations with Public IPs from $Dir/NinjaPublicIPs.csv"

    if (Test-Path "$Dir/ninjapublicips.csv") {
        $CsvLocations = Import-Csv -Path "$Dir/ninjapublicips.csv" | Where-Object { -not [string]::IsNullOrWhiteSpace($_.PublicIP) }
        # Check for duplicated Public IPs
        $DuplicateIPs = $CsvLocations | Group-Object -Property PublicIP | Where-Object { $_.Count -gt 1 }
        if ($DuplicateIPs) {
            Write-Host "FAIL: Duplicate Public IPs found, edit the CSV file." -ForegroundColor DarkRed
            $DuplicateIPs | ForEach-Object { Write-Host "FAIL: Duplicate Public IP | $($_.Name) | x$($_.Count)" -ForegroundColor DarkRed }
            exit
        }
    } else {
        Write-Host "FAIL: $Dir/NinjaPublicIPs.csv not found." -ForegroundColor DarkRed
        exit
    }

    Write-Host "INFO: Calling API to fetch Ninja devices with details."

    $NinjaOneDevices = Invoke-RestMethod -Uri "$($NinjaURL)/v2/devices-detailed" -Method GET -Headers (Get-NinjaToken)
    $NinjaEndpoints  = if ($OrgID) { $NinjaOneDevices | Where-Object { $_.organizationid -eq $OrgID } } else { $NinjaOneDevices }
    
    Write-Host "INFO: Matching Public IPs from Ninja to CSV imported Public IPs."

    foreach ($Ninja in $NinjaEndpoints) {
        $MatchedLocations = $CsvLocations | Where-Object { $_.PublicIP -eq $Ninja.publicIP }
        if (!$MatchedLocations) {
            $Unmatched_Array += [PSCustomObject]@{
                Device       = $Ninja.systemName
                Org          = ($CsvLocations | Where-Object { $_.OrgID -eq $Ninja.organizationId } | Select-Object -First 1).Org
                Old_Location = ($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId }).Location
                PublicIP     = $Ninja.publicIP
            }
            $Count_Unmatched++
            continue
        }
        foreach ($Matched in $MatchedLocations) {
         $Count_Matched++
         $PercentComplete = [math]::Round(($Count_Matched/($NinjaEndpoints.Count - $Count_Unmatched)) * 100)
         Write-Progress -Activity "Comparing Public IP to Location..." `
            -Status "$Count_Matched/$($NinjaEndpoints.Count - $Count_Unmatched) | $PercentComplete% Complete | $($Ninja.systemName)" `
            -PercentComplete $PercentComplete
             if ($Ninja.LocationID -ne $Matched.LocationID) {
                $Body = @{'locationId' = $Matched.LocationID} | ConvertTo-Json
                try {
                    Invoke-RestMethod -Uri "$($NinjaURL)/v2/device/$($Ninja.id)" -Method PATCH -Headers (Get-NinjaToken) -Body $Body
                    $Devices_Array += [PSCustomObject]@{
                        Device       = $Ninja.systemName
                        Org          = ($CsvLocations | Where-Object { $_.OrgID -eq $Ninja.organizationId } | Select-Object -First 1).Org
                        Old_Location = ($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId }).Location
                        New_Location = $Matched.Location
                        PublicIP     = $Ninja.publicIP
                    }
                } catch {
                    $Failed_Array += [PSCustomObject]@{
                        Device          = $Ninja.systemName
                        Org             = ($CsvLocations | Where-Object { $_.OrgID -eq $Ninja.organizationId } | Select-Object -First 1).Org
                        Old_Location    = ($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId }).Location
                        Failed_Location = $Matched.Location
                        PublicIP        = $Ninja.publicIP
                        Error           = $_.Exception.Message
                    }
                }
            }
        }
    }

    Write-Progress -Activity "Comparing Public IP to Location..." -Completed
    
    if ($Devices_Array.Count -gt 0) {
        $Devices_Array | Sort-Object Org, Location | Format-Table -AutoSize
        $Devices_Array | Sort-Object Org, Location | Export-Csv -Path "$Dir/movedendpoints.csv" -NoTypeInformation
        Write-Host "PASS: Devices moved to the correct location based on Public IP and exported to $Dir/movedendpoints.csv" -ForegroundColor DarkGreen
    } 
    if ($Unmatched_Array.Count -gt 0) { 
        $Unmatched_Array | Sort-Object Org, Device | Format-Table -AutoSize
        $Unmatched_Array | Sort-Object Org, Location | Export-Csv -Path "$Dir/unmatchedendpoints.csv" -NoTypeInformation
        Write-Host "WARN: Devices with unmatched Public IPs are displayed above and exported to $Dir/unmatchedendpoints.csv." -ForegroundColor DarkYellow
    }
    if ($Failed_Array.Count -gt 0) {
        $Failed_Array | Sort-Object Org, Device | Format-Table -AutoSize
        $Failed_Array | Sort-Object Org, Location | Export-Csv -Path "$Dir/failedendpoints.csv" -NoTypeInformation
        Write-Host "FAIL: Devices with failures are displayed above and exported to $Dir/failedendpoints.csv." -ForegroundColor DarkRed
    } 
    if ($Devices_Array.Count -eq 0 -and $Unmatched_Array.Count -eq 0 -and $Failed_Array.Count -eq 0) {
        Write-Host "INFO: No devices found in wrong locations via Public IP comparison." -ForegroundColor DarkCyan
    }
}

<#--------------------------------------------------------------------------------------------------------------------------
SCRIPT:EXECUTIONS
--------------------------------------------------------------------------------------------------------------------------#>

# Get-NinjaDevices -Dir 'C:/Temp' -OrgID '000'