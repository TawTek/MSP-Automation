<#
.SYNOPSIS
    Move endpoints to correct location in Ninja via API based on Public IP using imported CSV with list of all locations
    with their Public IPs.

.DESCRIPTION
    This script retrieves an authorization token, fetches detailed device information from Ninja, and imports a CSV file
    containing Public IPs and their corresponding locations. It compares each device's public IP with the CSV import.

    Requirements:
    - The CSV being imported must be named: `NinjaPublicIPs.csv`. (edit script if different name)
    - The CSV should be located in the specified directory (Dir).
    - Must contain the columns: `PublicIP`, `OrgID`, `Location`, `LocationID`.
    - Make sure regional URL is set correctly in $NinjaURL
    - 'client_id' & 'client_secret' must be set in Get-NinjaToken function, create in Ninja > Administration > Apps > API

    Executions:
    1. Retrieves the authorization token needed for API calls.
    2. Fetches detailed device information for all devices using the API.
    3. Compares each device's public IP with the CSV import with a graphical progress bar:
        - If match found AND LocationID matches, skips.
        - If match found BUT LocationID doesn't match, updates via the -PATCH API call.
        - If match found AND LocationID doesn't match BUT errors during move, adds to $Failed_Array.
        - If no match found, moves to $UnknownID location and writes 'Unknown' to Custom Field, adds to $Unmatched_Array
    4. Compiles three lists:
        - Devices successfully moved to the correct location.
        - Devices that did not match any Public IPs in CSV.
        - Devices that encountered errors during the move.
    5. Prints to screen and exports the results to CSV files for further analysis/records.

.PARAMETER Dir
    The directory where the CSV files are located and where the output files will be saved.

.PARAMETER OrgID
    The Organization ID used to filter devices by Ninja Organization. If undefined, all devices will be processed.

.PARAMETER UnknownID
    The Unknown LocationID where devices are moved to if it does not match any of the NinjaPublicIPs.

.EXAMPLE
    Get-NinjaDevices -Dir 'C:/Temp' -OrgID '000' -UnknownID '111'

.NOTES
    Author : Tawhid Chowdhury [Proactive Services Manager]
    Date   : 2024-11-04
    Updated: 2025-01-14
    Version: 5.0
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
        'client_id'     = (Get-Secret -Name 'API_Ninja_ClientID' -Vault 'SecretStore') | ConvertFrom-SecureString -AsPlainText
        'client_secret' = (Get-Secret -Name 'API_Ninja_ClientSecret' -Vault 'SecretStore') | ConvertFrom-SecureString -AsPlainText
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
        [switch]$Test,
        [int]$UnknownID,
        [int]$OrgID
    )

    $CsvLocations    = @()
    $Devices_Array   = @()
    $Failed_Array    = @()
    $Matched_Array   = @()
    $Unmatched_Array = @()
    $Count_Matched   = 0
    $Count_Unmatched = 0

    Write-Host "INFO: Importing locations with Public IPs from $Dir/NinjaPublicIPs.csv"

    if (Test-Path "$Dir/NinjaPublicIPs.csv") {
        $CsvLocations = Import-Csv -Path "$Dir/NinjaPublicIPs.csv" | Where-Object { -not [string]::IsNullOrWhiteSpace($_.PublicIP) }
        # Check for duplicated Public IPs
        $DuplicateIPs = $CsvLocations | Group-Object -Property PublicIP | Where-Object { $_.Count -gt 1 }
        if ($DuplicateIPs) {
            Write-Host 'FAIL: Duplicate Public IPs found, edit the CSV file.' -ForegroundColor DarkRed
            $DuplicateIPs | ForEach-Object { Write-Host "FAIL: Duplicate Public IP | $($_.Name) | x$($_.Count)" -ForegroundColor DarkRed }
            exit
        }
    } else {
        Write-Host "FAIL: $Dir/NinjaPublicIPs.csv not found." -ForegroundColor DarkRed
        exit
    }

    Write-Host 'INFO: Calling API to fetch Ninja devices with details.'

    $NinjaEndpoints = Invoke-RestMethod -Uri "$($NinjaURL)/v2/devices-detailed?df=org%3D$OrgID$(if($Test){'&pageSize='})" -Method GET -Headers (Get-NinjaToken)

    if ($Test) { $NinjaEndpoints | Export-Csv -Path 'C:/temp/NinjaEndpoints.csv' -NoTypeInformation }

    Write-Host 'INFO: Matching Public IPs from Ninja to CSV imported Public IPs.'

    foreach ($Ninja in $NinjaEndpoints) {

        # Check and skip iteration if CF 'CustomLocation' is True in Ninja
        $CustomLocation = (Invoke-RestMethod -Uri "$($NinjaURL)/v2/device/$($Ninja.ID)/custom-fields" -Method GET -Headers (Get-NinjaToken)).CustomLocation
        if ($CustomLocation -eq $True) {
            Write-Host "WARN: Custom Location CF -eq True | SKIP | $(if ($Ninja.displayName) { $Ninja.displayName } else { $Ninja.systemName })" -ForegroundColor DarkYellow
            continue
        }

        # If no match for location via PublicIP, add to array and move to Unknown location in Ninja
        $MatchedLocations = $CsvLocations | Where-Object { $_.PublicIP -eq $Ninja.publicIP }

        if (!$MatchedLocations) {
            $Count_Unmatched++
            $Unmatched_Array += [PSCustomObject]@{
                Device       = if ($Ninja.displayName) { $Ninja.displayName } else { $Ninja.systemName }
                Org          = ($CsvLocations | Where-Object { $_.OrgID -eq $Ninja.organizationId } | Select-Object -First 1).Org
                Old_Location = ($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId } | Select-Object -First 1).Location
                New_Location = ($CsvLocations | Where-Object { $_.LocationID -eq $UnknownID } | Select-Object -First 1).Location
                PrivateIP    = $Ninja.ipAddresses
                PublicIP     = $Ninja.publicIP
            }

            if ($Ninja.locationID -eq $UnknownID) {
                Write-Host "SKIP: $(if ($Ninja.displayName) { $Ninja.displayName } else { $Ninja.systemName }) ≠ PublicIPs | Already in $(($CsvLocations | Where-Object { $_.LocationID -eq $UnknownID } | Select-Object -First 1).Location)."  -ForegroundColor DarkCyan
                continue
            }

            if (!$Test) {
                $Body_LocationID  = @{'locationId' = $UnknownID} | ConvertTo-Json
                $Body_CustomField = @{'CustomLocation' = 'Unknown'} | ConvertTo-Json
                try {
                    Write-Host "WARN: $(if ($Ninja.displayName) { $Ninja.displayName } else { $Ninja.systemName }) ≠ PublicIPs | $(($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId } | Select-Object -First 1).Location) → $(($CsvLocations | Where-Object { $_.LocationID -eq $UnknownID } | Select-Object -First 1).Location)." -ForegroundColor DarkYellow
                    Invoke-RestMethod -Uri "$($NinjaURL)/v2/device/$($Ninja.id)" -Method PATCH -Headers (Get-NinjaToken) -Body $Body_LocationID | Out-Null
                    Invoke-RestMethod -Uri "$($NinjaURL)/v2/device/$($Ninja.id)/custom-fields" -Method PATCH -Headers (Get-NinjaToken) -Body $Body_CustomField | Out-Null
                } catch {
                    $Failed_Array += [PSCustomObject]@{
                        Device          = if ($Ninja.displayName) { $Ninja.displayName } else { $Ninja.systemName }
                        Org             = ($CsvLocations | Where-Object { $_.OrgID -eq $Ninja.organizationId } | Select-Object -First 1).Org
                        Old_Location    = ($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId } | Select-Object -First 1).Location
                        Failed_Location = ($CsvLocations | Where-Object { $_.LocationID -eq $UnknownID } | Select-Object -First 1).Location
                        PrivateIP       = $Ninja.ipAddresses
                        PublicIP        = $Ninja.publicIP
                        Error           = $_.Exception.Message
                    }
                }
                continue
            }
        }

        foreach ($Matched in $MatchedLocations) {
            $Count_Matched++
            $Matched_Array += [PSCustomObject]@{
                Device       = if ($Ninja.displayName) { $Ninja.displayName } else { $Ninja.systemName }
                Org          = ($CsvLocations | Where-Object { $_.OrgID -eq $Ninja.organizationId } | Select-Object -First 1).Org
                Old_Location = ($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId } | Select-Object -First 1).Location
                New_Location = $Matched.Location
                PrivateIP    = $Ninja.ipAddresses
                PublicIP     = $Ninja.publicIP
            }
            $PercentComplete = [math]::Round(($Count_Matched/($NinjaEndpoints.Count - $Count_Unmatched)) * 100)
            Write-Progress -Activity 'Comparing Public IP to Location...' `
                -Status "$Count_Matched/$($NinjaEndpoints.Count - $Count_Unmatched) | $PercentComplete% Complete | $($Ninja.systemName)" `
                -PercentComplete $PercentComplete
            if ($Ninja.LocationID -ne $Matched.LocationID) {
                if (!$Test) {
                    $Body = @{'locationId' = $Matched.LocationID} | ConvertTo-Json
                    try {
                        Write-Host "MOVE: $(if ($Ninja.displayName) { $Ninja.displayName } else { $Ninja.systemName }) | $(($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId } | Select-Object -First 1).Location) → $($Matched.Location)." -ForegroundColor DarkCyan
                        Invoke-RestMethod -Uri "$($NinjaURL)/v2/device/$($Ninja.id)" -Method PATCH -Headers (Get-NinjaToken) -Body $Body | Out-Null
                        $Devices_Array += [PSCustomObject]@{
                            Device       = if ($Ninja.displayName) { $Ninja.displayName } else { $Ninja.systemName }
                            Org          = ($CsvLocations | Where-Object { $_.OrgID -eq $Ninja.organizationId } | Select-Object -First 1).Org
                            Old_Location = ($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId } | Select-Object -First 1).Location
                            New_Location = $Matched.Location
                            PrivateIP    = $Ninja.ipAddresses
                            PublicIP     = $Ninja.publicIP
                        }
                    } catch {
                        $Failed_Array += [PSCustomObject]@{
                            Device          = if ($Ninja.displayName) { $Ninja.displayName } else { $Ninja.systemName }
                            Org             = ($CsvLocations | Where-Object { $_.OrgID -eq $Ninja.organizationId } | Select-Object -First 1).Org
                            Old_Location    = ($CsvLocations | Where-Object { $_.LocationID -eq $Ninja.locationId } | Select-Object -First 1).Location
                            Failed_Location = $Matched.Location
                            PrivateIP       = $Ninja.ipAddresses
                            PublicIP        = $Ninja.publicIP
                            Error           = $_.Exception.Message
                        }
                    }
                }
            }
        }
    }

    Write-Progress -Activity 'Comparing Public IP to Location...' -Completed

    if ($Devices_Array.Count -gt 0) {
        $Devices_Array | ForEach-Object { $_.PrivateIP = $_.PrivateIP -join "," }
        $Devices_Array | Sort-Object Org, Location | Format-Table -AutoSize
        $Devices_Array | Sort-Object Org, Location | Export-Csv -Path "$Dir/movedendpoints.csv" -NoTypeInformation
        Write-Host "PASS: Devices moved to the correct location based on Public IP and exported to $Dir/movedendpoints.csv" -ForegroundColor DarkGreen
    }
    if ($Matched_Array.Count -gt 0) {
        $Matched_Array | ForEach-Object { $_.PrivateIP = $_.PrivateIP -join "," }
        $Matched_Array | Sort-Object Org, Location | Export-Csv -Path "$Dir/matchedlocations.csv" -NoTypeInformation
        Write-Host "PASS: Matched locations exported to $Dir/matchedlocations.csv" -ForegroundColor DarkGreen
    }
    if ($Unmatched_Array.Count -gt 0) {
        $Unmatched_Array | ForEach-Object { $_.PrivateIP = $_.PrivateIP -join "," }
        $Unmatched_Array | Sort-Object Org, Device | Format-Table -AutoSize
        $Unmatched_Array | Sort-Object Org, Location | Export-Csv -Path "$Dir/unmatchedendpoints.csv" -NoTypeInformation
        Write-Host "WARN: Devices with unmatched Public IPs are displayed above and exported to $Dir/unmatchedendpoints.csv." -ForegroundColor DarkYellow
    }
    if ($Failed_Array.Count -gt 0) {
        $Failed_Array | ForEach-Object { $_.PrivateIP = $_.PrivateIP -join "," }
        $Failed_Array | Sort-Object Org, Device | Format-Table -AutoSize
        $Failed_Array | Sort-Object Org, Location | Export-Csv -Path "$Dir/failedendpoints.csv" -NoTypeInformation
        Write-Host "FAIL: Devices with failures are displayed above and exported to $Dir/failedendpoints.csv." -ForegroundColor DarkRed
    }
    if ($Devices_Array.Count -eq 0 -and $Unmatched_Array.Count -eq 0 -and $Failed_Array.Count -eq 0) {
        Write-Host 'INFO: No devices found in wrong locations via Public IP comparison.' -ForegroundColor DarkCyan
    }
}

<#--------------------------------------------------------------------------------------------------------------------------
SCRIPT:EXECUTIONS
--------------------------------------------------------------------------------------------------------------------------#>

Get-NinjaDevices -Dir 'C:\Temp' -OrgID '240' -UnknownID '540' -Test