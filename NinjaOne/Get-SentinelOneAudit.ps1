<#
.SYNOPSIS
    Performs an audit of missing endpoints in both NinjaOne and SentinelOne platforms.

.DESCRIPTION
    This script automates the comparison of device inventories registered in NinjaOne and SentinelOne platforms.
    
    [EXECUTION WORKFLOW + LOGIC]

    1. AUTHENTICATION & SESSION INITIALIZATION:
       - Retrieves SentinelOne API token using Get-S1Token function
       - Retrieves NinjaOne API token using Get-NinjaToken function
       - Establishes secure session context for both platforms

    2. DATA COLLECTION:
       - Queries SentinelOne for complete device inventory
       - Queries NinjaOne for complete device inventory
       - Normalizes and maps device attributes across both datasets for consistent comparison

    3. COMPARISON LOGIC:
       - Identifies devices present in SentinelOne but missing in NinjaOne
       - Identifies devices present in NinjaOne but missing in SentinelOne
       - Generates consolidated audit report highlighting discrepancies

    4. REPORTING & OUTPUT OPTIONS:
       - Default: Displays results in structured table format directly in the console
       - Optional: When -Output switch is specified:
         - Saves audit results as CSV file
         - Output file named 'Ninja+S1_Audit.csv'
         - Directory location determined by -Dir parameter

.PARAMETER Output
    Switch parameter to export results to CSV file instead of displaying in console. 
    When specified, results are written to the file 'Ninja+S1_Audit.csv' under the directory defined by -Dir.

.PARAMETER Dir
    Specifies the target directory where the CSV output file will be saved when -Output is used.

.NOTES
    Developer  : TawTek
    Created    : 2025-03-27
    Version    : 1.0
#>

#region FUNCTIONS ----------------------------------------------------------------------------------------------------------

function Get-NinjaEndpoints {

    #region LOGIC ----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Retrieves the list of endpoints from NinjaOne for a specified organization ID.

    [PARAMETERS]
    - $OrgID     : The unique identifier of the organization whose endpoints should be retrieved.
    - $URL_Ninja : The base URL for the NinjaOne API (default: 'https://app.ninjarmm.com').

    [LOGIC]
    1. Initialize an empty array to store NinjaOne endpoints in the script scope.
    2. Send a GET request to the NinjaOne API endpoint using the provided OrgID.
    3. If a valid response is returned, append the device data to the $script:Endpoints_Ninja array.
    4. Handle any exceptions by writing a descriptive error message to the console.
    #>
    #endregion -------------------------------------------------------------------------------------------------------------

    param (
        [int]$OrgID,
        [string]$URL_Ninja = 'https://app.ninjarmm.com'
    )
    
    $script:Endpoints_Ninja = @()

    try {
        $Response = Invoke-RestMethod -Uri "$($URL_Ninja)/v2/devices-detailed?df=org%3D$OrgID" -Method GET -Headers (Get-NinjaToken)
        if ($Response) {
            $script:Endpoints_Ninja += $Response
        }
    } catch {
        Write-Error "Error occurred: $_"
    }
}

function Get-S1Endpoints { 

    param (
        [int64]$ResultLimit = 100,
        [int64]$SiteID,
        [string]$URL_S1 = 'https://usea1-ninjaone.sentinelone.net'
    )
    
    $script:Endpoints_S1 = @()
    
    try {
        $Cursor         = $null
        $Remaining      = $true
        $ProcessedCount = 0
        $TotalCount     = 0

        $QueryParams = @{
            "siteIds" = $SiteID
            "limit"   = $ResultLimit
        }
        $QueryString     = ($QueryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
        $InitialResponse = Invoke-RestMethod -Uri "$URL_S1/web/api/v2.1/agents?$QueryString" -Headers (Get-S1Token) -Method Get
        $TotalCount      = $InitialResponse.pagination.totalItems

        while ($Remaining) {

            $QueryParams = @{
                "siteIds" = $SiteID
                "limit"   = $ResultLimit
            }
            
            if ($Cursor) {
                $QueryParams["cursor"] = $Cursor
            }

            $QueryString = ($QueryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
            
            $Response = if (!$Cursor) { $InitialResponse } else {
                Invoke-RestMethod -Uri "$URL_S1/web/api/v2.1/agents?$QueryString" -Headers (Get-S1Token) -Method Get
            }

            if ($Response.data) {
                $script:Endpoints_S1    += $Response.data
                        $ProcessedCount += $Response.data.Count
                $PercentComplete = [math]::Min(($ProcessedCount / $TotalCount) * 100, 100)
                Write-Progress -Activity "Getting S1 Endpoints" -Status "$ProcessedCount/$TotalCount Processed" -PercentComplete $PercentComplete
                $Cursor    = $Response.pagination.nextCursor
                $Remaining = -not [string]::IsNullOrEmpty($Cursor)
            } else {
                $Remaining = $false
            }
        }
        Write-Progress -Activity "Getting S1 Endpoints" -Completed

    } catch {
        Write-Error "Error occurred: $_"
        Write-Error $_.Exception.Response.StatusCode.Value__
        Write-Error $_.Exception.Response.StatusDescription
    }
}

function Compare-Endpoints {

    #region LOGIC ----------------------------------------------------------------------------------------------------------
    <#
    [SUMMARY]
    Compares endpoint inventories between SentinelOne (S1) and NinjaOne platforms to identify discrepancies in device coverage.

    [PARAMETERS]
    - $Output : Switch parameter. If declared, results are exported to CSV instead of displayed in the console.
    - $Dir    : Directory path where the CSV file will be saved when -Output is specified (default: C:\Temp).

    [LOGIC]
    1. VALIDATION:
       - Ensures that when -Output is specified, the -Dir parameter is provided.
       - Throws an error if -Dir is missing while -Output is declared.

    2. INITIALIZATION:
       - Creates empty arrays ($script:Missing_S1 and $script:Missing_Ninja) to track devices missing from each platform.

    3. COMPARISON:
       - For each NinjaOne endpoint:
         a) Checks if corresponding S1 endpoint exists by computerName or DNS short name.
         b) If no match found, checks for IP match in S1.
         c) Adds device to $script:Missing_S1 if no match is found.
       - For each SentinelOne endpoint:
         a) Checks if corresponding NinjaOne endpoint exists by systemName or DNS short name.
         b) If no match found, checks for IP match in NinjaOne.
         c) Adds device to $script:Missing_Ninja if no match is found.

    4. REPORT GENERATION:
       - Builds a collection of custom objects containing the missing endpoint name and the platform it is missing from.
       - Stores results in $Comparison for output.

    5. DISCREPANCY FLAG:
       - Sets $script:Discrepancies to $true if missing devices are found in either platform.
       - Otherwise, sets it to $false.

    6. OUTPUT HANDLING:
       - If -Output is NOT specified:
         * Displays results in console as a formatted table, sorted by platform and endpoint.
       - If -Output IS specified:
         * Exports results to CSV file named 'Ninja+S1_Audit.csv' in the directory defined by -Dir.

    7. STATUS MESSAGING:
       - Displays status messages indicating whether results were displayed in the console or exported to CSV.
    #>
    #endregion -------------------------------------------------------------------------------------------------------------

    param (
        [switch]$Output,
        [string]$Dir = 'C:\Temp'
    )

    if ($Output -and -not $PSBoundParameters.ContainsKey('Dir')) {
        throw "The -Dir parameter is required when using -Output"
    }

    $script:Missing_S1    = @()
    $script:Missing_Ninja = @()


    foreach ($Device in $script:Endpoints_Ninja) {
        if (-not ($script:Endpoints_S1 | Where-Object { $_.computerName -eq $Device.systemName -or $_.computerName -eq ($Device.dnsName -split '\.')[0] })) {
            if (-not ($script:Endpoints_S1 | Where-Object { $_.lastIpToMgmt -contains $Device.ipAddresses })) {
                $script:Missing_S1 += $Device.systemName
            }
        }
    }

    foreach ($Device in $script:Endpoints_S1) {
        if (-not ($script:Endpoints_Ninja | Where-Object { ($_.systemName -eq $Device.computerName) -or (($_.dnsName -split '\.')[0] -eq $Device.computerName) })) {
            if (-not ($script:Endpoints_Ninja | Where-Object { $Device.lastIpToMgmt -contains $_.ipAddresses })) {
                $script:Missing_Ninja += $Device.computerName
            }
        }
    }

    $Comparison = foreach ($Item in @(
        @{ Devices = $script:Missing_Ninja; Platform = 'NinjaOne' },
    )) {
        foreach ($Device in $Item.Devices) {
            [PSCustomObject]@{
                'Endpoint' = $Device
                'Missing'  = $Item.Platform
            }
        }
    }

    if ($script:Missing_Ninja.Count -gt 0 -or $script:Missing_S1.Count -gt 0) {
        $script:Discrepancies = $true
    } else {
        $script:Discrepancies = $false
    }

    if (!$Output) {
        $Comparison | Sort-Object -Property Missing,Endpoint | Format-Table -AutoSize
    } else {
        $Comparison | Sort-Object -Property Missing,Endpoint | Export-Csv -Path "$Dir\Ninja+S1_Audit.csv" -NoTypeInformation
    }
    
    if ($script:Discrepancies) { Write-Host "INFO: Results have been $(!$Output ? 'displayed above in console as table' : 'exported to CSV')." -ForegroundColor DarkCyan }
}

function Get-Results {
    if ($script:Discrepancies) {
        Write-Host "INFO: Total devices in SentinelOne: $($script:Endpoints_S1.Count)" -ForegroundColor DarkCyan
        Write-Host "INFO: Total devices in NinjaOne: $($script:Endpoints_Ninja.Count)" -ForegroundColor DarkCyan
        Write-Host "WARN: Devices missing from SentinelOne: $($script:Missing_S1.Count)" -ForegroundColor DarkYellow
        Write-Host "WARN: Devices missing from NinjaOne: $($script:Missing_Ninja.Count)" -ForegroundColor DarkYellow
    } else {
        Write-Host "PASS: No discrepancies found in SentinelOne and NinjaOne" -ForegroundColor DarkGreen
    }
}

#endregion -----------------------------------------------------------------------------------------------------------------

#region ANCILLARY_FUNCTIONS ------------------------------------------------------------------------------------------------

function Get-ID {
    return @{
        'CompanyA' = @{
            'Ninja' = '001'
            'S1'    = '0000000000000000000'
        }
        'CompanyB' = @{
            'Ninja' = '002'
            'S1'    = '0000000000000000000'
        }
        'CompanyC' = @{
            'Ninja' = '003'
            'S1'    = '0000000000000000000'
        }
    }
}

function Get-NinjaToken {
    $AuthBody = @{
        'grant_type'    = 'client_credentials'
        'client_id'     = ''
        'client_secret' = ''
        'scope'         = 'monitoring management'
    }
    return @{
        'Authorization' = "Bearer $(Invoke-WebRequest -Uri "$($URL_Ninja)/ws/oauth/token" -Method POST -Body $AuthBody -ContentType 'application/x-www-form-urlencoded' |
                          Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty access_token)"
        'Content-Type'  = 'application/json'
    }
}

function Get-S1Token {
    return @{
        'Authorization' = "ApiToken [TOKEN]"
        'Content-Type'  = 'application/json'
    }
}

#endregion -----------------------------------------------------------------------------------------------------------------

#region EXECUTIONS ---------------------------------------------------------------------------------------------------------

Get-NinjaEndpoints -OrgID $($(Get-ID).CompanyA.Ninja)
Get-S1Endpoints -SiteID $($(Get-ID).CompanyA.S1)
Compare-Endpoints -Output
Get-Results

#endregion -----------------------------------------------------------------------------------------------------------------
