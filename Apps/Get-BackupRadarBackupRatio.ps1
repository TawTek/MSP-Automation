$APIKey = ""

$Headers = @{
    "ApiKey" = $APIKey
    "accept" = "application/json"
}

function Get-BackupHistoryData {
    param(
        [string]$DateString,
        [hashtable]$Headers
    )
    
    try {
        $URL = "https://api.backupradar.com/backups/bg?date=$DateString&includeHistoryDetails=true&Size=1000"
        Write-Host "Fetching backup history from: $URL"
        
        $AllResults = @()
        $Page = 1
        
        do {
            $PageURL = "$URL&Page=$Page"
            Write-Host "Fetching page $Page..."
            
            $Response = Invoke-RestMethod -Uri $PageURL -Headers $Headers
            
            # Filter out non-scheduled backups
            $ScheduledBackups = $Response.Results | Where-Object { 
                $_.history -and $_.history[0].isScheduled -eq $true 
            }
            $AllResults += $ScheduledBackups
            
            Write-Host "Found $($Response.Results.Count) backups on page $Page ($($ScheduledBackups.Count) scheduled)"
            $Page++
            $HasMorePages = $Page -le $Response.TotalPages
            
        } while ($HasMorePages)
        
        return $AllResults
    } catch {
        Write-Warning "Failed to get backup history for $DateString : $($_.Exception.Message)"
        return @()
    }
}

function Get-HistoryMetrics {
    param(
        [array]$Backups,
        [string]$TargetDate
    )
    
    $TotalFails = 0
    $TotalWarnings = 0
    $TotalSuccess = 0
    $ProcessedBackups = 0

    $TargetDateFormatted = "${TargetDate}T00:00:00"
    
    Write-Host "Counting backups for date: $TargetDateFormatted" -ForegroundColor Yellow
    
    foreach ($Backup in $Backups) {
        $HistoryForDate = $Backup.history | Where-Object { $_.date -eq $TargetDateFormatted }
        
        if ($HistoryForDate -and $HistoryForDate.isScheduled -eq $true) {
            $StatusName = $HistoryForDate.status.name
            
            if ($StatusName -eq "Success") {
                $TotalSuccess++
            } elseif ($StatusName -eq "Warning") {
                $TotalWarnings++
            } elseif ($StatusName -in @("Failed", "Failure")) {
                $TotalFails++
            }
            
            $ProcessedBackups++
        }
    }
    
    $TotalBackups = $TotalFails + $TotalWarnings + $TotalSuccess
    $Ratio = if ($TotalBackups -gt 0) { 
        [math]::Round(($TotalFails + $TotalWarnings) / $TotalBackups * 100, 2) 
    } else { 0 }
    
    return [PSCustomObject]@{
        Fails = $TotalFails
        Warnings = $TotalWarnings
        Success = $TotalSuccess
        TotalBackups = $TotalBackups
        Ratio = $Ratio
        RatioPercent = "$Ratio%"
        ProcessedBackups = $ProcessedBackups
    }
}

try {
    # Get dates
    $Yesterday = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")
    $DayBeforeYesterday = (Get-Date).AddDays(-2).ToString("yyyy-MM-dd")
    $TwoDaysAgo = (Get-Date).AddDays(-3).ToString("yyyy-MM-dd")
    
    Write-Host "Calculating backup metrics for:"
    Write-Host "Yesterday: $Yesterday"
    Write-Host "Day Before: $DayBeforeYesterday"
    
    # Get data for yesterday
    Write-Host "`nGetting backup history for yesterday ONLY..."
    $YesterdayBackups = Get-BackupHistoryData -DateString $Yesterday -Headers $Headers
    Write-Host "Total yesterday backups retrieved: $($YesterdayBackups.Count) (scheduled only)"
    
    # Get data for day before
    Write-Host "`nGetting backup history for day before ONLY..."
    $DayBeforeBackups = Get-BackupHistoryData -DateString $DayBeforeYesterday -Headers $Headers
    Write-Host "Total day before backups retrieved: $($DayBeforeBackups.Count) (scheduled only)"
    
    # Get data for 2 days ago
    Write-Host "`nGetting backup history for 2 days ago ONLY..."
    $TwoDaysAgoBackups = Get-BackupHistoryData -DateString $TwoDaysAgo -Headers $Headers
    Write-Host "Total 2 days ago backups retrieved: $($TwoDaysAgoBackups.Count) (scheduled only)"

    # Calculate metrics
    $YesterdayMetrics = Get-HistoryMetrics -Backups $YesterdayBackups -TargetDate $Yesterday
    $DayBeforeMetrics = Get-HistoryMetrics -Backups $DayBeforeBackups -TargetDate $DayBeforeYesterday
    $TwoDaysAgoMetrics = Get-HistoryMetrics -Backups $TwoDaysAgoBackups -TargetDate $TwoDaysAgo
    
    # Create output
    $Output = [PSCustomObject]@{
    Yesterday = [PSCustomObject]@{
        Date = $Yesterday
        Fails = $YesterdayMetrics.Fails
        Warnings = $YesterdayMetrics.Warnings
        Success = $YesterdayMetrics.Success
        TotalBackups = $YesterdayMetrics.TotalBackups
        Ratio = $YesterdayMetrics.Ratio
        RatioPercent = $YesterdayMetrics.RatioPercent
        ScheduledBackupsProcessed = $YesterdayMetrics.ProcessedBackups
        TotalScheduledBackups = $YesterdayBackups.Count
    }
    DayBefore = [PSCustomObject]@{
        Date = $DayBeforeYesterday
        Fails = $DayBeforeMetrics.Fails
        Warnings = $DayBeforeMetrics.Warnings
        Success = $DayBeforeMetrics.Success
        TotalBackups = $DayBeforeMetrics.TotalBackups
        Ratio = $DayBeforeMetrics.Ratio
        RatioPercent = $DayBeforeMetrics.RatioPercent
        ScheduledBackupsProcessed = $DayBeforeMetrics.ProcessedBackups
        TotalScheduledBackups = $DayBeforeBackups.Count
    }
    TwoDaysAgo = [PSCustomObject]@{
        Date = $TwoDaysAgo
        Fails = $TwoDaysAgoMetrics.Fails
        Warnings = $TwoDaysAgoMetrics.Warnings
        Success = $TwoDaysAgoMetrics.Success
        TotalBackups = $TwoDaysAgoMetrics.TotalBackups
        Ratio = $TwoDaysAgoMetrics.Ratio
        RatioPercent = $TwoDaysAgoMetrics.RatioPercent
        ScheduledBackupsProcessed = $TwoDaysAgoMetrics.ProcessedBackups
        TotalScheduledBackups = $TwoDaysAgoBackups.Count
    }
}
    
    # Display results
    Write-Host "`nBackup Metrics Summary (Scheduled Backups Only):"
    Write-Host "================================================="
    Write-Host "YESTERDAY ($Yesterday):"
    Write-Host "  Scheduled Backups: $($YesterdayMetrics.ProcessedBackups)/$($YesterdayBackups.Count)"
    Write-Host "  Fails: $($YesterdayMetrics.Fails)"
    Write-Host "  Warnings: $($YesterdayMetrics.Warnings)" 
    Write-Host "  Success: $($YesterdayMetrics.Success)"
    Write-Host "  Total Backup Jobs: $($YesterdayMetrics.TotalBackups)"
    Write-Host "  Ratio (F+W/Total): $($YesterdayMetrics.RatioPercent)"
    
    Write-Host "`nDAY BEFORE ($DayBeforeYesterday):"
    Write-Host "  Scheduled Backups: $($DayBeforeMetrics.ProcessedBackups)/$($DayBeforeBackups.Count)"
    Write-Host "  Fails: $($DayBeforeMetrics.Fails)"
    Write-Host "  Warnings: $($DayBeforeMetrics.Warnings)"
    Write-Host "  Success: $($DayBeforeMetrics.Success)"
    Write-Host "  Total Backup Jobs: $($DayBeforeMetrics.TotalBackups)"
    Write-Host "  Ratio (F+W/Total): $($DayBeforeMetrics.RatioPercent)"
    
    Write-Host "`n2 DAYS AGO ($TwoDaysAgo):"
    Write-Host "  Scheduled Backups: $($TwoDaysAgoMetrics.ProcessedBackups)/$($TwoDaysAgoBackups.Count)"
    Write-Host "  Fails: $($TwoDaysAgoMetrics.Fails)"
    Write-Host "  Warnings: $($TwoDaysAgoMetrics.Warnings)"
    Write-Host "  Success: $($TwoDaysAgoMetrics.Success)"
    Write-Host "  Total Backup Jobs: $($TwoDaysAgoMetrics.TotalBackups)"
    Write-Host "  Ratio (F+W/Total): $($TwoDaysAgoMetrics.RatioPercent)"

    $Output | ConvertTo-Json -Depth 4
    
} catch {
    Write-Error "API request failed: $($_.Exception.Message)"
}