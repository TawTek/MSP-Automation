function Compare-DistributionGroupMembership {
    <#
    .SYNOPSIS
        Compares licensed mailboxes with distribution group members and identifies missing users.
    
    .DESCRIPTION
        This function compares all licensed user mailboxes with members of a specified distribution group
        and identifies users who are licensed but not members of the group.
    
    .PARAMETER GroupName
        The name of the distribution group to check membership against.
    
    .PARAMETER CSVPath
        The file path where the CSV report of missing users will be exported.
    
    .EXAMPLE
        Compare-DistributionGroupMembership -GroupName "All-Employees" -CSVPath "C:\Reports\missing_users.csv"
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$CSVPath
    )
    
    try {
        $Connected = Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { 
            $_.ConnectionUri -like "*outlook.office365.com*" -and $_.State -eq "Connected"
        }
        if (-not $Connected) {
            Write-Host 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false
            Write-Host 'Successfully connected to Exchange Online.'
        } else {
            Write-Host 'Already connected to Exchange Online.'
        }
    } catch {
        exit 1
    }
        
    # Get distribution group members
    Write-Host "[INFO] Retrieving members from distribution group '$GroupName'."
    $GroupMembers = Get-DistributionGroupMember -Identity $GroupName -ResultSize Unlimited
    
    # Get licensed user mailboxes (excluding disabled mailboxes)
    Write-Host "[INFO] Retrieving licensed user mailboxes..."
    $UsersLicensed = Get-Mailbox -ResultSize Unlimited -Filter {
        RecipientTypeDetails -eq "UserMailbox" -and 
        AccountDisabled -eq $false -and
        WhenMailboxCreated -ne $null
    }

    # Create hash table for faster lookups instead of using -notin
    $GroupEmailHash = @{}
    foreach ($Member in $GroupMembers) {
        $GroupEmailHash[$Member.PrimarySmtpAddress] = $true
    }

    # Find missing users using hash table
    $UsersMissing = $UsersLicensed | Where-Object { 
        -not $GroupEmailHash.ContainsKey($_.UserPrincipalName)
    }
    
    # Create and display statistics
    $Stats = @(
        [PSCustomObject]@{ Category = 'Licensed Users'; Count = $UsersLicensed.Count }
        [PSCustomObject]@{ Category = 'Group Members'; Count = $GroupMembers.Count }
        [PSCustomObject]@{ Category = 'Missing Users'; Count = $UsersMissing.Count }
    )   
    $Stats | Format-Table -AutoSize
    
    # Display warning if missing and results
    if ($UsersMissing.Count -gt 0) {
        Write-Host "[WARN] $($UsersMissing.Count) members are missing from '$GroupName'."
        # Export to CSV
        $UsersMissing | Select-Object DisplayName, UserPrincipalName | Export-Csv -Path $CSVPath -NoTypeInformation
        Write-Host "[INFO] Exported $($UsersMissing.Count) missing users to $CSVPath"
        # Display missing users in table format
        $UsersMissing | Select-Object DisplayName, UserPrincipalName | Format-Table -AutoSize
    } else {
        Write-Host "[INFO] No missing users found. All licensed users are members of '$GroupName'."
    }
}