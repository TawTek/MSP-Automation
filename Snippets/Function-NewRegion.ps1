function New-Region {
    param(
        [string]$Title,
        [ValidateSet('Main','Sub','Nest')][string]$Level,
        [ValidateSet('Region','EndRegion','EndRegionOnly')][string]$Type,
        [int]$LineLength = 120,
        [switch]$Clear
    )

    if ($Clear) {
        $script:RegionCollection = $null
        return
    }
    
    # Character and enclosure styles for each level
    switch ($Level) {
        'Main'   { 
            $Decoration     = '═'
            $LeftEnclosure  = '{'
            $RightEnclosure = '}'
        }
        'Sub'    { 
            $Decoration     = '─'
            $LeftEnclosure  = '['
            $RightEnclosure = ']'
        }
        'Nest' { 
            $Decoration     = '~'
            $LeftEnclosure  = '<'
            $RightEnclosure = '>'
        }
    }
    
    # Prefix based on region type
    switch ($Type) {
        'EndRegion'     { $Prefix = "#endregion" }
        'EndRegionOnly' { $Prefix = "#endregion" }
        'Region'        { $Prefix = "#region" }
    }
    
    # Handle EndRegionOnly case (no title)
    if ($Type -eq 'EndRegionOnly') {
        $PrefixWithSpace = "$Prefix "
        $PaddingNeeded   = ($LineLength - 1) - $PrefixWithSpace.Length
        $FullLine        = $Decoration * $PaddingNeeded
        $Result          = "$PrefixWithSpace$FullLine"
    } else {
        $Content  = " ${LeftEnclosure} ${Title} ${RightEnclosure} "
        $TotalPad = ($LineLength - 1) - $Content.Length
        $LeftPad  = $Decoration * [math]::Floor($TotalPad / 2)
        $RightPad = $Decoration * ($TotalPad - [math]::Floor($TotalPad / 2))
        $Centered = "$LeftPad$Content$RightPad"
        $Result   = "$Prefix " + $Centered.Substring(("$Prefix ").Length)
    }
    
    # Add to collection and copy all
    if (-not $script:RegionCollection) { $script:RegionCollection = @() }
    
    $script:RegionCollection += $Result
    
    # Copy the entire collection
    $script:RegionCollection -join "`r`n" | Set-Clipboard
    
    return $Result
}

# Usage Examples:

# New-Region -Title "FUNCTION.MAIN" -Level Main -Type Region
# New-Region -Title "FUNCTION.MAIN" -Level Main -Type EndRegion
# New-Region -Title "FUNCTION.Sub" -Level Sub -Type Region
# New-Region -Title "FUNCTION.Sub" -Level Sub -Type EndRegion
# New-Region -Title "FUNCTION.Nest" -Level Nest -Type Region
# New-Region -Title "FUNCTION.Nest" -Level Nest -Type EndRegion

# New-Region -Title "FUNCTION.MAIN" -Level Main -Type Region -LineLength 100
# New-Region -Title "FUNCTION.MAIN" -Level Main -Type EndRegion -LineLength 100
# New-Region -Title "FUNCTION.Sub" -Level Sub -Type Region -LineLength 100
# New-Region -Title "FUNCTION.Sub" -Level Sub -Type EndRegion -LineLength 100
# New-Region -Title "FUNCTION.Nest" -Level Nest -Type Region -LineLength 100
# New-Region -Title "FUNCTION.Nest" -Level Nest -Type EndRegion -LineLength 100

# New-Region -Level Main -Type EndRegionOnly
# New-Region -Level Sub -Type EndRegionOnly
# New-Region -Level Nest -Type EndRegionOnly

# New-Region -Level Main -Type EndRegionOnly -LineLength 100
# New-Region -Level Sub -Type EndRegionOnly -LineLength 100
# New-Region -Level Nest -Type EndRegionOnly -LineLength 100

# New-Region -Clear