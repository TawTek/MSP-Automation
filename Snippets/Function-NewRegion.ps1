function New-Region {
    param(
        [string]$Title,
        [ValidateSet('Main','Sub','Nest')]
        [string]$Level,
        [ValidateSet('Region','EndRegion')]
        [string]$Type
    )
    
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
            $Decoration     = '-'
            $LeftEnclosure  = '<'
            $RightEnclosure = '>'
        }
    }

    switch ($Type) {
        'EndRegion' { $Prefix = "#endregion" }
        'Region'    { $Prefix = "#region" }
    }
    
    $Content  = " ${LeftEnclosure} ${Title}${RightEnclosure} "
    $TotalPad = 119 - $Content.Length
    $LeftPad  = $Decoration * [math]::Floor($TotalPad / 2)
    $RightPad = $Decoration * ($TotalPad - [math]::Floor($TotalPad / 2))
    $Centered = "$LeftPad$Content$RightPad"
    $Result   = "$Prefix " + $Centered.Substring(("$Prefix ").Length)
    
    return $Result
}

# Usage Examples:
# New-Region -Title "FUNCTION.MAIN" -Level Main -Type Region
# New-Region -Title "FUNCTION.MAIN" -Level Main -Type EndRegion
# New-Region -Title "FUNCTION.MAIN" -Level Sub -Type Region
# New-Region -Title "FUNCTION.MAIN" -Level Sub -Type EndRegion
# New-Region -Title "FUNCTION.MAIN" -Level Nest -Type Region
# New-Region -Title "FUNCTION.MAIN" -Level Nest -Type EndRegion