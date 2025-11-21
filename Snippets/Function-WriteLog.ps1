function Write-Log {

    <#
    [SUMMARY]
    Logging function with multiple output types, colors, and formatting options.

    [PARAMETERS]
    - $Info, $Pass, $Warn, $Fail: Switch parameters for different log levels with colored output.
    - $View: Switch for raw message output without prefixes or coloring.
    - $Header, $HeaderEnd: Switches for section header formatting with decoration.
    - $SystemInfo: Switch for comprehensive system information block.
    - $Message: The log message text (position 0 for most parameter sets).
    - $LogPath: Path to log file (defaults to $LogFile).
    - $Decoration: Character used for header decoration lines (default: "-").
    - $HeaderWidth: Width of header lines in characters (default: 120).

    [LOGIC]
    1. Parameter Set Routing:
       - Use PowerShell parameter sets to handle mutually exclusive log types.
       - SystemInfo: Output pre-formatted system information block with hardware details.
       - Header: Create centered text with decoration characters for section headers.
       - HeaderEnd: Create full-width decoration lines for section endings.
       - View: Use for Format-Table and List to write to log as well as view in console.

    2. Message Formatting:
       - Standard messages: Apply timestamp and type prefix ([INFO], [PASS], etc.).
       - Color coding: White (Info), DarkCyan (Pass), Yellow (Warn), Red (Fail).
       - Header centering: Calculate padding for centered text with dynamic width.

    3. Output Handling:
       - Console: Write colored output appropriate for each log level.
       - File: Write timestamped entries with UTF8 encoding.
       - Error resilience: Continue console output if file writing fails.

    4. System Information:
       - Capture execution context, system specs, and environment details.
       - Include memory, disk space, PowerShell version, and process information.
       - Output as pre-formatted multi-line block with border decoration.

    [OUTPUT]
    - Console: Colored output based on log level with appropriate prefixes.
    - File: Timestamped log entries with consistent formatting.
    - Headers: Centered text with decorative borders for section organization.
    - System Info: Comprehensive environment snapshot for troubleshooting.
    #>

    [CmdletBinding()]
    param(
        # Log type switches
        [Parameter(ParameterSetName = "Info")][switch]$Info,
        [Parameter(ParameterSetName = "Pass")][switch]$Pass,
        [Parameter(ParameterSetName = "Warn")][switch]$Warn,
        [Parameter(ParameterSetName = "Fail")][switch]$Fail,
        [Parameter(ParameterSetName = "View")][switch]$View,
        [Parameter(ParameterSetName = "Header")][switch]$Header,
        [Parameter(ParameterSetName = "HeaderEnd")][switch]$HeaderEnd,
        [Parameter(ParameterSetName = "SystemInfo")][switch]$SystemInfo,

        # Message parameter
        [Parameter(Position = 0, ParameterSetName = "Info")]
        [Parameter(Position = 0, ParameterSetName = "Pass")]
        [Parameter(Position = 0, ParameterSetName = "Warn")]
        [Parameter(Position = 0, ParameterSetName = "Fail")]
        [Parameter(Position = 0, ParameterSetName = "View")]
        [Parameter(Position = 0, ParameterSetName = "Header")]
        [string]$Message,

        # Log configuration
        [string]$LogPath    = $LogFile,
        [string]$Decoration = "─",
        [int]$HeaderWidth   = $(if ($NinjaConsole) { $NinjaConsole } else { 120 })
    )

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Handle logfile failure tracking and recovery
    if ([string]::IsNullOrWhiteSpace($LogPath) -and -not $Script:LogfileFail) {
        Write-Host "[WARN] Logfile creation failed, outputting to console only."
        $Script:LogfileFail = $true
    }

    # Reset flag if logpath becomes valid again
    if (-not [string]::IsNullOrWhiteSpace($LogPath) -and $Script:LogfileFail) {
        $Script:LogfileFail = $false
    }

    if ($SystemInfo) {
        $Title           = "SYSTEM INFORMATION"
        $TitleWithSpaces = " $Title "
        $AvailableWidth  = $HeaderWidth - 1
        
        $TotalPadding = $AvailableWidth - $TitleWithSpaces.Length
        $LeftPadding  = [math]::Floor($TotalPadding / 2)
        $RightPadding = $TotalPadding - $LeftPadding
        
        $TopLine    = ('═' * $LeftPadding) + $TitleWithSpaces + ('═' * $RightPadding)
        $BottomLine = '═' * $AvailableWidth
    
        $SystemInfoContent = @"
$TopLine
Execution Time:   $($TimeStamp)
Executed By:      $($env:USERDOMAIN)\$($env:USERNAME)
Host Computer:    $($env:COMPUTERNAME)
PS Version:       $($PSVersionTable.PSVersion)
Process ID:       $PID
C: Drive Free:    $(try { [math]::Round((Get-PSDrive C).Free / 1GB, 2) } catch { "N/A" }) GB
Total Memory:     $(try { [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2) } catch { "N/A" }) GB
$BottomLine
"@
        Write-Host "`n$SystemInfoContent" -ForegroundColor "DarkGray"
        if (-not $script:LogfileFail) { $SystemInfoContent | Out-File -FilePath $LogPath -Encoding UTF8 }
        return
    }

    if ($Header) {
        $ActualWidth    = $HeaderWidth - 1 # VSCode displays character position, PowerShell counts string length from 0
        $Text           = $Message.Trim()
        $TextWithSpaces = " $Text "
        $TotalPadding   = $ActualWidth - $TextWithSpaces.Length

        # Truncate headers that are too long and add ellipsis
        if ($TotalPadding -lt 0) {
            $Text           = $Text.Substring(0, $ActualWidth - 5) + "..." # -5 accounts for '...' and spacing
            $TextWithSpaces = " $Text "
            $TotalPadding   = $ActualWidth - $TextWithSpaces.Length
        }

        $LeftPadding  = [math]::Floor($TotalPadding / 2)
        $RightPadding = $TotalPadding - $LeftPadding
        $HeaderText   = "`n$($Decoration * $LeftPadding)$TextWithSpaces$($Decoration * $RightPadding)"

        Write-Host $HeaderText -ForegroundColor "DarkGray"
        if (-not $script:LogfileFail) { $HeaderText | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
        return
    }

    # Handle HeaderEnd - full line with decoration only
    if ($HeaderEnd) {
        $FullLine = $Decoration * ($HeaderWidth - 1)
        Write-Host $FullLine -ForegroundColor "DarkGray"
        if (-not $script:LogfileFail) { $FullLine | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
        return
    }

    # Handle Display parameter to write to console and log file without prefix
    if ($View) {
        Write-Host $Message
        try {
            if (-not $script:LogfileFail) { $Message | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
        return
    }

    # Determine log type and formatting for regular messages
    switch ($PSCmdlet.ParameterSetName) {
        "Info" {
            $ConsoleColor = "White"
            $FilePrefix   = "[INFO]"
        }
        "Pass" {
            $ConsoleColor = "DarkCyan"
            $FilePrefix   = "[PASS]"
        }
        "Warn" {
            $ConsoleColor = "Yellow"
            $FilePrefix   = "[WARN]"
        }
        "Fail" {
            $ConsoleColor = "Red"
            $FilePrefix   = "[FAIL]"
        }
    }

    $ConsoleOutput = "$FilePrefix $Message"
    $FileOutput    = "$Timestamp $FilePrefix $Message"

    Write-Host $ConsoleOutput -ForegroundColor $ConsoleColor

    if (-not $script:LogfileFail) {
        try {
            $FileOutput | Out-File -FilePath $LogPath -Append -Encoding UTF8
        } catch {
            Write-Host "[FAIL] Failed to write to log file: $($_.Exception.Message)"
        }
    }
}