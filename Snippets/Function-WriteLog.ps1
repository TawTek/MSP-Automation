function Write-Log {

    <#
    [SUMMARY]
    Advanced logging function with Unicode icons, multiple output types, and configurable formatting.

    [PARAMETERS]
    - $Info, $Pass, $Warn, $Fail: Switch parameters for different log levels with colored output and Unicode icons.
    - $View: Switch for raw message output without prefixes or coloring.
    - $Header, $HeaderEnd: Switches for section header formatting with decoration.
    - $SystemInfo: Switch for comprehensive system information block.
    - $Step: Switch for step messages (only shows in console if $script:Log_ShowSteps = $true, always logs to file).
    - $Message: The log message text (position 0 for most parameter sets).
    - $LogPath: Path to log file (defaults to $LogFile).
    - $Decoration: Character used for header decoration lines (default: "-").
    - $HeaderWidth: Width of header lines in characters (default: 120).

    [CONFIGURATION VARIABLES]
    - $script:Log_ShowSteps: Controls Step message visibility in console ($true if $null).
    - $script:Log_ShowIconsInConsole: Shows/hides Unicode icons in console output ($true if $null).
    - $script:Log_ShowIconsInFile: Includes/excludes Unicode icons in log file ($true if $null).

    [UNICODE ICONS]
    - Info: 🛈 (Circled Information Source)
    - Pass: ✔ (Heavy Check Mark) 
    - Warn: ⚑ (Black Flag)
    - Fail: ✘ (Ballot X)
    - Step: ➜ (Heavy Rightwards Arrow)

    [LOGIC]
    1. Parameter Set Routing:
       - Use PowerShell parameter sets to handle mutually exclusive log types.
       - SystemInfo: Output pre-formatted system information block with hardware details.
       - Header: Create centered text with decoration characters for section headers.
       - HeaderEnd: Create full-width decoration lines for section endings.
       - View: Use for Format-Table and List to write to log as well as view in console.
       - Step: Step messages with conditional console output based on $script:Log_ShowSteps.

    2. Message Formatting:
       - Standard messages: Apply timestamp and type prefix with optional Unicode icons.
       - Icon format: [TYPE] Message (icons controlled by $script:Log_ShowIconsInConsole/File).
       - Color coding: White (Info), DarkCyan (Pass), Yellow (Warn), Red (Fail), Gray (Step).
       - Header centering: Calculate padding for centered text with dynamic width.

    3. Output Handling:
       - Console: Write colored output with optional Unicode icons based on configuration.
       - File: Write timestamped entries with optional icons based on $script:Log_ShowIconsInFile.
       - Error resilience: Continue console output if file writing fails.
       - Icon control: Separate settings for console and file icon display.

    4. System Information:
       - Capture execution context, system specs, and environment details.
       - Include memory, disk space, PowerShell version, and process information.
       - Output as pre-formatted multi-line block with border decoration.

    [USE CASES]
    - INFO: General information, status updates, initialization messages
    - PASS: Successful operations, completed tasks, validation success
    - WARN: Non-critical issues, deprecated features, performance concerns
    - FAIL: Critical errors, authentication failures, system issues that stop execution
    - STEP: Debug/trace messages for workflow progression (controlled by $script:Log_ShowSteps)
    #>

    [CmdletBinding()]
    param(
        # Log type switches
        [Parameter(ParameterSetName = "Info")][switch]$Info,
        [Parameter(ParameterSetName = "Pass")][switch]$Pass,
        [Parameter(ParameterSetName = "Warn")][switch]$Warn,
        [Parameter(ParameterSetName = "Fail")][switch]$Fail,
        [Parameter(ParameterSetName = "Step")][switch]$Step,
        [Parameter(ParameterSetName = "View")][switch]$View,
        [Parameter(ParameterSetName = "Header")][switch]$Header,
        [Parameter(ParameterSetName = "HeaderEnd")][switch]$HeaderEnd,
        [Parameter(ParameterSetName = "SystemInfo")][switch]$SystemInfo,

        # Message parameter
        [Parameter(Position = 0, ParameterSetName = "Info")]
        [Parameter(Position = 0, ParameterSetName = "Pass")]
        [Parameter(Position = 0, ParameterSetName = "Warn")]
        [Parameter(Position = 0, ParameterSetName = "Fail")]
        [Parameter(Position = 0, ParameterSetName = "Step")]
        [Parameter(Position = 0, ParameterSetName = "View")]
        [Parameter(Position = 0, ParameterSetName = "Header")]
        [string]$Message,

        # Log configuration
        [string]$LogPath    = $LogFile,
        [string]$Decoration = ($global:LogDecoration, "-" | Where-Object { $_ } | Select-Object -First 1),
        [int]$HeaderWidth   = ($global:HeaderWidth, 120 | Where-Object { $_ } | Select-Object -First 1)
    )

    # Set defaults if script variables don't exist
    switch ($true) {
        { $null -eq $script:Log_ShowSteps }          { $script:Log_ShowSteps = $true }
        { $null -eq $script:Log_ShowIconsInConsole } { $script:Log_ShowIconsInConsole = $true }
        { $null -eq $script:Log_ShowIconsInFile }    { $script:Log_ShowIconsInFile = $true }
    }

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
Execution Time: $($TimeStamp)
Executed By:    $($env:USERDOMAIN)\$($env:USERNAME)
Host Computer:  $($env:COMPUTERNAME)
PS Version:     $($PSVersionTable.PSVersion)
Process ID:     $PID
C: Drive Free:  $(try { [math]::Round((Get-PSDrive C).Free / 1GB, 2) } catch { "N/A" }) GB
Total Memory:   $(try { [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2) } catch { "N/A" }) GB
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

    # Define icons once (outside the switch)
    $icons = @{
        Info = "🛈"
        Pass = "✔" 
        Warn = "⚑"
        Fail = "✘"
        Step = "➜"
    }

    # Determine log type and formatting for regular messages
    switch ($PSCmdlet.ParameterSetName) {
        "Info" {
            $ConsoleColor = "White"
            $FilePrefix   = "[INFO]"
            $IconChar     = $icons.Info
        }
        "Pass" {
            $ConsoleColor = "DarkCyan"
            $FilePrefix   = "[PASS]"
            $IconChar     = $icons.Pass
        }
        "Warn" {
            $ConsoleColor = "Yellow"
            $FilePrefix   = "[WARN]"
            $IconChar     = $icons.Warn
        }
        "Fail" {
            $ConsoleColor = "Red"
            $FilePrefix   = "[FAIL]"
            $IconChar     = $icons.Fail
        }
        "Step" {
            $ConsoleColor = "DarkGray"
            $FilePrefix   = "[STEP]"
            $IconChar     = $icons.Step
        }
    }

    # Console output
    $ConsoleIconPrefix = if ($script:Log_ShowIconsInConsole) { "$FilePrefix $IconChar " } else { "$FilePrefix " }
    $ConsoleOutput = "$ConsoleIconPrefix$Message"

    # File output  
    $FileIconPrefix = if ($script:Log_ShowIconsInFile) { "$FilePrefix $IconChar " } else { "$FilePrefix " }
    $FileOutput = "$Timestamp $FileIconPrefix$Message"

    # Only show Step messages in console if parameter is not "Step" or $script:Log_ShowSteps is $true
    if ($PSCmdlet.ParameterSetName -ne "Step" -or $script:Log_ShowSteps) {
        Write-Host $ConsoleOutput -ForegroundColor $ConsoleColor
    }

    if (-not $script:LogfileFail -and $View -ne $true) {
        try {
            $FileOutput | Out-File -FilePath $LogPath -Append -Encoding UTF8
        } catch {
            Write-Host "[FAIL] Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

#Write-Log -Info "This is a test."
#Write-Log -Step "This is a step in execution process."
#Write-Log -Pass "Successfully did whatever."
#Write-Log -Warn "Something went wrong."
#Write-Log -Fail "Something went really wrong."