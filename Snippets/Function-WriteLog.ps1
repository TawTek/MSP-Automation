function Write-Log {

    <#
    [SUMMARY]
    Advanced logging function with Unicode icons, multiple output types, and configurable formatting.

    [PARAMETERS]
    - $Info, $Pass, $Warn, $Fail: Switch parameters for different log levels with colored output and Unicode icons.
    - $Dbug: Switch for debug-level messages with detailed diagnostic information.
    - $Trac: Switch for execution flow tracking and decision path logging (shows when Debug is enabled).
    - $Func: Switch for function entry/exit logging with automatic calling function name detection.
    - $Step: Switch for step messages (only shows in console if $script:Log_ShowSteps = $true, always logs to file).
    - $View: Switch for raw message output without prefixes or coloring.
    - $Header, $HeaderEnd: Switches for section header formatting with decoration.
    - $SystemInfo: Switch for comprehensive system information block.
    - $Message: The log message text (position 0 for most parameter sets).
    - $LogPath: Path to log file (defaults to $LogFile).
    - $Decoration: Character used for header decoration lines (default: "-").
    - $HeaderWidth: Width of header lines in characters (default: 120).

    [CONFIGURATION VARIABLES]
    - $script:Log_ShowSteps: Controls Step and Function entry/exit logging visibility in console ($true if $null).
    - $script:Log_ShowDebug: Controls Debug and Trace message visibility in console ($true if $null).
    - $script:Log_ShowIconsInConsole: Shows/hides Unicode icons in console output ($true if $null).
    - $script:Log_ShowIconsInFile: Includes/excludes Unicode icons in log file ($true if $null).
    - $script:ShowAllIconsInConsole: Controls FUNC gear icon display in console ($false if $null).
    - $Script:LogfileFail: Tracks log file creation failures for error recovery.

    [UNICODE ICONS]
    - Info: 🛈 (Circled Information Source)
    - Pass: ✔ (Heavy Check Mark)
    - Warn: ⚑ (Black Flag)
    - Fail: ✘ (Ballot X)
    - Func: ⚙ (Gear - function tracing, conditional display)
    - Step: ➜ (Rightwards Arrow - step progression)
    - Trac: ➜ (Rightwards Arrow - execution flow tracking)
    - Dbug: ▷ (Rightwards Arrow - diagnostic tracking)

    [LOGIC]
    1. Parameter Set Routing:
       - Use PowerShell parameter sets to handle mutually exclusive log types.
       - SystemInfo: Output pre-formatted system information block with hardware details.
       - Header: Create centered text with decoration characters for section headers.
       - HeaderEnd: Create full-width decoration lines for section endings.
       - View: Use for Format-Table and List to write to log as well as view in console.
       - Step: Step messages with conditional console output based on $script:Log_ShowSteps.
       - Func: Function entry/exit logging with automatic calling function name detection.
       - Trac: Execution flow tracking that shows when Debug is enabled.

    2. Message Formatting:
       - Standard messages: Apply timestamp and type prefix with optional Unicode icons.
       - Icon format: PREFIX ICON MESSAGE (icons controlled by configuration variables).
       - Color coding: White (Info), DarkCyan (Pass), DarkYellow (Warn), DarkRed (Fail), DarkBlue (Dbug), DarkGreen (Trac), DarkGray (Func), Gray (Step).
       - Header centering: Calculate padding for centered text with dynamic width.
       - FUNC special formatting: ∷∷∷  FUNCTION  ∷∷∷ with optional gear icon.

    3. Output Handling:
       - Console: Write colored output with optional Unicode icons based on configuration.
       - File: Write timestamped entries with optional icons based on $script:Log_ShowIconsInFile.
       - Error resilience: Continue console output if file writing fails.
       - Icon control: Separate settings for console and file icon display.
       - Log failure tracking: Automatic detection and recovery from log file issues.

    4. System Information:
       - Capture execution context, system specs, and environment details.
       - Include memory, disk space, PowerShell version, and process information.
       - Output as pre-formatted multi-line block with border decoration.

    [USE CASES]
    - INFO: General information, status updates, initialization messages
    - PASS: Successful operations, completed tasks, validation success
    - WARN: Non-critical issues, deprecated features, performance concerns
    - FAIL: Critical errors, authentication failures, system issues that stop execution
    - DBUG: Detailed diagnostic information, variable values, state tracking
    - TRAC: Execution flow tracking, decision paths, loop iterations, function entry/exit (shows when Debug enabled)
    - FUNC: Function entry/exit logging for execution flow and debugging. Automatically detects calling function name.
    - STEP: Debug/trace messages for workflow progression (controlled by $script:Log_ShowSteps)

    [FUNCTION NAME DETECTION]
    - Primary method: Get-PSCallStack[1].FunctionName (most reliable across all contexts)
    - Secondary fallback: MyInvocation scope detection (for module contexts)
    - Tertiary fallback: Scope iteration (for complex embedded scenarios)
    - Universal compatibility: Works in modules, embedded functions, and direct scripts
    - Error handling: Graceful degradation to "UNKNOWN" if all methods fail
    - Silent operation: No internal logging to prevent recursion and keep output clean

    [TRAC DEBUGGING INTEGRATION]
    - TRAC messages automatically show when $script:Log_ShowDebug = $true
    - Provides execution flow context alongside variable state from DBUG messages
    - Perfect for decision flow analysis, loop tracking, and function call tracing
    - Uses DarkGreen color with ➜ icon for maximum visibility
    - Always logs to file regardless of console visibility settings
    #>

    [CmdletBinding()]
    param(
        # Log type switches
        [Parameter(ParameterSetName = "Info")][switch]$Info,
        [Parameter(ParameterSetName = "Pass")][switch]$Pass,
        [Parameter(ParameterSetName = "Warn")][switch]$Warn,
        [Parameter(ParameterSetName = "Fail")][switch]$Fail,
        [Parameter(ParameterSetName = "Dbug")][switch]$Dbug,
        [Parameter(ParameterSetName = "Trac")][switch]$Trac,
        [Parameter(ParameterSetName = "Func")][switch]$Func,
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
        [Parameter(Position = 0, ParameterSetName = "Dbug")]
        [Parameter(Position = 0, ParameterSetName = "Func")]
        [Parameter(Position = 0, ParameterSetName = "Step")]
        [Parameter(Position = 0, ParameterSetName = "Trac")]
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
        { $null -eq $script:Log_ShowDebug }          { $script:Log_ShowDebug = $true }
        { $null -eq $script:ShowAllIconsInConsole }  { $script:ShowAllIconsInConsole = $false }
        { $null -eq $script:Log_ShowIconsInConsole } { $script:Log_ShowIconsInConsole = $true }
        { $null -eq $script:Log_ShowIconsInFile }    { $script:Log_ShowIconsInFile = $true }
    }

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Handle logfile failure tracking and recovery
    if ([string]::IsNullOrWhiteSpace($LogPath)) {
        if (-not $Script:LogfileFail) {
            Write-Host "WARN ⚑ Logfile creation failed, outputting to console only."
            $Script:LogfileFail = $true
        }
    } elseif ($Script:LogfileFail) {
        $Script:LogfileFail = $false
    }

    if ($SystemInfo) {
        $Title           = "SYSTEM INFORMATION"
        $TitleWithSpaces = " $Title "
        $AvailableWidth  = $HeaderWidth - 1
        $TotalPadding    = $AvailableWidth - $TitleWithSpaces.Length
        $LeftPadding     = [math]::Floor($TotalPadding / 2)
        $RightPadding    = $TotalPadding - $LeftPadding
        $TopLine         = ('═' * $LeftPadding) + $TitleWithSpaces + ('═' * $RightPadding)
        $BottomLine      = '═' * $AvailableWidth
        $SystemInfoProp  = @(
            $TopLine
            "Execution Time: $($TimeStamp)"
            "Executed By:    $($env:USERDOMAIN)\$($env:USERNAME)"
            "Host Computer:  $($env:COMPUTERNAME)"
            "PS Version:     $($PSVersionTable.PSVersion)"
            "Process ID:     $PID"
            "C: Drive Free:  $(try { [math]::Round((Get-PSDrive C).Free / 1GB, 2) } catch { "N/A" }) GB"
            "Total Memory:   $(try { [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2) } catch { "N/A" }) GB"
            $BottomLine
        )
        $SystemInfoContent = $SystemInfoProp -join "`n"
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

    # Define log type configuration with icons
    $logTypes = @{
        Info = @{ Prefix = "INFO"; Icon = "🛈"; Color = "White" }
        Pass = @{ Prefix = "PASS"; Icon = "✔"; Color = "DarkCyan" }
        Warn = @{ Prefix = "WARN"; Icon = "⚑"; Color = "DarkYellow" }
        Fail = @{ Prefix = "FAIL"; Icon = "✘"; Color = "DarkRed" }
        Func = @{ Prefix = "FUNC"; Icon = "⚙"; Color = "DarkGray" }
        Dbug = @{ Prefix = "DBUG"; Icon = "▷"; Color = "DarkBlue" }
        Trac = @{ Prefix = "TRAC"; Icon = "➜"; Color = "DarkGreen" }
        Step = @{ Prefix = "STEP"; Icon = "➜"; Color = "Gray" }
    }

    # Handle special cases first
    if ($PSCmdlet.ParameterSetName -eq 'Func') {
        $ConsoleColor = $logTypes.Func.Color
        $FilePrefix = $logTypes.Func.Prefix
        $IconChar = $logTypes.Func.Icon

        # Get the calling function name (skipping this embedded function scope)
        $Caller = $null
        try {
            $Stack = Get-PSCallStack -ErrorAction SilentlyContinue
            if ($Stack.Count -gt 1) {
                $Caller = $Stack[1].FunctionName
            }
        } catch {
            # Fallback to MyInvocation if Get-PSCallStack fails
            try {
                $CallerStack = Get-PSCallStack -ErrorAction SilentlyContinue
                if ($CallerStack -and $CallerStack.Count -gt 1) {
                    $Caller = $CallerStack[1].FunctionName
                } else {
                    # Last resort: use MyInvocation from higher scopes for embedded functions
                    for ($Scope = 2; $Scope -le 5; $Scope++) {
                        try {
                            $Invocation = (Get-Variable -Name MyInvocation -Scope $Scope -ErrorAction SilentlyContinue).Value
                            if ($Invocation.MyCommand.Name -and $Invocation.MyCommand.Name -ne "Write-Log") {
                                $Caller = $Invocation.MyCommand.Name
                                break
                            }
                        } catch {
                            # Continue to next scope
                        }
                    }
                }
            } catch {
                # Final fallback to MyInvocation
                $Caller = "UNKNOWN"
            }
        }

        if ($null -eq $Caller -or $Caller -eq "") {
            $Caller = "UNKNOWN"
        }

        # Format message: auto function name only, or function name + custom message
        $Message = if ([string]::IsNullOrEmpty($Message)) {
            "∷∷∷  $($Caller.ToUpper())  ∷∷∷"
        } else {
            "∷∷∷  $($Caller.ToUpper())  ∷∷∷ $Message"
        }
    } elseif ($PSCmdlet.ParameterSetName -eq 'View') {
        # View doesn't use console output, only file output
        return
    } else {
        # Standard log types - use hashtable lookup
        $typeConfig = $logTypes[$PSCmdlet.ParameterSetName]
        $ConsoleColor = $typeConfig.Color
        $FilePrefix = $typeConfig.Prefix
        $IconChar = $typeConfig.Icon
    }

    # Output formatting and rendering
    $ShowIcon = if ($PSCmdlet.ParameterSetName -eq 'Func') {
        $script:ShowAllIconsInConsole -eq $true
    } else {
        $script:Log_ShowIconsInConsole
    }
    $ShowFileIcon = if ($PSCmdlet.ParameterSetName -eq 'Func') {
        $script:ShowAllIconsInConsole -eq $true
    } else {
        $script:Log_ShowIconsInFile
    }

    # Console + File output
    $ConsoleOutput = "$FilePrefix$(if ($ShowIcon) { " $IconChar" }) $Message"
    $FileOutput    = "$Timestamp $FilePrefix$(if ($ShowFileIcon) { " $IconChar" }) $Message"

    # Visibility control
    $ShowConsole = switch ($PSCmdlet.ParameterSetName) {
        { $_ -in @("Step", "Func") } { $script:Log_ShowSteps }
        { $_ -in @("Dbug", "Trac") } { $script:Log_ShowDebug }
        default { $true }
    }

    # Render output to console and/or file
    if ($ShowConsole) {
        Write-Host $ConsoleOutput -ForegroundColor $ConsoleColor
    }
    if (-not ($View -or $script:LogfileFail)) {
        try {
            $FileOutput | Out-File -FilePath $LogPath -Append -Encoding UTF8
        } catch {
            Write-Host "FAIL ✘ Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

#Write-Log -Info "This is a general information message."
#Write-Log -Step "This is a step in execution process."
#Write-Log -Pass "Successfully completed the operation."
#Write-Log -Warn "Something went wrong but execution can continue."
#Write-Log -Fail "Critical error occurred, stopping execution."
#Write-Log -Dbug "Detailed diagnostic information for troubleshooting."
#Write-Log -Trac "Decision path: Taking alternate route due to condition."
#Write-Log -Func
#Write-Log -Header "SECTION HEADER"
#Write-Log -HeaderEnd
#Write-Log -View $Results
#Write-Log -SystemInfo