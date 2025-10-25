# ============================================================================
# Windows Agent for CEG25 Blue Team Operations
# ============================================================================
# PowerShell-based monitoring and response agent for Windows energy infrastructure
# Optimized for CEG25 competition scoring and automated defense
# ============================================================================

param(
    [string]$Mode = "monitor",
    [string]$ConfigFile = "$PSScriptRoot\windows_agent_config.json",
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Test
)

# Configuration
$VERSION = "1.0"
$SCRIPT_NAME = "Windows Agent for CEG25"
$LOG_DIR = "$PSScriptRoot\logs"
$REPORT_DIR = "$PSScriptRoot\reports"
$CONFIG_DIR = "$PSScriptRoot\config"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"

# CEG25 Competition Settings
$CEG25_PROTECTED = @(
    "10.83.171.142",
    "*.253"  # All .253 hosts
)

$CEG25_CRITICAL_SERVICES = @(
    "SCADA",
    "HMI",
    "EMS",
    "DMS",
    "Historian",
    "WebServer",
    "Database"
)

# Windows Security Events to Monitor
$SECURITY_EVENTS = @(
    4624,  # Successful logon
    4625,  # Failed logon
    4648,  # Explicit credential logon
    4672,  # Special privileges assigned
    4720,  # User account created
    4722,  # User account enabled
    4723,  # Password change attempt
    4724,  # Password reset attempt
    4725,  # User account disabled
    4726,  # User account deleted
    4732,  # Member added to local group
    4733,  # Member removed from local group
    4740,  # User account locked out
    4771,  # Kerberos pre-authentication failed
    4776   # Credential validation
)

# Network Events to Monitor
$NETWORK_EVENTS = @(
    5152,  # Filtering platform packet drop
    5153,  # Filtering platform connection
    5154,  # Listening port
    5155,  # Listening port closed
    5156,  # Connection allowed
    5157,  # Connection blocked
    5158,  # Binding to local port
    5159   # Listening port unbound
)

# Create necessary directories
function New-Directories {
    $dirs = @($LOG_DIR, $REPORT_DIR, $CONFIG_DIR)
    foreach ($dir in $dirs) {
        if (!(Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
}

# Logging function
function Write-LogMessage {
    param(
        [string]$Level,
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Color output
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor Green }
        "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Cyan }
        "CRITICAL" { Write-Host $logMessage -ForegroundColor White -BackgroundColor Red }
        "CEG25" { Write-Host $logMessage -ForegroundColor Magenta }
    }

    # Write to log file
    $logFile = "$LOG_DIR\windows_agent_${TIMESTAMP}.log"
    Add-Content -Path $logFile -Value $logMessage
}

# Display banner
function Show-Banner {
    Clear-Host
    Write-Host "════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "    🪟 Windows Agent for CEG25 Blue Team Operations 🪟" -ForegroundColor Blue
    Write-Host "════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "Version: $VERSION | Windows Energy Infrastructure Defense" -ForegroundColor White
    Write-Host "Target: Windows Monitoring & Response | Competition Scoring Optimized" -ForegroundColor White
    Write-Host "Date: October 28-30, 2025 | Location: Warsaw, Poland" -ForegroundColor White
    Write-Host "════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host ""
    Write-Host "🛡️  WINDOWS DEFENSE MISSION: Monitor and Protect Energy Infrastructure" -ForegroundColor Yellow
    Write-Host "• Real-time security event monitoring" -ForegroundColor White
    Write-Host "• Automated incident response" -ForegroundColor White
    Write-Host "• Service availability protection" -ForegroundColor White
    Write-Host "• Competition scoring optimization" -ForegroundColor White
    Write-Host ""
}

# Create default configuration
function New-DefaultConfig {
    $config = @{
        "competition" = @{
            "phase" = "day1_morning"
            "team" = "Blue Team"
            "protected_hosts" = $CEG25_PROTECTED
            "critical_services" = $CEG25_CRITICAL_SERVICES
        }
        "monitoring" = @{
            "enabled" = $true
            "interval_seconds" = 30
            "log_security_events" = $true
            "log_network_events" = $true
            "monitor_processes" = $true
            "monitor_services" = $true
            "monitor_network" = $true
        }
        "response" = @{
            "auto_response" = $true
            "block_suspicious_ips" = $true
            "restart_critical_services" = $true
            "alert_threshold" = 5
        }
        "scoring" = @{
            "prioritize_service_availability" = $true
            "focus_vulnerability_removal" = $true
            "enable_incident_response" = $true
            "maintain_hardening" = $true
        }
    }

    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFile -Encoding UTF8
    Write-LogMessage "SUCCESS" "Default configuration created: $ConfigFile"
}

# Load configuration
function Get-Config {
    if (!(Test-Path $ConfigFile)) {
        New-DefaultConfig
    }

    try {
        $config = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
        return $config
    }
    catch {
        Write-LogMessage "ERROR" "Failed to load configuration: $($_.Exception.Message)"
        return $null
    }
}

# Check Windows security status
function Test-WindowsSecurity {
    Write-LogMessage "INFO" "Analyzing Windows security configuration"

    Write-Host "🛡️  WINDOWS SECURITY ANALYSIS" -ForegroundColor Cyan
    Write-Host ""

    # Check Windows Defender status
    $defenderStatus = Get-MpComputerStatus
    if ($defenderStatus.AntivirusEnabled) {
        Write-Host "✓ Windows Defender: Enabled" -ForegroundColor Green
    } else {
        Write-Host "✗ Windows Defender: Disabled" -ForegroundColor Red
    }

    # Check firewall status
    $firewallProfiles = Get-NetFirewallProfile
    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled) {
            Write-Host "✓ Firewall $($profile.Name): Enabled" -ForegroundColor Green
        } else {
            Write-Host "✗ Firewall $($profile.Name): Disabled" -ForegroundColor Red
        }
    }

    # Check audit policy
    $auditPolicy = auditpol /get /category:*
    if ($auditPolicy -match "Success") {
        Write-Host "✓ Audit Policy: Configured" -ForegroundColor Green
    } else {
        Write-Host "⚠ Audit Policy: Limited" -ForegroundColor Yellow
    }

    # Check user privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "✓ Running as Administrator" -ForegroundColor Green
    } else {
        Write-Host "⚠ Not running as Administrator" -ForegroundColor Yellow
    }

    Write-LogMessage "SUCCESS" "Windows security analysis completed"
}

# Monitor security events
function Watch-SecurityEvents {
    param([int]$MaxEvents = 10)

    Write-LogMessage "INFO" "Monitoring Windows security events"

    Write-Host "📊 SECURITY EVENT MONITORING" -ForegroundColor Cyan

    try {
        $events = Get-WinEvent -LogName Security -MaxEvents $MaxEvents | Select-Object TimeCreated, Id, Message

        foreach ($event in $events) {
            $eventType = switch ($event.Id) {
                4624 { "Successful Logon" }
                4625 { "Failed Logon" }
                4648 { "Explicit Credential Logon" }
                4672 { "Special Privileges" }
                default { "Security Event $($event.Id)" }
            }

            Write-Host "[$($event.TimeCreated)] $eventType" -ForegroundColor Yellow
        }

        Write-LogMessage "SUCCESS" "Security event monitoring completed"
    }
    catch {
        Write-LogMessage "ERROR" "Failed to monitor security events: $($_.Exception.Message)"
    }
}

# Monitor network connections
function Watch-NetworkConnections {
    Write-LogMessage "INFO" "Monitoring network connections"

    Write-Host "🌐 NETWORK CONNECTION MONITORING" -ForegroundColor Cyan

    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State

        foreach ($conn in $connections) {
            $isSuspicious = $false
            $reason = ""

            # Check for suspicious ports
            if ($conn.RemotePort -in @(21, 23, 25, 53, 110, 143, 993, 995)) {
                $isSuspicious = $true
                $reason = "Legacy protocol port"
            }

            # Check for suspicious remote addresses
            if ($conn.RemoteAddress -notmatch "^(10\.|172\.16\.|192\.168\.)") {
                $isSuspicious = $true
                $reason = "External connection"
            }

            if ($isSuspicious) {
                Write-Host "⚠ Suspicious: $($conn.RemoteAddress):$($conn.RemotePort) - $reason" -ForegroundColor Red
                Write-LogMessage "WARN" "Suspicious connection detected: $($conn.RemoteAddress):$($conn.RemotePort) - $reason"
            } else {
                Write-Host "✓ $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Green
            }
        }

        Write-LogMessage "SUCCESS" "Network connection monitoring completed"
    }
    catch {
        Write-LogMessage "ERROR" "Failed to monitor network connections: $($_.Exception.Message)"
    }
}

# Monitor critical services
function Watch-CriticalServices {
    Write-LogMessage "INFO" "Monitoring critical services"

    Write-Host "⚙️  CRITICAL SERVICE MONITORING" -ForegroundColor Cyan

    $config = Get-Config
    if ($null -eq $config) { return }

    foreach ($service in $config.competition.critical_services) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.Status -eq "Running") {
                    Write-Host "✓ $service service: Running" -ForegroundColor Green
                } else {
                    Write-Host "✗ $service service: $($svc.Status)" -ForegroundColor Red
                    Write-LogMessage "WARN" "Critical service $service is not running"

                    # Auto-restart if enabled
                    if ($config.response.restart_critical_services) {
                        Write-Host "🔄 Attempting to restart $service..." -ForegroundColor Yellow
                        Restart-Service -Name $service -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 2

                        $svc = Get-Service -Name $service
                        if ($svc.Status -eq "Running") {
                            Write-Host "✓ $service service restarted successfully" -ForegroundColor Green
                            Write-LogMessage "SUCCESS" "Critical service $service restarted"
                        } else {
                            Write-Host "✗ Failed to restart $service service" -ForegroundColor Red
                            Write-LogMessage "ERROR" "Failed to restart critical service $service"
                        }
                    }
                }
            } else {
                Write-Host "⚠ $service service not found" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "✗ Error checking $service service" -ForegroundColor Red
            Write-LogMessage "ERROR" "Error checking service $service : $($_.Exception.Message)"
        }
    }

    Write-LogMessage "SUCCESS" "Critical service monitoring completed"
}

# Monitor processes for suspicious activity
function Watch-Processes {
    Write-LogMessage "INFO" "Monitoring processes for suspicious activity"

    Write-Host "🔍 PROCESS MONITORING" -ForegroundColor Cyan

    try {
        $processes = Get-Process | Where-Object { $_.CPU -gt 50 -or $_.WorkingSet -gt 500MB } | Select-Object Name, Id, CPU, WorkingSet

        foreach ($process in $processes) {
            $cpuFormatted = "{0:N2}" -f $process.CPU
            $memoryFormatted = "{0:N2} MB" -f ($process.WorkingSet / 1MB)

            Write-Host "⚠ High resource usage: $($process.Name) (PID: $($process.Id)) - CPU: $cpuFormatted%, Memory: $memoryFormatted" -ForegroundColor Yellow
            Write-LogMessage "WARN" "High resource usage detected: $($process.Name) (PID: $($process.Id))"
        }

        if ($processes.Count -eq 0) {
            Write-Host "✓ No high-resource processes detected" -ForegroundColor Green
        }

        Write-LogMessage "SUCCESS" "Process monitoring completed"
    }
    catch {
        Write-LogMessage "ERROR" "Failed to monitor processes: $($_.Exception.Message)"
    }
}

# Generate Windows agent report
function New-WindowsReport {
    $reportFile = "$REPORT_DIR\windows_agent_report_${TIMESTAMP}.txt"

    Write-LogMessage "INFO" "Generating Windows agent report"

    $config = Get-Config

    $report = @"
Windows Agent Report - CEG25 Competition
Generated: $(Get-Date)
=========================================

COMPETITION CONTEXT:
- Event: CyberEXPERT Game 2025 (CEG25)
- Phase: $($config.competition.phase)
- Team: $($config.competition.team)
- Location: Warsaw, Poland
- Date: October 28-30, 2025

SYSTEM INFORMATION:
- Hostname: $($env:COMPUTERNAME)
- OS: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
- Architecture: $($env:PROCESSOR_ARCHITECTURE)
- PowerShell Version: $($PSVersionTable.PSVersion)

SECURITY STATUS:
"@

    # Windows Defender status
    $defenderStatus = Get-MpComputerStatus
    $report += "- Windows Defender: $(if ($defenderStatus.AntivirusEnabled) { 'Enabled' } else { 'Disabled' })`n"

    # Firewall status
    $firewallProfiles = Get-NetFirewallProfile
    foreach ($profile in $firewallProfiles) {
        $report += "- Firewall $($profile.Name): $(if ($profile.Enabled) { 'Enabled' } else { 'Disabled' })`n"
    }

    # Service status
    $report += "`nCRITICAL SERVICES STATUS:`n"
    foreach ($service in $config.competition.critical_services) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                $report += "- $service service: $($svc.Status)`n"
            } else {
                $report += "- $service service: Not found`n"
            }
        }
        catch {
            $report += "- $service service: Error`n"
        }
    }

    # Network connections
    $report += "`nNETWORK CONNECTIONS:`n"
    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | Select-Object -First 10
        foreach ($conn in $connections) {
            $report += "- $($conn.RemoteAddress):$($conn.RemotePort) ($($conn.State))`n"
        }
    }
    catch {
        $report += "- Error retrieving network connections`n"
    }

    # Recent security events
    $report += "`nRECENT SECURITY EVENTS:`n"
    try {
        $events = Get-WinEvent -LogName Security -MaxEvents 5 | Select-Object TimeCreated, Id
        foreach ($event in $events) {
            $report += "- [$($event.TimeCreated)] Event ID: $($event.Id)`n"
        }
    }
    catch {
        $report += "- Error retrieving security events`n"
    }

    $report += "`nCEG25 COMPETITION COMPLIANCE:`n"
    $report += "✓ Service Availability Monitoring: Enabled`n"
    $report += "✓ Security Event Monitoring: Enabled`n"
    $report += "✓ Network Connection Monitoring: Enabled`n"
    $report += "✓ Automated Response: $(if ($config.response.auto_response) { 'Enabled' } else { 'Disabled' })`n"

    $report += "`nCOMPETITION RECOMMENDATIONS:`n"
    $report += "1. Monitor security events continuously for Red Team activity`n"
    $report += "2. Ensure critical services remain available`n"
    $report += "3. Investigate suspicious network connections`n"
    $report += "4. Maintain Windows Defender real-time protection`n"
    $report += "5. Document all security incidents for scoring`n"

    $report | Out-File -FilePath $reportFile -Encoding UTF8

    Write-LogMessage "SUCCESS" "Windows agent report generated: $(Split-Path $reportFile -Leaf)"
    Write-Host "📄 Windows Agent Report: $reportFile" -ForegroundColor Green
}

# Install Windows agent as service
function Install-WindowsAgent {
    Write-LogMessage "CEG25" "Installing Windows agent service"

    Write-Host "🔧 INSTALLING WINDOWS AGENT SERVICE" -ForegroundColor Cyan

    $serviceName = "CEG25WindowsAgent"
    $serviceDisplayName = "CEG25 Windows Blue Team Agent"
    $serviceDescription = "Windows monitoring and response agent for CEG25 competition"

    # Check if service already exists
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "⚠ Service $serviceName already exists. Removing..." -ForegroundColor Yellow
        Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # Create service
    $scriptPath = $MyInvocation.MyCommand.Path
    $serviceParams = @{
        Name = $serviceName
        DisplayName = $serviceDisplayName
        Description = $serviceDescription
        BinaryPathName = "powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode monitor"
        StartupType = "Automatic"
    }

    try {
        New-Service @serviceParams
        Write-Host "✓ Windows agent service installed successfully" -ForegroundColor Green
        Write-LogMessage "SUCCESS" "Windows agent service installed: $serviceName"

        # Start service
        Start-Service -Name $serviceName
        Write-Host "✓ Windows agent service started" -ForegroundColor Green
        Write-LogMessage "SUCCESS" "Windows agent service started"
    }
    catch {
        Write-Host "✗ Failed to install Windows agent service" -ForegroundColor Red
        Write-LogMessage "ERROR" "Failed to install Windows agent service: $($_.Exception.Message)"
    }
}

# Uninstall Windows agent service
function Uninstall-WindowsAgent {
    Write-LogMessage "INFO" "Uninstalling Windows agent service"

    Write-Host "🗑️  UNINSTALLING WINDOWS AGENT SERVICE" -ForegroundColor Cyan

    $serviceName = "CEG25WindowsAgent"

    try {
        Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Write-Host "✓ Windows agent service uninstalled successfully" -ForegroundColor Green
        Write-LogMessage "SUCCESS" "Windows agent service uninstalled"
    }
    catch {
        Write-Host "✗ Failed to uninstall Windows agent service" -ForegroundColor Red
        Write-LogMessage "ERROR" "Failed to uninstall Windows agent service: $($_.Exception.Message)"
    }
}

# Continuous monitoring mode
function Start-ContinuousMonitoring {
    Write-LogMessage "CEG25" "Starting continuous monitoring mode"

    Write-Host "👁️  CONTINUOUS MONITORING MODE ACTIVE" -ForegroundColor Magenta
    Write-Host "Monitoring Windows energy infrastructure for Red Team activity..." -ForegroundColor White
    Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Yellow
    Write-Host ""

    $config = Get-Config
    if ($null -eq $config) { return }

    $interval = $config.monitoring.interval_seconds

    try {
        while ($true) {
            $timestamp = Get-Date -Format "HH:mm:ss"

            Write-Host "[$timestamp] 🔄 Monitoring cycle started..." -ForegroundColor Cyan

            # Monitor security events
            if ($config.monitoring.log_security_events) {
                Watch-SecurityEvents -MaxEvents 3
            }

            # Monitor network connections
            if ($config.monitoring.monitor_network) {
                Watch-NetworkConnections
            }

            # Monitor critical services
            if ($config.monitoring.monitor_services) {
                Watch-CriticalServices
            }

            # Monitor processes
            if ($config.monitoring.monitor_processes) {
                Watch-Processes
            }

            Write-Host "[$timestamp] ✅ Monitoring cycle completed" -ForegroundColor Green
            Write-Host "Next check in $interval seconds..." -ForegroundColor White
            Write-Host ""

            Start-Sleep -Seconds $interval
        }
    }
    catch {
        Write-LogMessage "INFO" "Continuous monitoring stopped"
        Write-Host "Monitoring stopped." -ForegroundColor Yellow
    }
}

# Main execution
function Main {
    Show-Banner
    New-Directories

    switch ($Mode.ToLower()) {
        "monitor" {
            Write-LogMessage "CEG25" "Starting Windows agent monitoring"
            Test-WindowsSecurity
            Watch-SecurityEvents
            Watch-NetworkConnections
            Watch-CriticalServices
            Watch-Processes
            New-WindowsReport
        }
        "continuous" {
            Start-ContinuousMonitoring
        }
        "install" {
            Install-WindowsAgent
        }
        "uninstall" {
            Uninstall-WindowsAgent
        }
        "test" {
            Test-WindowsSecurity
            New-WindowsReport
        }
        "report" {
            New-WindowsReport
        }
        "help" {
            Write-Host "Windows Agent for CEG25 Competition" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "USAGE:" -ForegroundColor White
            Write-Host "  .\windows_agent.ps1 [mode] [options]" -ForegroundColor Gray
            Write-Host ""
            Write-Host "MODES:" -ForegroundColor White
            Write-Host "  monitor     - Run single monitoring cycle (default)" -ForegroundColor Gray
            Write-Host "  continuous  - Start continuous monitoring mode" -ForegroundColor Gray
            Write-Host "  install     - Install as Windows service" -ForegroundColor Gray
            Write-Host "  uninstall   - Uninstall Windows service" -ForegroundColor Gray
            Write-Host "  test        - Test Windows security configuration" -ForegroundColor Gray
            Write-Host "  report      - Generate monitoring report" -ForegroundColor Gray
            Write-Host "  help        - Show this help message" -ForegroundColor Gray
            Write-Host ""
            Write-Host "OPTIONS:" -ForegroundColor White
            Write-Host "  -ConfigFile <file>  - Specify configuration file" -ForegroundColor Gray
            Write-Host ""
            Write-Host "EXAMPLES:" -ForegroundColor White
            Write-Host "  .\windows_agent.ps1 monitor" -ForegroundColor Gray
            Write-Host "  .\windows_agent.ps1 continuous" -ForegroundColor Gray
            Write-Host "  .\windows_agent.ps1 install" -ForegroundColor Gray
            Write-Host "  .\windows_agent.ps1 -Mode test -ConfigFile .\custom_config.json" -ForegroundColor Gray
        }
        default {
            Write-Host "Invalid mode: $Mode" -ForegroundColor Red
            Write-Host "Use 'help' for usage information" -ForegroundColor Yellow
        }
    }
}

# Execute main function
Main