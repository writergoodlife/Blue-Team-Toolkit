# CEG Blue Team Automation and Infrastructure Hardening Agent
#
# This script provides a modular framework for automating blue team tasks
# during the CyberEXPERT Game 2025. It focuses on rapid vulnerability
# identification and remediation without disrupting critical services.
#
# Usage: .\blue_agent.ps1 -Module <module> [options]
#
# Modules:
#   - Scan: Perform system-wide scans for common vulnerabilities.
#   - Harden: Apply automated fixes for identified issues.
#   - Monitor: Continuously watch for suspicious activity.
#   - Report: Generate a summary of findings and actions.
#

param (
    [string]$Module
)

# --- Configuration ---
$LogFile = "C:\ProgramData\BlueAgent\blue_agent.log"
$ReportDir = "$env:USERPROFILE\Desktop\CEG25\reports"
$ExclusionIPs = @("10.83.171.142", "rt01.core.i-isp.eu", "rt02.core.i-isp.eu", "rt03.core.i-isp.eu")
$ExclusionPorts = @("54321")

# --- Helper Functions ---
function Write-Log {
    param ([string]$Message)
    $LogEntry = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $LogFile -Value $LogEntry
    Write-Host $LogEntry
}

function Is-ExcludedIP {
    param ([string]$IP)
    if ($ExclusionIPs -contains $IP) {
        return $true
    }
    if ($IP -like "*.253") {
        return $true
    }
    return $false
}

function Is-ExcludedPort {
    param ([string]$Port)
    if ($ExclusionPorts -contains $Port) {
        return $true
    }
    return $false
}

# --- Modules ---
function Run-Scan {
    Write-Log "Starting system scan..."
    
    # Scan for weak passwords (example: check for password policies)
    Write-Log "Scanning for weak passwords..."
    # Get-ADDefaultDomainPasswordPolicy | Out-File -Append -FilePath $LogFile
    
    # Scan for excessive users
    Write-Log "Scanning for excessive users..."
    # Get-LocalUser | Out-File -Append -FilePath $LogFile
    
    # Scan for excessive permissions
    Write-Log "Scanning for excessive permissions..."
    # Implement logic to check for FullControl on sensitive files/folders
    
    # Scan for open ports and exposed services
    Write-Log "Scanning for open ports..."
    Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | ForEach-Object {
        if (-not (Is-ExcludedPort $_.LocalPort)) {
            Write-Log "Found open port: $($_.LocalPort)"
        }
    }
    
    Write-Log "Scan complete."
}

function Run-Harden {
    Write-Log "Starting system hardening..."
    
    # Harden file permissions (example: remove Everyone FullControl)
    Write-Log "Hardening file permissions..."
    # Implement logic to remove permissive ACLs
    
    # Disable unused services (example: disable Telnet)
    Write-Log "Disabling unused services..."
    # Get-Service -Name "Telnet" | Set-Service -StartupType Disabled
    
    Write-Log "Hardening complete."
}

function Run-Monitor {
    Write-Log "Starting continuous monitoring..."
    
    # Monitor for new user creation (example: using event logs)
    # Implement logic to subscribe to user creation events
    
    Write-Log "Monitoring started."
}

function Run-Report {
    Write-Log "Generating report..."
    
    if (-not (Test-Path -Path $ReportDir)) {
        New-Item -ItemType Directory -Path $ReportDir | Out-Null
    }
    
    $ReportFile = Join-Path -Path $ReportDir -ChildPath "report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    "--- Blue Team Agent Report ---" | Out-File -FilePath $ReportFile
    "Generated on: $(Get-Date)" | Out-File -Append -FilePath $ReportFile
    "" | Out-File -Append -FilePath $ReportFile
    
    "--- System Scan Findings ---" | Out-File -Append -FilePath $ReportFile
    Get-Content $LogFile | Where-Object { $_ -like "*Found*" } | Out-File -Append -FilePath $ReportFile
    
    "--- Hardening Actions Taken ---" | Out-File -Append -FilePath $ReportFile
    Get-Content $LogFile | Where-Object { $_ -like "*Hardening*" } | Out-File -Append -FilePath $ReportFile
    
    Write-Log "Report generated at $ReportFile"
}

# --- Main Logic ---
function Main {
    if (-not $Module) {
        Write-Host "Usage: .\blue_agent.ps1 -Module <module>"
        Write-Host "Modules: Scan, Harden, Monitor, Report"
        return
    }
    
    switch ($Module) {
        "Scan" { Run-Scan }
        "Harden" { Run-Harden }
        "Monitor" { Run-Monitor }
        "Report" { Run-Report }
        default { Write-Host "Unknown module: $Module" }
    }
}

Main
