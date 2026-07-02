<#
.SYNOPSIS
    Dynamic Remediation and Eradication Script for Unauthorized Monitoring Tool (Net Monitor for Employees Pro)
    Target: Automated PID Discovery based on Process Names and Network Port 4495
.DESCRIPTION
    This script dynamically tracks and terminates suspected processes, deletes associated 
    Windows services, purges binary files from the disk, and enforces strict firewall block rules.
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Starting Intelligent Threat Eradication Script..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Array to collect all discovered suspicious PIDs
$TargetPIDs = @()

# A) Discover PIDs based on known process names
$ProcessNames = @("nmep_ctrlagent", "nmep_agent", "nmep_ctrlagentsvc")
foreach ($ProcName in $ProcessNames) {
    $Procs = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
    if ($Procs) {
        foreach ($P in $Procs) {
            $TargetPIDs += $P.Id
            Write-Host "[+] Process identified by name: $ProcName with ID (PID: $($P.Id))" -ForegroundColor Yellow
        }
    }
}

# B) Discover PIDs based on Port 4495 activity (to capture renamed malicious binaries)
try {
    $NetworkConnections = Get-NetTCPConnection -LocalPort 4495 -ErrorAction SilentlyContinue
    if ($NetworkConnections) {
        foreach ($Conn in $NetworkConnections) {
            if ($Conn.OwningProcess -and $Conn.OwningProcess -ne 0) {
                $TargetPIDs += $Conn.OwningProcess
                Write-Host "[+] Process identified by network port 4495 activity with ID (PID: $($Conn.OwningProcess))" -ForegroundColor Yellow
            }
        }
    }
} catch {
    Write-Host "[-] Error encountered while scanning network connections on Port 4495." -ForegroundColor Red
}

# Remove duplicate entries from the gathered PID list
$TargetPIDs = $TargetPIDs | Select-Object -Unique

# 1. Enforce termination of all discovered active processes
if ($TargetPIDs.Count -gt 0) {
    Write-Host "[*] Terminating identified processes..." -ForegroundColor Cyan
    foreach ($PID in $TargetPIDs) {
        if (Get-Process -Id $PID -ErrorAction SilentlyContinue) {
            try {
                Stop-Process -Id $PID -Force
                Write-Host "[+] Process with ID (PID: $PID) successfully terminated." -ForegroundColor Green
            } catch {
                Write-Host "[-] Failed to force terminate process with ID (PID: $PID)." -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "[+] No active target processes found in memory." -ForegroundColor Green
}

# 2. Stop and Delete Windows Services via Service Control Manager (SCM)
$ServiceNames = @("nlnme_ctrlagent", "nmep_ctrlagent", "nmep_agent", "NetMonitorEmployees")
foreach ($Svc in $ServiceNames) {
    if (Get-Service -Name $Svc -ErrorAction SilentlyContinue) {
        Write-Host "[!] Target service found: $Svc. Stopping and removing..." -ForegroundColor Yellow
        try {
            Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue
            sc.exe delete $Svc | Out-Null
            Write-Host "[+] Service successfully deleted: $Svc" -ForegroundColor Green
        } catch {
            Write-Host "[-] Error occurred while removing service: $Svc" -ForegroundColor Red
        }
    }
}

# 3. Clean and Block Network Port 4495
Write-Host "[*] Auditing and removing old firewall rules for Port 4495..." -ForegroundColor Cyan
$BadRules = Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Net Monitor*" -or $_.DisplayName -like "*nmep*" -or $_.DisplayName -like "*nlnme*"}
if ($BadRules) {
    foreach ($Rule in $BadRules) {
        Remove-NetFirewallRule -Name $Rule.Name
        Write-Host "[+] Removed legacy firewall rule: $($Rule.DisplayName)" -ForegroundColor Green
    }
}

Write-Host "[*] Creating explicit inbound/outbound BLOCK rules for Port 4495..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "BLOCK_Unauthorized_4495_In" -Direction Inbound -LocalPort 4495 -Protocol TCP -Action Block | Out-Null
New-NetFirewallRule -DisplayName "BLOCK_Unauthorized_4495_Out" -Direction Outbound -LocalPort 4495 -Protocol TCP -Action Block | Out-Null
Write-Host "[+] Port 4495 has been successfully blocked in both directions." -ForegroundColor Green

# 4. Purge Binary Files and Remaining Folders from Disk
$TargetPaths = @(
    "C:\Windows\SysWOW64\nlnme",
    "C:\Windows\System32\nlnme",
    "$env:ProgramFiles\nlnme",
    "$env:ProgramFiles (x86)\nlnme",
    "$env:ProgramData\nlnme"
)

foreach ($Path in $TargetPaths) {
    if (Test-Path $Path) {
        Write-Host "[!] Artifact folder found on disk: $Path. Deleting..." -ForegroundColor Yellow
        try {
            Remove-Item -Path $Path -Recurse -Force
            Write-Host "[+] Folder successfully purged: $Path" -ForegroundColor Green
        } catch {
            Write-Host "[-] Error occurred while trying to delete folder: $Path" -ForegroundColor Red
        }
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[+] Threat eradication completed successfully!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
