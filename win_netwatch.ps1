<#
.SYNOPSIS
    Snapshot network threat scanner.

.DESCRIPTION
    Scans active TCP/UDP connections, flags connections to blacklisted IPs
    and suspicious listening ports commonly abused by malware.

.NOTES
    Author  : Fareed
    Version : 1.0
#>

[CmdletBinding()]
param(
    [string]$BlacklistPath = ".\blacklist.txt",
    [int[]]$SuspiciousPorts = @(21,22,23,135,137,138,139,445,3389,5985,5986),
    [string]$ExportPath = ".\reports\netwatch_report_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

if (-not (Test-Path '.\reports')) {
    New-Item -ItemType Directory -Path '.\reports' | Out-Null
}

$blacklist = @()
if (Test-Path $BlacklistPath) {
    $blacklist = Get-Content -Path $BlacklistPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
}

Write-Host "[+] Gathering active TCP connections..." -ForegroundColor Cyan
$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue

$results = foreach ($conn in $connections) {

    $isBlacklisted = $false
    if ($conn.RemoteAddress -and $conn.RemoteAddress -ne '0.0.0.0') {
        if ($blacklist -contains $conn.RemoteAddress) {
            $isBlacklisted = $true
        }
    }

    $isSuspiciousPort = $false
    if ($SuspiciousPorts -contains $conn.LocalPort -or $SuspiciousPorts -contains $conn.RemotePort) {
        $isSuspiciousPort = $true
    }

    if ($isBlacklisted -or $isSuspiciousPort) {
        [PSCustomObject]@{
            LocalAddress    = $conn.LocalAddress
            LocalPort       = $conn.LocalPort
            RemoteAddress   = $conn.RemoteAddress
            RemotePort      = $conn.RemotePort
            State           = $conn.State
            OwningProcess   = $conn.OwningProcess
            BlacklistedIP   = $isBlacklisted
            SuspiciousPort  = $isSuspiciousPort
        }
    }
}

if (-not $results) {
    Write-Host "[-] No suspicious connections detected in this snapshot." -ForegroundColor Yellow
} else {
    Write-Host "`n[+] Suspicious connections detected:" -ForegroundColor Red
    $results | Format-Table -AutoSize
    $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Report written to $ExportPath" -ForegroundColor Green
}
