<#
.SYNOPSIS
    CookieGuard ETW & Filesystem Real-Time Monitor for Windows
.DESCRIPTION
    Monitorea en tiempo real cualquier intento de lectura o copia de los almacenes
    de cookies y Local State en perfiles de Chrome, Edge, Brave y Firefox.
#>

param (
    [switch]$AudioAlert = $true
)

$Host.UI.RawUI.WindowTitle = "CookieGuard - Windows Real-Time Monitor"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " 🛡️  CookieGuard - Monitor en Tiempo Real para Windows" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$ProfilePaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
    "$env:APPDATA\Mozilla\Firefox\Profiles"
)

$ValidBrowsers = @("chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "python.exe")

$Watchers = @()

foreach ($BasePath in $ProfilePaths) {
    if (Test-Path $BasePath) {
        $Watcher = New-Object System.IO.FileSystemWatcher
        $Watcher.Path = $BasePath
        $Watcher.IncludeSubdirectories = $true
        $Watcher.EnableRaisingEvents = $true
        $Watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastAccess

        $Action = {
            $Path = $Event.SourceEventArgs.FullPath
            $Name = $Event.SourceEventArgs.Name
            $ChangeType = $Event.SourceEventArgs.ChangeType

            if ($Path -like "*Cookies*" -or $Path -like "*Local State*" -or $Path -like "*cookies.sqlite*") {
                $Time = Get-Date -Format "HH:mm:ss"
                Write-Host "[$Time] 🚨 ACCESO SOSPECHOSO DETECTADO!" -ForegroundColor Red
                Write-Host "  Ruta: $Path" -ForegroundColor Yellow
                Write-Host "  Tipo: $ChangeType" -ForegroundColor Gray

                if ($AudioAlert) {
                    [Console]::Beep(1200, 250)
                }
            }
        }

        Register-ObjectEvent $Watcher "Changed" -Action $Action | Out-Null
        Register-ObjectEvent $Watcher "Created" -Action $Action | Out-Null
        $Watchers += $Watcher
        Write-Host "[+] Vigilando: $BasePath" -ForegroundColor Green
    }
}

Write-Host "`n[✓] Sensor activo. Presiona Ctrl+C para detener.`n" -ForegroundColor Cyan

try {
    while ($true) { Start-Sleep -Seconds 1 }
} finally {
    foreach ($w in $Watchers) {
        $w.EnableRaisingEvents = $false
        $w.Dispose()
    }
    Get-EventSubscriber | Unregister-Event
    Write-Host "`n[!] Sensor detenido." -ForegroundColor Yellow
}
