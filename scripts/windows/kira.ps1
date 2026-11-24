<#
 Kira - native Windows control script (no Docker).
   .\scripts\windows\kira.ps1 build      compile the Rust services and the web dashboard
   .\scripts\windows\kira.ps1 init       create the bundled PostgreSQL cluster (once)
   .\scripts\windows\kira.ps1 start      start PostgreSQL, collector and API
   .\scripts\windows\kira.ps1 stop       stop everything
   .\scripts\windows\kira.ps1 status     show what is running and the collector counters
   .\scripts\windows\kira.ps1 firewall   open 8080 and 5514 on Domain/Private profiles (run as Administrator)
   .\scripts\windows\kira.ps1 autostart  start Kira when this user logs on
 Works in Windows PowerShell 5.1 and PowerShell 7. Settings come from kira.env in the repository root.
#>
param([Parameter(Position = 0)][ValidateSet('build', 'init', 'start', 'stop', 'status', 'firewall', 'autostart')][string]$Command = 'status')
$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Runtime = Join-Path $Root '.runtime'
$Logs = Join-Path $Runtime 'logs'
$Pids = Join-Path $Runtime 'pids'
$PgData = Join-Path $Runtime 'pgdata'
$EnvFile = Join-Path $Root 'kira.env'
$DbName = 'sfos'
$DbUser = 'kira'

function Read-KiraEnv {
    if (-not (Test-Path $EnvFile)) { throw "kira.env not found. Copy kira.env.example to kira.env and edit it." }
    $map = @{}
    foreach ($line in Get-Content $EnvFile) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $i = $t.IndexOf('=')
        if ($i -lt 1) { continue }
        $map[$t.Substring(0, $i).Trim()] = $t.Substring($i + 1).Trim()
    }
    return $map
}

function Find-PgBin($cfg) {
    $candidates = @()
    if ($cfg['PG_BIN']) { $candidates += $cfg['PG_BIN'] }
    $onPath = Get-Command pg_ctl.exe -ErrorAction SilentlyContinue
    if ($onPath) { $candidates += (Split-Path $onPath.Source) }
    $globs = @(
        (Join-Path $Runtime 'postgres\*\bin'),
        'C:\Program Files\PostgreSQL\*\bin',
        'C:\Program Files (x86)\PostgreSQL\*\bin',
        'C:\PostgreSQL\*\bin',
        (Join-Path $env:USERPROFILE '*\.runtime\postgres\*\bin'),
        (Join-Path $env:USERPROFILE 'Documents\*\.runtime\postgres\*\bin')
    )
    foreach ($g in $globs) {
        $candidates += (Get-ChildItem -Path $g -Directory -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | ForEach-Object { $_.FullName })
    }
    foreach ($c in $candidates) { if ($c -and (Test-Path (Join-Path $c 'pg_ctl.exe'))) { Write-Host "Using PostgreSQL binaries in $c"; return $c } }
    throw @"
PostgreSQL binaries (pg_ctl.exe, initdb.exe) were not found.
Install PostgreSQL 16 or 17:   winget install PostgreSQL.PostgreSQL.17
then open a NEW PowerShell and run this again. If PostgreSQL is already somewhere else,
set PG_BIN=<folder containing pg_ctl.exe> in kira.env.
"@
}

function Get-DbPassword($cfg) {
    if ($cfg['DB_PASSWORD']) { return $cfg['DB_PASSWORD'] }
    $f = Join-Path $Runtime 'db.pass'
    if (Test-Path $f) { return (Get-Content $f -Raw).Trim() }
    return $null
}

function Test-PgRunning($pgBin) {
    & (Join-Path $pgBin 'pg_ctl.exe') -D $PgData status *> $null
    return ($LASTEXITCODE -eq 0)
}

function Stop-KiraProcess($name) {
    $pidFile = Join-Path $Pids "$name.pid"
    if (Test-Path $pidFile) {
        $p = [int](Get-Content $pidFile -Raw)
        $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -like 'sfos-*') {
            Write-Host "Stopping $name (PID $p)"
            Stop-Process -Id $p -Force
        }
        Remove-Item $pidFile -Force
    }
}

function Start-KiraProcess($name, $exe, $logBase) {
    $pidFile = Join-Path $Pids "$name.pid"
    if (Test-Path $pidFile) {
        $old = Get-Process -Id ([int](Get-Content $pidFile -Raw)) -ErrorAction SilentlyContinue
        if ($old -and $old.ProcessName -like 'sfos-*') { Write-Host "$name already running (PID $($old.Id))"; return }
    }
    # Windows refuses the same file for stdout and stderr, so each gets its own log.
    $p = Start-Process -FilePath $exe -WorkingDirectory $Root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Logs "$logBase.out.log") `
        -RedirectStandardError (Join-Path $Logs "$logBase.err.log")
    Set-Content -Path $pidFile -Value $p.Id
    Write-Host "Started $name (PID $($p.Id)), logs: .runtime\logs\$logBase.*.log"
}

switch ($Command) {
    'build' {
        Push-Location $Root
        try {
            Write-Host '== cargo build --release' -ForegroundColor Cyan
            cargo build --release --locked
            if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
            Write-Host '== dashboard' -ForegroundColor Cyan
            npm --prefix web ci --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
            npm --prefix web run build
            if ($LASTEXITCODE -ne 0) { throw 'npm run build failed' }
            Write-Host 'Build finished.' -ForegroundColor Green
        } finally { Pop-Location }
    }

    'init' {
        $cfg = Read-KiraEnv
        $pgBin = Find-PgBin $cfg
        New-Item -ItemType Directory -Force $Runtime, $Logs, $Pids | Out-Null
        if (Test-Path (Join-Path $PgData 'PG_VERSION')) { Write-Host 'Database cluster already exists.'; break }
        $pw = $cfg['DB_PASSWORD']
        if (-not $pw) {
            $pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 28 | ForEach-Object { [char]$_ })
            Set-Content -Path (Join-Path $Runtime 'db.pass') -Value $pw -NoNewline
            Write-Host 'Generated a database password and saved it in .runtime\db.pass'
        }
        $pwFile = Join-Path $Runtime 'initdb.pw'
        Set-Content -Path $pwFile -Value $pw -NoNewline
        try {
            & (Join-Path $pgBin 'initdb.exe') -D $PgData -U $DbUser -A scram-sha-256 --pwfile=$pwFile -E UTF8
            if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
        } finally { Remove-Item $pwFile -Force -ErrorAction SilentlyContinue }
        $port = if ($cfg['PG_PORT']) { $cfg['PG_PORT'] } else { '55432' }
        & (Join-Path $pgBin 'pg_ctl.exe') -D $PgData -l (Join-Path $Logs 'postgres.log') -o "-p $port -c listen_addresses=127.0.0.1" -w start
        $env:PGPASSWORD = $pw
        & (Join-Path $pgBin 'createdb.exe') -h 127.0.0.1 -p $port -U $DbUser $DbName
        & (Join-Path $pgBin 'pg_ctl.exe') -D $PgData -m fast -w stop
        Write-Host "Database initialised. Next: .\scripts\windows\kira.ps1 start" -ForegroundColor Green
    }

    'start' {
        $cfg = Read-KiraEnv
        $pgBin = Find-PgBin $cfg
        $pw = Get-DbPassword $cfg
        if (-not $pw -or -not (Test-Path (Join-Path $PgData 'PG_VERSION'))) { throw "Run '.\scripts\windows\kira.ps1 init' first." }
        $api = Join-Path $Root 'target\release\sfos-api.exe'
        $ingest = Join-Path $Root 'target\release\sfos-ingest.exe'
        if (-not (Test-Path $api) -or -not (Test-Path $ingest) -or -not (Test-Path (Join-Path $Root 'web\dist\index.html'))) {
            throw "Not built yet. Run '.\scripts\windows\kira.ps1 build' first."
        }
        New-Item -ItemType Directory -Force $Logs, $Pids | Out-Null
        $port = if ($cfg['PG_PORT']) { $cfg['PG_PORT'] } else { '55432' }

        # Everything in kira.env becomes an environment variable for the child processes.
        foreach ($k in $cfg.Keys) { if ($cfg[$k] -ne '') { Set-Item -Path "Env:$k" -Value $cfg[$k] } }
        $env:DATABASE_URL = "postgres://${DbUser}@127.0.0.1:${port}/${DbName}"
        $env:DATABASE_PASSWORD = $pw
        $env:WEB_DIR = Join-Path $Root 'web\dist'
        if (-not $env:RUST_LOG) { $env:RUST_LOG = 'info' }

        if (Test-PgRunning $pgBin) {
            Write-Host 'PostgreSQL already running.'
        } else {
            Write-Host 'Starting PostgreSQL...' -ForegroundColor Cyan
            # A fresh log file name per start avoids "Permission denied" when an old server still holds postgres.log
            $pgLog = Join-Path $Logs ('postgres-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
            & (Join-Path $pgBin 'pg_ctl.exe') -D $PgData -l $pgLog -o "-p $port -c listen_addresses=127.0.0.1" -w start
            if ($LASTEXITCODE -ne 0) { throw "PostgreSQL failed to start. See $pgLog" }
        }

        Start-KiraProcess 'ingest' $ingest 'ingest'
        Start-Sleep -Seconds 2
        Start-KiraProcess 'api' $api 'api'

        $healthPort = ($env:API_ADDR -split ':')[-1]
        $ready = $false
        for ($i = 0; $i -lt 60; $i++) {
            try { Invoke-RestMethod "http://127.0.0.1:$healthPort/healthz" -TimeoutSec 2 | Out-Null; $ready = $true; break } catch { Start-Sleep -Milliseconds 500 }
        }
        if (-not $ready) { Write-Warning "API did not answer on port $healthPort. Check .runtime\logs\api.err.log"; break }
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress
        if (-not $ip) { $ip = 'localhost' }
        Write-Host ''
        Write-Host '=== Kira is running ===' -ForegroundColor Green
        Write-Host "Dashboard : http://${ip}:${healthPort}   (sign in as $($cfg['ADMIN_USERNAME']))"
        Write-Host "Syslog    : udp/tcp ${ip}:$(($env:SYSLOG_UDP_ADDR -split ':')[-1])  (Sophos > System > Logging > Syslog servers)"
        Write-Host "Collector : http://${ip}:$(($env:HEALTH_ADDR -split ':')[-1])/metrics"
    }

    'stop' {
        $cfg = Read-KiraEnv
        Stop-KiraProcess 'api'
        Stop-KiraProcess 'ingest'
        $pgBin = Find-PgBin $cfg
        if (Test-PgRunning $pgBin) {
            Write-Host 'Stopping PostgreSQL'
            & (Join-Path $pgBin 'pg_ctl.exe') -D $PgData -m fast -w stop
        }
        Write-Host 'Stopped.' -ForegroundColor Green
    }

    'status' {
        $cfg = Read-KiraEnv
        $pgBin = Find-PgBin $cfg
        Write-Host ("PostgreSQL : " + $(if (Test-PgRunning $pgBin) { 'running' } else { 'stopped' }))
        foreach ($n in 'ingest', 'api') {
            $f = Join-Path $Pids "$n.pid"
            $p = if (Test-Path $f) { Get-Process -Id ([int](Get-Content $f -Raw)) -ErrorAction SilentlyContinue } else { $null }
            Write-Host ("{0,-11}: {1}" -f $n, $(if ($p) { "running (PID $($p.Id))" } else { 'stopped' }))
        }
        $hp = if ($cfg['HEALTH_ADDR']) { ($cfg['HEALTH_ADDR'] -split ':')[-1] } else { '8081' }
        try { (Invoke-RestMethod "http://127.0.0.1:$hp/metrics" -TimeoutSec 3) | ConvertTo-Json -Compress | Write-Host } catch { Write-Host 'collector metrics unavailable' }
    }

    'firewall' {
        $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $admin) { throw 'Run this in an Administrator PowerShell.' }
        $rules = @(
            @{ n = 'Kira Dashboard 8080'; p = 'TCP'; port = 8080 },
            @{ n = 'Kira Syslog UDP 5514'; p = 'UDP'; port = 5514 },
            @{ n = 'Kira Syslog TCP 5514'; p = 'TCP'; port = 5514 }
        )
        foreach ($r in $rules) {
            Remove-NetFirewallRule -DisplayName $r.n -ErrorAction SilentlyContinue
            # Domain and Private only: never the Public profile.
            New-NetFirewallRule -DisplayName $r.n -Direction Inbound -Action Allow -Protocol $r.p -LocalPort $r.port -Profile Domain, Private | Out-Null
            Write-Host "Opened $($r.p) $($r.port) (Domain, Private)"
        }
        Write-Host 'Tip: restrict the syslog rules to the firewall address with -RemoteAddress in the Windows Firewall console.'
    }

    'autostart' {
        $script = Join-Path $PSScriptRoot 'kira.ps1'
        $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`" start"
        schtasks /Create /F /SC ONLOGON /RL LIMITED /TN 'Kira' /TR $action | Out-Host
        Write-Host "Kira will start when $env:USERNAME logs on. Remove with: schtasks /Delete /TN Kira /F"
    }
}
