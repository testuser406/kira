<#
 Kira - native Windows control script (no Docker).
   .\scripts\windows\kira.ps1 build      compile the Rust services and the web dashboard
   .\scripts\windows\kira.ps1 init       create the bundled PostgreSQL cluster (once)
   .\scripts\windows\kira.ps1 start      start PostgreSQL, collector and API
   .\scripts\windows\kira.ps1 stop       stop everything
   .\scripts\windows\kira.ps1 status     show what is running and the collector counters
   .\scripts\windows\kira.ps1 doctor     diagnose why logs are not arriving (add -Fix to apply safe fixes)
   .\scripts\windows\kira.ps1 firewall   open 8080 and 5514 on Domain/Private profiles (run as Administrator)
   .\scripts\windows\kira.ps1 autostart  start Kira when this user logs on
 Works in Windows PowerShell 5.1 and PowerShell 7. Settings come from kira.env in the repository root.
#>
param([Parameter(Position = 0)][ValidateSet('build', 'init', 'start', 'stop', 'status', 'doctor', 'firewall', 'autostart')][string]$Command = 'status', [switch]$Fix)
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
        $val = $t.Substring($i + 1)
        # Strip trailing inline comments (whitespace + #); a # without leading space stays part of the value.
        $val = ($val -replace '\s+#.*$', '').Trim()
        $map[$t.Substring(0, $i).Trim()] = $val
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
        $hport = if ($cfg['HEALTH_ADDR']) { ($cfg['HEALTH_ADDR'] -split ':')[-1] } else { '8081' }
        $env:INGEST_METRICS_URL = "http://127.0.0.1:$hport/metrics"
        if (-not $env:RUST_LOG) { $env:RUST_LOG = 'info' }

        if (Test-PgRunning $pgBin) {
            Write-Host 'PostgreSQL already running.'
        } else {
            Write-Host 'Starting PostgreSQL...' -ForegroundColor Cyan
            # A fresh log file name per start avoids "Permission denied" when an old server still holds postgres.log
            $pgLog = Join-Path $Logs ('postgres-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
            & (Join-Path $pgBin 'pg_ctl.exe') -D $PgData -l $pgLog -o "-p $port -c listen_addresses=127.0.0.1" -w start
            if ($LASTEXITCODE -ne 0) {
                # A just-stopped server can still hold files for a moment (or antivirus scans them): retry once.
                Write-Warning 'PostgreSQL did not start; retrying in 5 seconds...'
                Start-Sleep -Seconds 5
                $pgLog = Join-Path $Logs ('postgres-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
                & (Join-Path $pgBin 'pg_ctl.exe') -D $PgData -l $pgLog -o "-p $port -c listen_addresses=127.0.0.1" -w start
                if ($LASTEXITCODE -ne 0) {
                    if (Test-Path $pgLog) { Get-Content $pgLog -Tail 15 | ForEach-Object { Write-Host "  pg: $_" -ForegroundColor Yellow } }
                    throw "PostgreSQL failed to start. See $pgLog. If it says 'Access is denied', run PowerShell as the same user that ran init, and exclude the .runtime folder from antivirus."
                }
            }
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

    'doctor' {
        $cfg = Read-KiraEnv
        $pgBin = Find-PgBin $cfg
        $problems = New-Object System.Collections.ArrayList
        function Ok($m) { Write-Host "  [ OK ] $m" -ForegroundColor Green }
        function Bad($m, $fix) { Write-Host "  [FAIL] $m" -ForegroundColor Red; if ($fix) { Write-Host "         -> $fix" -ForegroundColor Yellow }; [void]$problems.Add($m) }
        function Warn($m, $fix) { Write-Host "  [WARN] $m" -ForegroundColor Yellow; if ($fix) { Write-Host "         -> $fix" -ForegroundColor Yellow } }
        $sysPort = if ($cfg['SYSLOG_UDP_ADDR']) { ($cfg['SYSLOG_UDP_ADDR'] -split ':')[-1] } else { '5514' }
        $hp = if ($cfg['HEALTH_ADDR']) { ($cfg['HEALTH_ADDR'] -split ':')[-1] } else { '8081' }

        Write-Host "`n1. Services"
        if (Test-PgRunning $pgBin) { Ok 'PostgreSQL is running' } else { Bad 'PostgreSQL is stopped' "run: .\scripts\windows\kira.ps1 start" }
        foreach ($n in 'ingest', 'api') {
            $f = Join-Path $Pids "$n.pid"
            $p = if (Test-Path $f) { Get-Process -Id ([int](Get-Content $f -Raw)) -ErrorAction SilentlyContinue } else { $null }
            if ($p) { Ok "$n is running (PID $($p.Id))" } else { Bad "$n is not running" "run: .\scripts\windows\kira.ps1 start (details: .runtime\logs\$n*.err.log)" }
        }

        Write-Host "`n2. Ports on this PC"
        # A collector that was just (re)started needs a few seconds before it listens.
        $udp = $null
        for ($w = 0; $w -lt 6 -and -not $udp; $w++) { $udp = Get-NetUDPEndpoint -LocalPort ([int]$sysPort) -ErrorAction SilentlyContinue; if (-not $udp) { Start-Sleep -Seconds 2 } }
        if ($udp) { Ok "UDP $sysPort is listening (PID $(($udp | Select-Object -First 1).OwningProcess))" } else { Bad "UDP $sysPort is not listening" 'start Kira, or another program may own the port: Get-NetUDPEndpoint -LocalPort 5514' }
        $tcp = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
        if ($tcp) { Ok 'Dashboard TCP 8080 is listening' } else { Bad 'Dashboard TCP 8080 is not listening' 'start Kira and check .runtime\logs\api.err.log' }

        Write-Host "`n3. Windows Firewall and network profile"
        $prof = Get-NetConnectionProfile -ErrorAction SilentlyContinue
        foreach ($c in $prof) {
            if ($c.NetworkCategory -eq 'Public') { Warn "Network '$($c.Name)' is Public - Kira's rules only apply to Domain/Private" "Settings > Network & internet > set the network profile to Private (or: Set-NetConnectionProfile -InterfaceIndex $($c.InterfaceIndex) -NetworkCategory Private as Administrator)" }
            else { Ok "Network '$($c.Name)' profile: $($c.NetworkCategory)" }
        }
        $rules = Get-NetFirewallRule -DisplayName 'Kira*' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' }
        if ($rules.Count -ge 3) { Ok "$($rules.Count) Kira firewall rules are enabled" } else { Bad 'Kira firewall rules are missing or disabled' "run as Administrator: .\scripts\windows\kira.ps1 firewall (or: kira.ps1 doctor -Fix)" }

        Write-Host "`n4. Is data arriving? (two samples, 10 s apart)"
        $m1 = $null; $m2 = $null
        try { $m1 = Invoke-RestMethod "http://127.0.0.1:$hp/metrics" -TimeoutSec 3; Start-Sleep -Seconds 10; $m2 = Invoke-RestMethod "http://127.0.0.1:$hp/metrics" -TimeoutSec 3 } catch { Bad 'collector metrics unavailable (collector not running?)' 'run: .\scripts\windows\kira.ps1 start' }
        if ($m2) {
            Write-Host ("  datagrams={0} parsed={1} rejected={2} denied_sources={3} written={4} db_errors={5} dropped={6} queue={7}%" -f $m2.datagrams, $m2.parsed, $m2.rejected, $m2.denied_sources, $m2.written, $m2.db_errors, $m2.dropped, [math]::Round($m2.queue_utilization_percent))
            if ($m2.datagrams -eq 0 -and $m2.lines -eq 0) { Bad 'Nothing has ever reached the collector' "check firewall rules above, the Sophos syslog server entry (this PC's IP, port $sysPort, UDP, 'Device standard'), and that logging is enabled on the firewall rules" }
            elseif (($m2.datagrams + $m2.lines) -le ($m1.datagrams + $m1.lines)) { Warn 'No new syslog in the last 10 s' 'Sophos may be idle, or sending stopped; generate traffic and re-run' } else { Ok 'Syslog is arriving' }
            if ($m2.denied_sources -gt 0) { Bad "$($m2.denied_sources) datagrams from sources not in ALLOWED_SOURCES" 'edit kira.env: add the Sophos IP to ALLOWED_SOURCES (or leave empty), then stop/start' }
            if ($m2.rejected -gt 0 -and $m2.parsed -eq 0) { Bad 'Logs arrive but none can be parsed' "set Sophos syslog format to 'Device standard'" }
            if ($m2.db_errors -gt 0 -or $m2.dropped -gt 0) { Bad "database errors=$($m2.db_errors), dropped=$($m2.dropped)" 'see section 6 for the error lines; check disk space' }
            elseif ($m2.written -gt $m1.written) { Ok 'Events are being written to the database' }
        }

        Write-Host "`n5. Newest stored event"
        $psql = Join-Path $pgBin 'psql.exe'
        $pw = Get-DbPassword $cfg
        if ((Test-Path $psql) -and $pw) {
            $port = if ($cfg['PG_PORT']) { $cfg['PG_PORT'] } else { '55432' }
            $env:PGPASSWORD = $pw
            $r = & $psql -h 127.0.0.1 -p $port -U $DbUser -d $DbName -Atc "SELECT now() - max(ts), max(ts) FROM events" 2>&1
            Write-Host "  age / timestamp: $r"
            if ($r -match '^-') { Warn 'Newest event is in the FUTURE: firewall clock or time zone differs from Kira' 'set DEFAULT_TZ_OFFSET_MINUTES in kira.env (e.g. 300 for UTC+5) and fix the firewall time zone' }
            Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
        } else { Warn 'psql or database password not found; skipped' }

        Write-Host "`n6. Recent errors in logs"
        $hits = Get-ChildItem $Logs -Filter '*.err.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | ForEach-Object { Select-String -Path $_.FullName -Pattern 'ERROR|failed|panick|cannot bind|dropp' | Select-Object -Last 5 }
        if ($hits) { $hits | ForEach-Object { Write-Host "  $($_.Filename): $($_.Line.Substring(0, [math]::Min(200, $_.Line.Length)))" -ForegroundColor Yellow } } else { Ok 'no recent errors' }
        $cidr = Get-ChildItem $Logs -Filter 'ingest*.err.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { Select-String -Path $_.FullName -Pattern 'invalid CIDR' | Select-Object -Last 1 }
        if ($cidr) { Bad 'kira.env has an invalid ALLOWED_SOURCES value, so the collector refuses to start' 'edit kira.env: ALLOWED_SOURCES must be IPs/CIDRs separated by commas (e.g. 172.16.0.210), then run kira.ps1 start' }
        $d = Get-PSDrive -Name ($Root.Substring(0, 1)) -ErrorAction SilentlyContinue
        if ($d -and $d.Free -lt 2GB) { Bad ("only {0:N1} GB free on {1}:" -f ($d.Free / 1GB), $d.Name) 'free disk space; PostgreSQL stops writing when the disk is full' }

        Write-Host ''
        if ($problems.Count -eq 0) { Write-Host 'No blocking problem found.' -ForegroundColor Green }
        else {
            Write-Host "$($problems.Count) problem(s) found." -ForegroundColor Red
            if ($Fix) {
                Write-Host 'Applying safe fixes: start missing services, open firewall (if Administrator)...'
                & $PSCommandPath start
                $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if ($admin) { & $PSCommandPath firewall } else { Write-Warning 'Not Administrator: firewall rules were not changed. Re-run in an Administrator PowerShell.' }
            } else { Write-Host 'Run again with -Fix to restart services and open the firewall.' }
        }
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
