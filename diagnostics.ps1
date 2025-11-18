[CmdletBinding()]
param(
    [switch]$NoGui,
    [string]$LogPath,
    [switch]$SkipAdminCheck,
    [string[]]$RunClientChecks,
    [string[]]$RunServerChecks
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:DiagnosticsScriptRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot
}
elseif ($PSCommandPath) {
    Split-Path -LiteralPath $PSCommandPath -Parent
}
elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -LiteralPath $MyInvocation.MyCommand.Path -Parent
}
else {
    (Get-Location).ProviderPath
}

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $LogPath = Join-Path -Path $script:DiagnosticsScriptRoot -ChildPath 'diagnostics.log'
}
elseif (-not [System.IO.Path]::IsPathRooted($LogPath)) {
    $LogPath = Join-Path -Path $script:DiagnosticsScriptRoot -ChildPath $LogPath
}

function Ensure-AdminPrivileges {
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        throw 'Se requiere PowerShell 3.0 o superior.'
    }
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }

    if ($SkipAdminCheck.IsPresent) {
        return
    }

    if (-not $PSCommandPath) {
        throw 'Se necesitan privilegios de administrador para continuar.'
    }

    Write-Verbose 'Relanzando el script con privilegios elevados.'
    $quotedScript = '"' + $PSCommandPath + '"'
    $arguments = @('-ExecutionPolicy', 'Bypass', '-File', $quotedScript)
    if ($NoGui) { $arguments += '-NoGui' }
    if ($SkipAdminCheck) { $arguments += '-SkipAdminCheck' }
    Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments -Verb RunAs | Out-Null
    exit
}

function New-CheckResult {
    param(
        [Parameter(Mandatory)][ValidateSet('OK','Advertencia','Error')]
        [string]$Status,
        [Parameter(Mandatory)][string]$Details,
        [object]$Data
    )
    [PSCustomObject]@{
        Status = $Status
        Details = $Details
        Data = $Data
    }
}

function Invoke-Diagnostic {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    try {
        $result = & $ScriptBlock
        if (-not $result) {
            $result = New-CheckResult -Status 'OK' -Details 'Sin resultados adicionales.'
        }
        if (-not $result.PSObject.Properties.Match('Status')) {
            $result = New-CheckResult -Status 'OK' -Details ($result | Out-String)
        }
    }
    catch {
        $result = New-CheckResult -Status 'Error' -Details $_.Exception.Message
    }

    $result | Add-Member -NotePropertyName Check -NotePropertyValue $Name -Force
    return $result
}

function Write-ResultsToConsole {
    param(
        [Parameter(Mandatory)][pscustomobject[]]$Results
    )

    foreach ($result in $Results) {
        Write-Host (Convert-ResultToText -Result $result)
    }
}

function Convert-ResultDataToString {
    param([object]$Data)

    if (-not $Data) { return $null }

    try {
        $formatted = $Data | Format-List | Out-String
        return $formatted.TrimEnd()
    }
    catch {
        $raw = ($Data | Out-String).TrimEnd()
        $errorLine = "No se pudo formatear los datos: $($_.Exception.Message)"
        if ($raw) {
            return "$errorLine`n$raw"
        }
        return $errorLine
    }
}

function Convert-ResultToText {
    param(
        [Parameter(Mandatory)][pscustomobject]$Result
    )
    $sb = [System.Text.StringBuilder]::new()
    $header = "[$($Result.Status)] $($Result.Check)"
    [void]$sb.AppendLine($header)
    $details = if ($Result.Details) { $Result.Details } else { '' }
    [void]$sb.AppendLine($details.Trim())
    $dataText = Convert-ResultDataToString -Data $Result.Data
    if ($dataText) {
        [void]$sb.AppendLine($dataText)
    }
    [void]$sb.AppendLine(('-' * 60))
    return $sb.ToString()
}

function Write-LogEntry {
    param(
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('INFO','ADVERTENCIA','ERROR')]
        [string]$Level = 'INFO'
    )

    $lines = $Text -split "`r?`n"
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $entry = "[$timestamp] [$Level] $line"
        Add-Content -Path $LogPath -Value $entry
    }
}

function Write-ResultToLog {
    param(
        [Parameter(Mandatory)][pscustomobject]$Result
    )

    $level = switch ($Result.Status) {
        'Error' { 'ERROR' }
        'Advertencia' { 'ADVERTENCIA' }
        default { 'INFO' }
    }

    $text = Convert-ResultToText -Result $Result
    Write-LogEntry -Text $text -Level $level
}

function Test-IsGuiAvailable {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        return [Environment]::UserInteractive
    }
    catch {
        Write-Verbose "La interfaz gráfica no está disponible: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-Checks {
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$CheckTable,
        [string[]]$SelectedChecks
    )

    $results = @()
    $targets = $SelectedChecks
    if (-not $targets -or $targets.Count -eq 0) {
        $targets = $CheckTable.Keys
    }

    foreach ($checkName in $targets) {
        if (-not $CheckTable.Contains($checkName)) { continue }
        $result = Invoke-Diagnostic -Name $checkName -ScriptBlock $CheckTable[$checkName]
        $results += $result
        Write-ResultToLog -Result $result
    }

    return $results
}

function Show-ConsoleMenu {
    param(
        [System.Collections.Specialized.OrderedDictionary]$ClientChecks,
        [System.Collections.Specialized.OrderedDictionary]$ServerChecks
    )

    while ($true) {
        Write-Host 'Seleccione un menú:' -ForegroundColor Cyan
        Write-Host '1. Cliente' -ForegroundColor Yellow
        Write-Host '2. Servidor' -ForegroundColor Yellow
        Write-Host '3. Salir' -ForegroundColor Yellow
        $choice = Read-Host 'Opción'
        switch ($choice) {
            '1' { Show-ConsoleCheckMenu -Title 'Cliente' -Checks $ClientChecks }
            '2' { Show-ConsoleCheckMenu -Title 'Servidor' -Checks $ServerChecks }
            '3' { return }
            default { Write-Warning 'Opción no válida' }
        }
    }
}

function Show-ConsoleCheckMenu {
    param(
        [string]$Title,
        [System.Collections.Specialized.OrderedDictionary]$Checks
    )

    while ($true) {
        Write-Host "--- Menú $Title ---" -ForegroundColor Cyan
        $index = 1
        foreach ($name in $Checks.Keys) {
            Write-Host "$index. $name"
            $index++
        }
        Write-Host "$index. Ejecutar todos"
        Write-Host "0. Volver"
        $selection = Read-Host 'Opción'
        if ($selection -eq '0') { return }
        $parsed = 0
        if (-not [int]::TryParse($selection, [ref]$parsed)) {
            Write-Warning 'Introduzca un número válido.'
            continue
        }
        if ($parsed -eq $index) {
            $results = Invoke-Checks -CheckTable $Checks
        }
        elseif ($parsed -gt 0 -and $parsed -lt $index) {
            $key = $Checks.Keys[$parsed - 1]
            $results = Invoke-Checks -CheckTable $Checks -SelectedChecks $key
        }
        else {
            Write-Warning 'Selección no válida'
            continue
        }

        foreach ($res in $results) {
            Write-Host (Convert-ResultToText -Result $res)
        }
        Read-Host 'Pulse Enter para continuar'
    }
}

function Show-Gui {
    param(
        [System.Collections.Specialized.OrderedDictionary]$ClientChecks,
        [System.Collections.Specialized.OrderedDictionary]$ServerChecks
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'ITC Diagnostic Toolkit'
    $form.Width = 1000
    $form.Height = 700
    $form.StartPosition = 'CenterScreen'

    $tab = New-Object System.Windows.Forms.TabControl
    $tab.Dock = 'Fill'

    $clientTab = New-Object System.Windows.Forms.TabPage
    $clientTab.Text = 'Cliente'
    $serverTab = New-Object System.Windows.Forms.TabPage
    $serverTab.Text = 'Servidor'

    $clientList = New-Object System.Windows.Forms.CheckedListBox
    $clientList.Dock = 'Left'
    $clientList.Width = 320
    $clientList.CheckOnClick = $true

    foreach ($key in $ClientChecks.Keys) { [void]$clientList.Items.Add($key) }

    $serverList = New-Object System.Windows.Forms.CheckedListBox
    $serverList.Dock = 'Left'
    $serverList.Width = 320
    $serverList.CheckOnClick = $true
    foreach ($key in $ServerChecks.Keys) { [void]$serverList.Items.Add($key) }

    $clientOutput = New-Object System.Windows.Forms.TextBox
    $clientOutput.Multiline = $true
    $clientOutput.ScrollBars = 'Vertical'
    $clientOutput.Dock = 'Fill'

    $serverOutput = New-Object System.Windows.Forms.TextBox
    $serverOutput.Multiline = $true
    $serverOutput.ScrollBars = 'Vertical'
    $serverOutput.Dock = 'Fill'

    $clientPanel = New-Object System.Windows.Forms.Panel
    $clientPanel.Dock = 'Fill'

    $serverPanel = New-Object System.Windows.Forms.Panel
    $serverPanel.Dock = 'Fill'

    $clientButtons = New-Object System.Windows.Forms.FlowLayoutPanel
    $clientButtons.FlowDirection = 'LeftToRight'
    $clientButtons.Height = 40
    $clientButtons.Dock = 'Bottom'

    $serverButtons = New-Object System.Windows.Forms.FlowLayoutPanel
    $serverButtons.FlowDirection = 'LeftToRight'
    $serverButtons.Height = 40
    $serverButtons.Dock = 'Bottom'

    $clientRunSelected = New-Object System.Windows.Forms.Button
    $clientRunSelected.Text = 'Ejecutar selección'
    $clientRunSelected.Width = 150

    $clientRunAll = New-Object System.Windows.Forms.Button
    $clientRunAll.Text = 'Ejecutar todo'
    $clientRunAll.Width = 150

    $serverRunSelected = New-Object System.Windows.Forms.Button
    $serverRunSelected.Text = 'Ejecutar selección'
    $serverRunSelected.Width = 150

    $serverRunAll = New-Object System.Windows.Forms.Button
    $serverRunAll.Text = 'Ejecutar todo'
    $serverRunAll.Width = 150

    $clientButtons.Controls.Add($clientRunSelected)
    $clientButtons.Controls.Add($clientRunAll)
    $serverButtons.Controls.Add($serverRunSelected)
    $serverButtons.Controls.Add($serverRunAll)

    $clientPanel.Controls.Add($clientButtons)
    $clientPanel.Controls.Add($clientOutput)
    $clientPanel.Controls.Add($clientList)
    $serverPanel.Controls.Add($serverButtons)
    $serverPanel.Controls.Add($serverOutput)
    $serverPanel.Controls.Add($serverList)

    $clientTab.Controls.Add($clientPanel)
    $serverTab.Controls.Add($serverPanel)

    $tab.TabPages.AddRange(@($clientTab, $serverTab))
    $form.Controls.Add($tab)

    $runChecks = {
        param($list, $output, $table, $selectedOnly)
        $selected = if ($selectedOnly) {
            $list.CheckedItems | ForEach-Object { $_ }
        } else {
            @()
        }

        if ($selectedOnly -and -not $selected) {
            [System.Windows.Forms.MessageBox]::Show('Seleccione al menos una verificación.', 'ITC Diagnostics') | Out-Null
            return
        }

        $results = Invoke-Checks -CheckTable $table -SelectedChecks $selected
        $text = ($results | ForEach-Object { Convert-ResultToText -Result $_ }) -join [Environment]::NewLine
        $output.Text = $text
    }

    $clientRunSelected.Add_Click({ & $runChecks $clientList $clientOutput $ClientChecks $true })
    $clientRunAll.Add_Click({ & $runChecks $clientList $clientOutput $ClientChecks $false })
    $serverRunSelected.Add_Click({ & $runChecks $serverList $serverOutput $ServerChecks $true })
    $serverRunAll.Add_Click({ & $runChecks $serverList $serverOutput $ServerChecks $false })

    $form.Add_Shown({ $form.Activate() })
    [void]$form.ShowDialog()
}

function Get-DefaultGateway {
    try {
        $gateway = Get-NetIPConfiguration | Select-Object -First 1 -ExpandProperty IPv4DefaultGateway
        if ($gateway -and $gateway.NextHop) { return $gateway.NextHop }
    }
    catch {
        $route = Get-CimInstance -Class Win32_IP4RouteTable | Where-Object { $_.Destination -eq '0.0.0.0' } | Sort-Object Metric1 | Select-Object -First 1
        if ($route) { return $route.NextHop }
    }
    return $null
}

function Get-DomainControllerName {
    $logonServer = $env:LOGONSERVER -replace '^\\\\',''
    if ($logonServer) { return $logonServer }
    try {
        $dc = (nltest /dclist:$env:USERDNSDOMAIN 2>$null | Select-String -Pattern '^\s+\\\\').Line.Trim(' \\') | Select-Object -First 1
        return $dc
    }
    catch {
        return $null
    }
}

function Get-DnsServers {
    try {
        $addresses = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses
        return $addresses | Select-Object -Unique
    }
    catch {
        return @('8.8.8.8','1.1.1.1')
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMilliseconds = 3000
    )
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            $client.Close()
            return $false
        }
        $client.EndConnect($async)
        $client.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Get-ExecutablePath {
    param([Parameter(Mandatory)][string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    if ($cmd.Source) { return $cmd.Source }
    if ($cmd.Path) { return $cmd.Path }
    if ($cmd.Definition) { return $cmd.Definition }
    return $null
}

function Get-LocalCertificates {
    param(
        [string]$Store = 'Cert:\LocalMachine\My'
    )
    try {
        return Get-ChildItem -Path $Store -ErrorAction Stop
    }
    catch {
        return @()
    }
}

$script:DiagnosticConfig = [ordered]@{
    Gateway = Get-DefaultGateway
    DomainController = Get-DomainControllerName
    FileServer = $env:LOGONSERVER -replace '^\\\\',''
    ExchangeDomain = if ($env:USERDNSDOMAIN) { "autodiscover.$($env:USERDNSDOMAIN)" } else { 'autodiscover.outlook.com' }
    PrinterIPs = @()
    CriticalClientServices = @('Dnscache','Dhcp','LanmanWorkstation','LanmanServer','Spooler','wuauserv','Netlogon')
    CriticalServerServices = @('DNS','NTDS','DhcpServer','Netlogon','LanmanServer','W32Time')
    BackupServices = @('VeeamBackupSvc','CobianBackup11')
    HyperVServices = @('vmms','vmcompute')
    CorporateSubnets = @('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')
}

function Join-Array {
    param([object[]]$Values)
    return ($Values -join ', ')
}

$clientChecks = [ordered]@{
    'Interfaz de red' = {
        $adapters = Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object Name, Status, LinkSpeed, MacAddress, MediaConnectionState
        $ipconfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, @{n='IPv4';e={$_.IPv4Address.IPAddress}}, @{n='Gateway';e={$_.IPv4DefaultGateway.NextHop}}, @{n='DNS';e={$_.DNSServer.ServerAddresses -join ', '}}
        $details = "Adaptadores: $($adapters.Count). IPs configuradas: $($ipconfig.Count)."
        New-CheckResult -Status 'OK' -Details $details -Data (@{Adapters=$adapters;IPConfig=$ipconfig})
    }
    'DHCP' = {
        $service = Get-Service -Name 'Dhcp' -ErrorAction SilentlyContinue
        if (-not $service) {
            return New-CheckResult -Status 'Advertencia' -Details 'Servicio DHCP Client no encontrado.'
        }
        $status = if ($service.Status -eq 'Running') { 'OK' } else { 'Advertencia' }
        New-CheckResult -Status $status -Details "DHCP Client: $($service.Status)" -Data $service
    }
    'DNS y resolución' = {
        $targets = @($script:DiagnosticConfig.DomainController, 'microsoft.com') | Where-Object { $_ }
        $results = foreach ($target in $targets) {
            try {
                $entry = Resolve-DnsName -Name $target -ErrorAction Stop | Select-Object -First 1
                "${target}: $($entry.IPAddress)"
            }
            catch {
                "${target}: ERROR $($_.Exception.Message)"
            }
        }
        New-CheckResult -Status 'OK' -Details (Join-Array $results)
    }
    'Ping LAN' = {
        if (-not $script:DiagnosticConfig.Gateway) {
            return New-CheckResult -Status 'Advertencia' -Details 'No se pudo determinar la puerta de enlace.'
        }
        $ping = Test-Connection -ComputerName $script:DiagnosticConfig.Gateway -Count 2 -ErrorAction SilentlyContinue
        if ($ping) {
            $avg = [math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average,2)
            New-CheckResult -Status 'OK' -Details "Gateway $($script:DiagnosticConfig.Gateway) responde. Latencia media ${avg}ms"
        }
        else {
            New-CheckResult -Status 'Error' -Details "No hay respuesta de la puerta de enlace $($script:DiagnosticConfig.Gateway)."
        }
    }
    'Ping Firebox' = {
        if (-not $script:DiagnosticConfig.Gateway) {
            return New-CheckResult -Status 'Advertencia' -Details 'No se pudo determinar la Firebox (se usa gateway).'
        }
        $ping = Test-Connection -ComputerName $script:DiagnosticConfig.Gateway -Count 4 -ErrorAction SilentlyContinue
        if ($ping) {
            New-CheckResult -Status 'OK' -Details "Firebox/Gateway accesible con ${($ping.Count)} respuestas."
        }
        else {
            New-CheckResult -Status 'Error' -Details "Firebox/Gateway sin respuesta."
        }
    }
    'Ping Internet' = {
        $targets = '8.8.8.8','1.1.1.1'
        $results = foreach ($target in $targets) {
            $ping = Test-Connection -ComputerName $target -Count 2 -ErrorAction SilentlyContinue
            if ($ping) {
                $avg = [math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average,2)
                "${target}: OK (${avg}ms)"
            }
            else {
                "${target}: sin respuesta"
            }
        }
        $hasIssue = $results | Where-Object { $_ -like '*sin respuesta*' }
        $status = if ($hasIssue) { 'Advertencia' } else { 'OK' }
        New-CheckResult -Status $status -Details (Join-Array $results)
    }
    'Latencia/pérdida' = {
        $ping = Test-Connection -ComputerName '8.8.8.8' -Count 10 -ErrorAction SilentlyContinue
        if ($ping) {
            $avg = [math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average,2)
            $loss = 100 - (($ping.Count / 10) * 100)
            New-CheckResult -Status 'OK' -Details "Latencia media ${avg}ms. Pérdida ${loss}%"
        }
        else {
            New-CheckResult -Status 'Advertencia' -Details 'No se pudieron medir latencias contra 8.8.8.8'
        }
    }
    'Puertos abiertos' = {
        if (-not $script:DiagnosticConfig.DomainController) {
            return New-CheckResult -Status 'Advertencia' -Details 'No se conoce un servidor destino.'
        }
        $ports = 80,443,445,3389
        $statuses = foreach ($port in $ports) {
            $ok = Test-TcpPort -ComputerName $script:DiagnosticConfig.DomainController -Port $port
            "${port}: $([string](if ($ok) { 'OK' } else { 'Fallo' }))"
        }
        $status = if ($statuses -match 'Fallo') { 'Advertencia' } else { 'OK' }
        New-CheckResult -Status $status -Details (Join-Array $statuses)
    }
    'SMB servidor de archivos' = {
        if (-not $script:DiagnosticConfig.FileServer) {
            return New-CheckResult -Status 'Advertencia' -Details 'No se definió un servidor de archivos.'
        }
        $ok = Test-TcpPort -ComputerName $script:DiagnosticConfig.FileServer -Port 445
        if ($ok) {
            New-CheckResult -Status 'OK' -Details "Conectividad SMB con $($script:DiagnosticConfig.FileServer) confirmada."
        }
        else {
            New-CheckResult -Status 'Error' -Details "No se pudo abrir 445 en $($script:DiagnosticConfig.FileServer)."
        }
    }
    'VPN WatchGuard' = {
        $services = Get-Service -DisplayName '*WatchGuard*VPN*' -ErrorAction SilentlyContinue
        if (-not $services) {
            return New-CheckResult -Status 'Advertencia' -Details 'No se detectaron servicios del cliente VPN.'
        }
        $running = $services | Where-Object { $_.Status -eq 'Running' }
        $status = if ($running) { 'OK' } else { 'Advertencia' }
        $version = (Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*WatchGuard*VPN*' } | Select-Object -First 1).DisplayVersion
        $details = "Servicios activos: $($running.Count)/$($services.Count). Versión: $version"
        New-CheckResult -Status $status -Details $details -Data $services
    }
    'Subred duplicada' = {
        try {
            $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.LinkLayerAddress }
            $duplicates = $neighbors | Group-Object -Property IPAddress | Where-Object { $_.Count -gt 1 }
            if ($duplicates) {
                New-CheckResult -Status 'Advertencia' -Details 'Se detectaron IPs duplicadas en la tabla ARP.' -Data ($duplicates | Select-Object Name,Count,Group)
            }
            else {
                New-CheckResult -Status 'OK' -Details 'Sin IPs duplicadas detectadas en ARP.'
            }
        }
        catch {
            New-CheckResult -Status 'Advertencia' -Details 'No se pudo consultar la tabla ARP.'
        }
    }
    'AD integrado y secure channel' = {
        try {
            $ok = Test-ComputerSecureChannel -ErrorAction Stop
            $status = if ($ok) { 'OK' } else { 'Error' }
            New-CheckResult -Status $status -Details "Secure channel: $ok"
        }
        catch {
            New-CheckResult -Status 'Advertencia' -Details $_.Exception.Message
        }
    }
    'Servicios Windows críticos' = {
        $services = $script:DiagnosticConfig.CriticalClientServices | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
        $problem = $services | Where-Object { $_ -and $_.Status -ne 'Running' }
        if ($problem) {
            New-CheckResult -Status 'Advertencia' -Details ('Servicios detenidos: ' + (Join-Array ($problem.Name))) -Data $services
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Todos los servicios críticos están activos.' -Data $services
        }
    }
    'Perfil usuario correcto' = {
        $profileKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $profile = Get-ChildItem -Path $profileKey | Where-Object { (Get-ItemProperty $_.PSPath).ProfileImagePath -eq $env:USERPROFILE }
        if ($profile) {
            $state = (Get-ItemProperty $profile.PSPath).State
            if ($state -band 0x00000100) {
                New-CheckResult -Status 'Advertencia' -Details 'Perfil temporal detectado.'
            }
            else {
                New-CheckResult -Status 'OK' -Details 'Perfil cargado correctamente.'
            }
        }
        else {
            New-CheckResult -Status 'Advertencia' -Details 'No se pudo validar el perfil del usuario.'
        }
    }
    'Certificados locales' = {
        $certs = Get-LocalCertificates | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) }
        if ($certs) {
            New-CheckResult -Status 'Advertencia' -Details 'Certificados próximos a expirar.' -Data $certs
        }
        else {
            New-CheckResult -Status 'OK' -Details 'No hay certificados próximos a expirar.'
        }
    }
    'Antivirus WatchGuard EPDR' = {
        $services = Get-Service -DisplayName '*WatchGuard*' -ErrorAction SilentlyContinue
        $communication = $services | Where-Object { $_.DisplayName -match 'Communication' -or $_.DisplayName -match 'Endpoint' }
        if (-not $services) {
            return New-CheckResult -Status 'Advertencia' -Details 'No se detectaron servicios de WatchGuard EPDR.'
        }
        $stopped = $services | Where-Object { $_.Status -ne 'Running' }
        $status = if ($stopped) { 'Advertencia' } else { 'OK' }
        $details = if ($stopped) { 'Servicios detenidos: ' + (Join-Array ($stopped.DisplayName)) } else { 'Todos los servicios EPDR están activos.' }
        New-CheckResult -Status $status -Details $details -Data $services
    }
    'Procesos Outlook' = {
        $process = Get-Process -Name 'OUTLOOK' -ErrorAction SilentlyContinue
        if ($process) {
            $hung = $process | Where-Object { $_.Responding -eq $false }
            if ($hung) {
                New-CheckResult -Status 'Advertencia' -Details 'Se detectaron procesos de Outlook no respondientes.' -Data $hung
            }
            else {
                New-CheckResult -Status 'OK' -Details 'Outlook en ejecución sin bloqueos.'
            }
        }
        else {
            New-CheckResult -Status 'Advertencia' -Details 'Outlook no está en ejecución.'
        }
    }
    'Autodiscover' = {
        $host = $script:DiagnosticConfig.ExchangeDomain
        $ok = Test-TcpPort -ComputerName $host -Port 443
        if ($ok) {
            New-CheckResult -Status 'OK' -Details "Autodiscover ($host) accesible en 443."
        }
        else {
            New-CheckResult -Status 'Advertencia' -Details "No se puede abrir 443 contra $host."
        }
    }
    'Impresoras + spooler' = {
        $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
        $printers = @()
        try { $printers = Get-Printer -ErrorAction Stop } catch {}
        $targets = if ($script:DiagnosticConfig.PrinterIPs.Count -gt 0) { $script:DiagnosticConfig.PrinterIPs } else { $printers | Where-Object { $_.PortName -match '\d+\.\d+\.\d+\.\d+' } | Select-Object -ExpandProperty PortName }
        $connectivity = foreach ($target in $targets) {
            if (-not $target) { continue }
            $ping = Test-Connection -ComputerName $target -Count 1 -ErrorAction SilentlyContinue
            "${target}: $([bool]$ping)"
        }
        $status = if ($spooler -and $spooler.Status -eq 'Running') { 'OK' } else { 'Advertencia' }
        New-CheckResult -Status $status -Details ("Spooler: $($spooler.Status). " + (Join-Array $connectivity)) -Data $printers
    }
    'Espacio en disco' = {
        $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, @{n='Libre(GB)';e={[math]::Round($_.FreeSpace/1GB,2)}}, @{n='Total(GB)';e={[math]::Round($_.Size/1GB,2)}}, @{n='% Libre';e={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}
        $low = $disks | Where-Object { $_.'% Libre' -lt 15 }
        if ($low) {
            New-CheckResult -Status 'Advertencia' -Details ('Unidades con poco espacio: ' + (Join-Array ($low.DeviceID))) -Data $disks
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Espacio en disco saludable.' -Data $disks
        }
    }
    'Eventos críticos' = {
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddHours(-48)} -Max 50 -ErrorAction SilentlyContinue
        if ($events) {
            New-CheckResult -Status 'Advertencia' -Details "Se detectaron $($events.Count) eventos críticos en las últimas 48h." -Data ($events | Select-Object TimeCreated,Id,ProviderName,Message)
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Sin eventos críticos recientes.'
        }
    }
}

$serverChecks = [ordered]@{
    'Ping LAN' = {
        $target = $script:DiagnosticConfig.Gateway
        if (-not $target) { return New-CheckResult -Status 'Advertencia' -Details 'Sin gateway detectada.' }
        $ping = Test-Connection -ComputerName $target -Count 2 -ErrorAction SilentlyContinue
        if ($ping) {
            $avg = [math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average,2)
            New-CheckResult -Status 'OK' -Details "Gateway responde con latencia ${avg} ms"
        }
        else {
            New-CheckResult -Status 'Error' -Details 'Sin respuesta de la red local.'
        }
    }
    'DNS funcionando' = {
        $service = Get-Service -Name 'DNS' -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            try {
                $test = Resolve-DnsName -Name 'microsoft.com' -Server '127.0.0.1' -ErrorAction Stop
                New-CheckResult -Status 'OK' -Details 'Servicio DNS operativo.' -Data $test
            }
            catch {
                New-CheckResult -Status 'Advertencia' -Details "DNS operativo pero la resolución falló: $($_.Exception.Message)"
            }
        }
        else {
            New-CheckResult -Status 'Error' -Details 'Servicio DNS detenido.'
        }
    }
    'Replicación AD' = {
        $repadminPath = Get-ExecutablePath -Name 'repadmin.exe'
        if ($repadminPath) {
            $output = & $repadminPath /replsummary 2>&1
            $errors = $output | Select-String 'fails' -SimpleMatch
            $status = if ($errors) { 'Advertencia' } else { 'OK' }
            New-CheckResult -Status $status -Details ($output | Out-String)
        }
        else {
            New-CheckResult -Status 'Advertencia' -Details 'repadmin.exe no disponible.'
        }
    }
    'Servicios críticos' = {
        $services = $script:DiagnosticConfig.CriticalServerServices | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
        $down = $services | Where-Object { $_ -and $_.Status -ne 'Running' }
        if ($down) {
            New-CheckResult -Status 'Advertencia' -Details ('Servicios detenidos: ' + (Join-Array ($down.Name))) -Data $services
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Servicios críticos funcionando.' -Data $services
        }
    }
    'Certificados del servidor' = {
        $certs = Get-LocalCertificates | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) }
        if ($certs) {
            New-CheckResult -Status 'Advertencia' -Details 'Certificados próximos a caducar.' -Data ($certs | Select-Object Subject,NotAfter)
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Todos los certificados vigentes.'
        }
    }
    'Espacio en discos' = {
        $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, @{n='Libre(GB)';e={[math]::Round($_.FreeSpace/1GB,2)}}, @{n='Total(GB)';e={[math]::Round($_.Size/1GB,2)}}, @{n='% Libre';e={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}
        $low = $disks | Where-Object { $_.'% Libre' -lt 15 }
        if ($low) {
            New-CheckResult -Status 'Advertencia' -Details ('Unidades críticas: ' + (Join-Array ($low.DeviceID))) -Data $disks
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Espacio saludable.' -Data $disks
        }
    }
    'RAID (si aplica)' = {
        try {
            $status = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction Stop | Select-Object InstanceName, PredictFailure, Reason
            $failed = $status | Where-Object { $_.PredictFailure }
            if ($failed) {
                New-CheckResult -Status 'Advertencia' -Details 'RAID reporta fallos inminentes.' -Data $failed
            }
            else {
                New-CheckResult -Status 'OK' -Details 'No hay alertas en el RAID.'
            }
        }
        catch {
            New-CheckResult -Status 'Advertencia' -Details 'No se pudo consultar el estado del RAID.'
        }
    }
    'Copias de seguridad' = {
        $services = $script:DiagnosticConfig.BackupServices | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
        $down = $services | Where-Object { $_ -and $_.Status -ne 'Running' }
        if ($down) {
            New-CheckResult -Status 'Advertencia' -Details ('Servicios de backup detenidos: ' + (Join-Array ($down.DisplayName))) -Data $services
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Servicios de backup en ejecución.' -Data $services
        }
    }
    'Salud del AD' = {
        $dcdiagPath = Get-ExecutablePath -Name 'dcdiag.exe'
        if ($dcdiagPath) {
            $output = & $dcdiagPath /q 2>&1
            if ($LASTEXITCODE -eq 0) {
                New-CheckResult -Status 'OK' -Details 'dcdiag sin errores.'
            }
            else {
                New-CheckResult -Status 'Advertencia' -Details ($output | Out-String)
            }
        }
        else {
            New-CheckResult -Status 'Advertencia' -Details 'dcdiag no disponible.'
        }
    }
    'Revisar logs críticos' = {
        $logs = 'System','Application','Directory Service'
        $events = foreach ($log in $logs) {
            Get-WinEvent -FilterHashtable @{LogName=$log; Level=1,2; StartTime=(Get-Date).AddHours(-48)} -Max 30 -ErrorAction SilentlyContinue
        }
        if ($events) {
            New-CheckResult -Status 'Advertencia' -Details "Eventos críticos: $($events.Count)" -Data ($events | Select-Object LogName,TimeCreated,Id,Message)
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Sin eventos críticos recientes.'
        }
    }
    'Comprobación de puertos internos' = {
        $ports = 445,3389,389,53
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $ports -contains $_.LocalPort }
        $listenerPorts = if ($listeners) { $listeners.LocalPort } else { @() }
        $missing = $ports | Where-Object { $listenerPorts -notcontains $_ }
        if ($missing) {
            New-CheckResult -Status 'Advertencia' -Details ('Puertos sin escuchar: ' + (Join-Array $missing)) -Data $listeners
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Puertos críticos escuchando.' -Data $listeners
        }
    }
    'Estado de Hyper-V' = {
        $services = $script:DiagnosticConfig.HyperVServices | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
        $installed = $services | Where-Object { $_ }
        if (-not $installed) {
            return New-CheckResult -Status 'Advertencia' -Details 'Hyper-V no parece instalado.'
        }
        $down = $installed | Where-Object { $_.Status -ne 'Running' }
        if ($down) {
            New-CheckResult -Status 'Advertencia' -Details ('Servicios Hyper-V detenidos: ' + (Join-Array ($down.Name))) -Data $installed
        }
        else {
            New-CheckResult -Status 'OK' -Details 'Hyper-V operativo.' -Data $installed
        }
    }
    'Procesos bloqueados' = {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Responding -eq $false -or $_.CPU -eq 0 }
        if ($processes) {
            New-CheckResult -Status 'Advertencia' -Details 'Procesos potencialmente bloqueados detectados.' -Data ($processes | Select-Object Name,Id,CPU,Responding)
        }
        else {
            New-CheckResult -Status 'OK' -Details 'No se detectaron procesos bloqueados.'
        }
    }
}

if (-not $SkipAdminCheck) {
    Ensure-AdminPrivileges
}

if (-not (Test-Path $LogPath)) {
    New-Item -ItemType File -Path $LogPath -Force | Out-Null
}

$autoRun = $false
$clientSelectionProvided = $PSBoundParameters.ContainsKey('RunClientChecks')
$serverSelectionProvided = $PSBoundParameters.ContainsKey('RunServerChecks')
if ($clientSelectionProvided -and $RunClientChecks -and $RunClientChecks -contains '*') { $RunClientChecks = @() }
if ($serverSelectionProvided -and $RunServerChecks -and $RunServerChecks -contains '*') { $RunServerChecks = @() }

if ($clientSelectionProvided -or $serverSelectionProvided) {
    $autoRun = $true
    if ($clientSelectionProvided) {
        $clientResults = Invoke-Checks -CheckTable $clientChecks -SelectedChecks $RunClientChecks
        Write-Host 'Resultados (Cliente)' -ForegroundColor Cyan
        Write-ResultsToConsole -Results $clientResults
    }
    if ($serverSelectionProvided) {
        $serverResults = Invoke-Checks -CheckTable $serverChecks -SelectedChecks $RunServerChecks
        Write-Host 'Resultados (Servidor)' -ForegroundColor Cyan
        Write-ResultsToConsole -Results $serverResults
    }
}

if (-not $autoRun) {
    if (-not $NoGui -and (Test-IsGuiAvailable)) {
        Show-Gui -ClientChecks $clientChecks -ServerChecks $serverChecks
    }
    else {
        Show-ConsoleMenu -ClientChecks $clientChecks -ServerChecks $serverChecks
    }
}
