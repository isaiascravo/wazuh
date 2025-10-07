<#
.SYNOPSIS
  Instala Sysmon, aplica configuração SwiftOnSecurity, integra com Wazuh e habilita auditorias/logs conforme CIS.

.NOTES
  - Execute em prompt PowerShell como Administrador.
  - Testado em Windows Server e Windows 10/11.
  - Após rodar, eventos Sysmon, Security e PowerShell serão coletados pelo Wazuh.
#>

# ---------------------- Configurações ----------------------
$ToolsDir      = 'C:\Tools'
$SysmonZip     = Join-Path $ToolsDir 'Sysmon.zip'
$SysmonDir     = Join-Path $ToolsDir 'Sysmon'
$SysmonExe64   = Join-Path $SysmonDir 'Sysmon64.exe'
$SysmonExe32   = Join-Path $SysmonDir 'Sysmon.exe'
$ConfigFile    = Join-Path $ToolsDir 'sysmonconfig.xml'

$SysmonUrl     = 'https://download.sysinternals.com/files/Sysmon.zip'
$ConfigUrl     = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'

$AgentPaths = @(
  'C:\Program Files (x86)\ossec-agent\ossec.conf',
  'C:\Program Files\ossec-agent\ossec.conf',
  'C:\Program Files (x86)\wazuh\ossec.conf',
  'C:\Program Files\Wazuh\agent\ossec.conf'
)
$AgentServiceNames = @('wazuh-agent','wazuh','ossec','WazuhAgent','Wazuh Agent')

Write-Host "### Iniciando configuração Sysmon + Wazuh + Auditoria ###" -ForegroundColor Cyan

# ---------------------- Verificar privilégios ----------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Execute este script como Administrador (Run as Administrator)."
  exit 1
}

# ---------------------- Preparação ----------------------
if (-not (Test-Path $ToolsDir)) { New-Item -Path $ToolsDir -ItemType Directory -Force | Out-Null }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------- Baixar Sysmon ----------------------
if (-not (Test-Path $SysmonExe64) -and -not (Test-Path $SysmonExe32)) {
  Write-Host "Baixando Sysmon..."
  Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonZip -UseBasicParsing
  Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
  Remove-Item $SysmonZip -Force
}

# ---------------------- Baixar configuração ----------------------
Write-Host "Baixando configuração SwiftOnSecurity..."
Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigFile -UseBasicParsing

# ---------------------- Instalar / atualizar Sysmon ----------------------
$sysmonInstalled = Get-Service -Name 'sysmon64' -ErrorAction SilentlyContinue
if ($sysmonInstalled) {
  Write-Host "Sysmon já instalado — atualizando configuração..."
  & $SysmonExe64 -c $ConfigFile
} else {
  Write-Host "Instalando Sysmon..."
  if (Test-Path $SysmonExe64) {
    & $SysmonExe64 -accepteula -i $ConfigFile
  } else {
    & $SysmonExe32 -accepteula -i $ConfigFile
  }
}
Start-Sleep -Seconds 2

# ---------------------- Ajustes CIS de auditoria ----------------------
Write-Host "Aplicando políticas de auditoria padrão CIS..."
auditpol /set /category:* /success:enable /failure:enable | Out-Null

$subs = @(
  "Process Creation", "Process Termination", "File System",
  "Registry", "Logon", "Network Connection"
)
foreach ($s in $subs) { auditpol /set /subcategory:"$s" /success:enable /failure:disable | Out-Null }

wevtutil sl Security /e:true
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /e:true
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /e:true

# ---------------------- PowerShell Logging ----------------------
Write-Host "Ativando logs de PowerShell (ScriptBlock e Transcription)..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\Logs\PowerShell" -PropertyType String -Force | Out-Null
if (-not (Test-Path "C:\Logs\PowerShell")) { New-Item -ItemType Directory -Path "C:\Logs\PowerShell" -Force | Out-Null }

# ---------------------- Integração com Wazuh ----------------------
function Find-OssecConf {
  param([string[]]$paths)
  foreach ($p in $paths) { if (Test-Path $p) { return (Resolve-Path $p).ProviderPath } }
  return $null
}
$ossecConf = Find-OssecConf -paths $AgentPaths
if (-not $ossecConf) {
  Write-Warning "ossec.conf não encontrado — buscando em C:\ ..."
  $found = Get-ChildItem -Path 'C:\' -Filter ossec.conf -Recurse -ErrorAction SilentlyContinue -Force -Depth 3 | Select-Object -First 1
  if ($found) { $ossecConf = $found.FullName }
}

if ($ossecConf) {
  Write-Host "Integrando Sysmon + Security + PowerShell ao Wazuh..."
  [xml]$xml = Get-Content $ossecConf
  $entries = @(
    @{loc="Microsoft-Windows-Sysmon/Operational"; fmt="eventchannel"},
    @{loc="Security"; fmt="eventchannel"},
    @{loc="Microsoft-Windows-PowerShell/Operational"; fmt="eventchannel"}
  )
  foreach ($e in $entries) {
    $exists = $xml.ossec_config.localfile | Where-Object { $_.location -eq $e.loc }
    if (-not $exists) {
      $lf = $xml.CreateElement("localfile")
      $loc = $xml.CreateElement("location"); $loc.InnerText = $e.loc
      $fmt = $xml.CreateElement("log_format"); $fmt.InnerText = $e.fmt
      $lf.AppendChild($loc) | Out-Null
      $lf.AppendChild($fmt) | Out-Null
      $xml.ossec_config.AppendChild($lf) | Out-Null
    }
  }
  $xml.Save($ossecConf)
  Write-Host "ossec.conf atualizado."
  foreach ($name in $AgentServiceNames) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {
      Restart-Service -Name $svc.Name -Force
      Write-Host "Serviço $($svc.Name) reiniciado."
      break
    }
  }
} else {
  Write-Warning "ossec.conf não encontrado. Adicione manualmente estes blocos:"
  @"
<localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>
<localfile><location>Security</location><log_format>eventchannel</log_format></localfile>
<localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format></localfile>
"@ | Write-Host
}

# ---------------------- Verificação final ----------------------
Write-Host ""
Write-Host "### Verificação pós-instalação ###" -ForegroundColor Yellow

# Sysmon status
$sysmonStatus = Get-Service sysmon64 -ErrorAction SilentlyContinue
if ($sysmonStatus) {
  Write-Host ("Sysmon: {0} (PID {1})" -f $sysmonStatus.Status, (Get-Process sysmon64 -ErrorAction SilentlyContinue).Id)
} else {
  Write-Warning "Sysmon não encontrado como serviço ativo."
}

# Wazuh status
$wazuhSvc = $null
foreach ($name in $AgentServiceNames) {
  $wazuhSvc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($wazuhSvc) { break }
}
if ($wazuhSvc) {
  Write-Host ("Wazuh Agent: {0}" -f $wazuhSvc.Status)
} else {
  Write-Warning "Serviço do Wazuh não encontrado."
}

# Últimos eventos Sysmon
Write-Host "`nÚltimos 5 eventos Sysmon:" -ForegroundColor Cyan
try {
  $events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 -ErrorAction Stop
  if ($events) {
    $events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -AutoSize
  } else {
    Write-Warning "Nenhum evento Sysmon encontrado ainda — aguarde alguns minutos."
  }
} catch {
  Write-Warning ("Erro ao ler eventos Sysmon: {0}" -f $_.Exception.Message)
}

Write-Host ""
Write-Host "### Configuração completa e validada. ###" -ForegroundColor Green
