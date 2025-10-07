#!/usr/bin/env bash
#
# wazuh_full_setup.sh
# Instalações/ajustes de coleta Wazuh (Ubuntu 24.04) para ~50 hosts:
#  - Ajustes globais (syscollector, vulnerability-detector, syscheck, rootcheck)
#  - Cria shared agent.conf para grupos: linux, windows, servers, workstations
#  - Adiciona regras de brute-force (AUDIT-ONLY) em local_rules.xml
#  - Cria script de active-response (nftables) e whitelist (não habilitado por padrão)
#  - Backups, idempotência, dry-run, validação XML e opção --enable-ar / --restart
#
# USO:
#   sudo ./wazuh_full_setup.sh                -> aplica em modo audit-only (padrão)
#   sudo ./wazuh_full_setup.sh --dry-run      -> mostra o que faria
#   sudo ./wazuh_full_setup.sh --enable-ar    -> ativa também active-response (cuidado)
#   sudo ./wazuh_full_setup.sh --restart      -> reinicia wazuh-manager no fim
#
set -euo pipefail
IFS=$'\n\t'

# ======================= CONFIGURAÇÃO =======================
OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
SHARED_DIR="/var/ossec/etc/shared"
BACKUP_DIR="/var/ossec/etc/backups"
AR_DIR="/var/ossec/active-response/bin"
WHITELIST="$AR_DIR/whitelist.txt"
AR_SCRIPT="$AR_DIR/firewall-drop.sh"
TIMESTAMP="$(date +%F_%H-%M-%S)"

DRY_RUN=false
ENABLE_AR=false
RESTART=false

# IDs das regras criadas (verifique conflitos no seu ambiente)
RF_SSH_ID="110000"
RF_RDP_ID="110001"
RF_GEN_ID="110002"

# =============================================================
log(){ echo "[$(date +%T)] $*"; }

usage(){
  cat <<EOF
Uso: $0 [--dry-run] [--enable-ar] [--restart]
  --dry-run    : não aplica mudanças (apenas mostra)
  --enable-ar  : habilita active-response (adiciona command + active-response)
  --restart    : reinicia wazuh-manager no final
EOF
  exit 1
}

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --enable-ar) ENABLE_AR=true; shift ;;
    --restart) RESTART=true; shift ;;
    -h|--help) usage ;;
    *) echo "Parâmetro inválido: $1"; usage ;;
  esac
done

# ======================= CHECAGENS =======================
for bin in xmllint sed awk nft grep mkdir cp mv systemctl; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    log "ERRO: comando '$bin' não encontrado. Instale antes (ex: apt install libxml2-utils nftables sed awk grep coreutils systemd)."
    exit 1
  fi
done

# ======================= BACKUPS =======================
mkdir -p "$BACKUP_DIR"
if [[ -f "$OSSEC_CONF" ]]; then
  cp -a "$OSSEC_CONF" "$BACKUP_DIR/ossec.conf.bak.$TIMESTAMP"
  log "Backup: $OSSEC_CONF -> $BACKUP_DIR/ossec.conf.bak.$TIMESTAMP"
fi
if [[ -f "$LOCAL_RULES" ]]; then
  cp -a "$LOCAL_RULES" "$BACKUP_DIR/local_rules.xml.bak.$TIMESTAMP"
  log "Backup: $LOCAL_RULES -> $BACKUP_DIR/local_rules.xml.bak.$TIMESTAMP"
fi

# ======================= FUNÇÕES PARA INSERÇÃO SEGURA =======================
insert_if_missing() {
  # insert BLOCK before closing </ossec_config> if TAG not present (xpath style via xmllint)
  local TAG_XPATH="$1"   # ex: wodle[@name='syscollector']
  local BLOCK="$2"
  if xmllint --xpath "boolean(//$TAG_XPATH)" "$OSSEC_CONF" 2>/dev/null; then
    log "Bloco //${TAG_XPATH} já presente em ossec.conf — pulando inserção."
  else
    log "Inserindo bloco //${TAG_XPATH} em ossec.conf..."
    if $DRY_RUN; then
      echo "DRYRUN: inserir bloco:"
      echo "$BLOCK"
    else
      sed -i "/<\/ossec_config>/i\\
$BLOCK
" "$OSSEC_CONF"
    fi
  fi
}

append_marker_rules() {
  local MARKER_START="### WAZUH_AUTOMATED_BRUTEFORCE_RULES ###"
  local MARKER_END="### END WAZUH_AUTOMATED_BRUTEFORCE_RULES ###"
  if [[ -f "$LOCAL_RULES" && $(grep -F "$MARKER_START" "$LOCAL_RULES" 2>/dev/null || true) ]]; then
    log "local_rules.xml já contém regras automatizadas — pulando append."
  else
    log "Adicionando regras de brute-force em $LOCAL_RULES ..."
    if $DRY_RUN; then
      echo "DRYRUN: adicionar bloco ao $LOCAL_RULES"
    else
      mkdir -p "$(dirname "$LOCAL_RULES")"
      cat >> "$LOCAL_RULES" <<XML
<!-- $MARKER_START -->
<group name="local,">
  <rule id="$RF_SSH_ID" level="10">
    <match>Failed password</match>
    <same_source_ip>yes</same_source_ip>
    <frequency>5</frequency>
    <timeframe>300</timeframe>
    <description>Brute force SSH detectado: 5 falhas em 5 minutos (AUDIT-ONLY)</description>
    <group>authentication_failed,bruteforce</group>
    <options>no_full_log</options>
  </rule>

  <rule id="$RF_RDP_ID" level="12">
    <match>EventID: 4625</match>
    <same_source_ip>yes</same_source_ip>
    <frequency>5</frequency>
    <timeframe>300</timeframe>
    <description>Brute force RDP/Windows detectado: 5 falhas em 5 minutos (AUDIT-ONLY)</description>
    <group>authentication_failed,bruteforce</group>
    <options>no_full_log</options>
  </rule>

  <rule id="$RF_GEN_ID" level="12">
    <if_matched_sid>0</if_matched_sid>
    <same_source_ip>yes</same_source_ip>
    <frequency>10</frequency>
    <timeframe>600</timeframe>
    <description>Brute force genérico (10 tentativas em 10 minutos) (AUDIT-ONLY)</description>
    <group>authentication_failed,bruteforce</group>
    <options>no_full_log</options>
  </rule>
</group>
<!-- $MARKER_END -->
XML
    fi
  fi
}

# ======================= BLOCO: Ajustes globais em ossec.conf =======================
SYS_COLLECTOR_BLOCK='<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>24h</interval>
  <os>yes</os>
  <hardware>yes</hardware>
  <packages>yes</packages>
  <ports all="yes">yes</ports>
  <processes>no</processes>
</wodle>'

VULN_DETECTOR_BLOCK='<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>12h</interval>
  <run_on_start>yes</run_on_start>
  <provider name="canonical">yes</provider>
  <provider name="msu">yes</provider>
  <feed name="nvd" enabled="yes"/>
</vulnerability-detector>'

SYS_CHECK_BLOCK='<syscheck>
  <disabled>no</disabled>
  <scan_on_start>yes</scan_on_start>
  <frequency>10800</frequency> <!-- 3h -->
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories check_all="yes">/var/www</directories>
  <ignore>/tmp,/var/tmp</ignore>
  <skip_nfs>yes</skip_nfs>
</syscheck>'

ROOT_CHECK_BLOCK='<rootcheck>
  <disabled>no</disabled>
</rootcheck>'

# Inserir os blocos de forma segura
insert_if_missing "wodle[@name='syscollector']" "$SYS_COLLECTOR_BLOCK"
insert_if_missing "vulnerability-detector" "$VULN_DETECTOR_BLOCK"
insert_if_missing "syscheck" "$SYS_CHECK_BLOCK"
insert_if_missing "rootcheck" "$ROOT_CHECK_BLOCK"

# ======================= BLOCO: shared agent.conf por grupo =======================
# Função para criar agent.conf por grupo (idempotente)
create_shared_agent_conf() {
  local GROUP="$1"
  local PATH_CONF="$SHARED_DIR/$GROUP/agent.conf"
  if [[ -f "$PATH_CONF" ]]; then
    log "agent.conf para grupo '$GROUP' já existe em $PATH_CONF — pulando."
    return 0
  fi
  log "Criando agent.conf para grupo '$GROUP' em $PATH_CONF ..."
  if $DRY_RUN; then
    echo "DRYRUN: criação $PATH_CONF"
    return 0
  fi
  mkdir -p "$(dirname "$PATH_CONF")"
  case "$GROUP" in
    linux)
      cat > "$PATH_CONF" <<'XML'
<agent_config>
  <syscollector>
    <disabled>no</disabled>
    <interval>24h</interval>
    <hardware>yes</hardware>
    <os>yes</os>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>no</processes>
  </syscollector>

  <syscheck>
    <disabled>no</disabled>
    <frequency>10800</frequency>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/var/www</directories>
    <ignore>/tmp,/var/tmp</ignore>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</agent_config>
XML
    ;;
    windows)
      cat > "$PATH_CONF" <<'XML'
<agent_config>
  <syscollector>
    <disabled>no</disabled>
    <interval>24h</interval>
    <hardware>yes</hardware>
    <os>yes</os>
    <packages>yes</packages>
  </syscollector>

  <syscheck>
    <disabled>no</disabled>
    <frequency>21600</frequency>
    <directories check_all="yes">C:\Windows\System32</directories>
    <directories check_all="yes">C:\Program Files</directories>
    <ignore>C:\Windows\Temp</ignore>
  </syscheck>

  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
XML
    ;;
    servers)
      cat > "$PATH_CONF" <<'XML'
<agent_config>
  <syscheck>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin,/var/www</directories>
    <frequency>10800</frequency>
  </syscheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</agent_config>
XML
    ;;
    workstations)
      cat > "$PATH_CONF" <<'XML'
<agent_config>
  <syscollector>
    <interval>24h</interval>
  </syscollector>

  <syscheck>
    <frequency>43200</frequency> <!-- 12h -->
    <directories check_all="yes">/etc</directories>
  </syscheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</agent_config>
XML
    ;;
    *)
      log "Grupo desconhecido: $GROUP — pulando."
      return 0
    ;;
  esac
  chmod 640 "$PATH_CONF" || true
  log "Criado $PATH_CONF"
}

create_shared_agent_conf linux
create_shared_agent_conf windows
create_shared_agent_conf servers
create_shared_agent_conf workstations

# ======================= BLOCO: Regras Brute-force (audit-only) =======================
append_marker_rules

# ======================= BLOCO: Criar active-response script e whitelist (mas não ativar por padrão) =======================
create_ar_script() {
  if [[ -f "$AR_SCRIPT" && $(grep -F "wazuh-block" "$AR_SCRIPT" 2>/dev/null || true) ]]; then
    log "Script AR já existe em $AR_SCRIPT — pulando."
  else
    log "Criando script active-response em $AR_SCRIPT ..."
    if $DRY_RUN; then
      echo "DRYRUN: criar $AR_SCRIPT"
    else
      mkdir -p "$AR_DIR"
      cat > "$AR_SCRIPT" <<'SH'
#!/usr/bin/env bash
IP="$1"
TIMEOUT="${2:-600}"
TABLE="inet filter"
CHAIN="wazuh-block"
WHITELIST="/var/ossec/active-response/bin/whitelist.txt"

if [[ -z "$IP" ]]; then
  echo "No IP provided" >&2; exit 1
fi

# whitelist basic check
if [[ -f "$WHITELIST" ]]; then
  if grep -qE "^($IP|$IP/|$(echo $IP | sed 's/\\./\\\\./g'))" "$WHITELIST"; then
    echo "IP $IP on whitelist — skipping"
    exit 0
  fi
fi

nft list table "$TABLE" >/dev/null 2>&1 || nft add table "$TABLE"
nft list chain "$TABLE" "$CHAIN" >/dev/null 2>&1 || nft add chain "$TABLE" "$CHAIN" '{ type filter hook input priority 0 ; }'

if nft list chain "$TABLE" "$CHAIN" -a | grep -q "$IP"; then
  echo "IP $IP already blocked"; exit 0
fi

nft add rule "$TABLE" "$CHAIN" ip saddr "$IP" drop comment "wazuh-block-$IP"

# schedule removal after timeout
(
  sleep "$TIMEOUT"
  nft list chain "$TABLE" "$CHAIN" -a | awk -v ip="$IP" '/wazuh-block-/{print $1}' | while read -r handle; do
    nft delete rule "$TABLE" "$CHAIN" handle "$handle" 2>/dev/null || true
  done
) &

exit 0
SH
      chmod 750 "$AR_SCRIPT"
      chown root:ossec "$AR_SCRIPT" || true
      log "Script AR criado."
    fi
  fi

  if [[ -f "$WHITELIST" ]]; then
    log "Whitelist já existe em $WHITELIST"
  else
    log "Criando whitelist em $WHITELIST ..."
    if $DRY_RUN; then
      echo "DRYRUN: criar $WHITELIST"
    else
      cat > "$WHITELIST" <<WL
10.0.0.0/8
192.168.0.0/16
127.0.0.1
# Adicione IPs/CIDRs seguros
WL
      chmod 640 "$WHITELIST"
      chown root:ossec "$WHITELIST" || true
      log "Whitelist criada em $WHITELIST"
    fi
  fi
}

create_ar_script

# ======================= BLOCO: Inserir <command> e <active-response> em ossec.conf (somente se --enable-ar) =======================
if $ENABLE_AR; then
  # Insere <command> firewall-drop se não existir
  if xmllint --xpath "boolean(//command[name='firewall-drop'])" "$OSSEC_CONF" 2>/dev/null; then
    log "<command> firewall-drop já presente — pulando inserção."
  else
    log "Inserindo <command> firewall-drop em ossec.conf ..."
    if $DRY_RUN; then
      echo "DRYRUN: inserir <command> firewall-drop"
    else
      sed -i "/<\/ossec_config>/i\\
  <command>\\
    <name>firewall-drop</name>\\
    <executable>/var/ossec/active-response/bin/firewall-drop.sh</executable>\\
    <timeout_allowed>no</timeout_allowed>\\
  </command>\\
" "$OSSEC_CONF"
    fi
  fi

  # Insere bloco <active-response> se não existir
  if xmllint --xpath "boolean(//active-response/command[text()='firewall-drop'])" "$OSSEC_CONF" 2>/dev/null; then
    log "<active-response> para firewall-drop já presente — pulando."
  else
    log "Inserindo <active-response> para firewall-drop ..."
    if $DRY_RUN; then
      echo "DRYRUN: inserir <active-response> firewall-drop"
    else
      sed -i "/<\/ossec_config>/i\\
  <active-response>\\
    <command>firewall-drop</command>\\
    <location>local</location>\\
    <rules_id>$RF_RDP_ID,$RF_GEN_ID</rules_id>\\
    <timeout>600</timeout>\\
  </active-response>\\
" "$OSSEC_CONF"
    fi
  fi
else
  log "ENABLE_AR não habilitado — active-response NÃO será inserido."
fi

# ======================= VALIDAÇÃO XML =======================
if $DRY_RUN; then
  log "DRY-RUN ativado; pulando validação final e reinício."
  exit 0
fi

if xmllint --noout "$OSSEC_CONF" 2>/dev/null; then
  log "Validação XML: OK"
else
  log "ERRO: ossec.conf inválido após alterações. Restaurando backup e abortando."
  cp -a "$BACKUP_DIR/ossec.conf.bak.$TIMESTAMP" "$OSSEC_CONF"
  exit 1
fi

# ======================= PERMISSÕES =======================
chown -R root:ossec /var/ossec/active-response || true
chmod 750 "$AR_SCRIPT" || true

# ======================= REINÍCIO (opcional) =======================
if $RESTART; then
  if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    log "Reiniciando wazuh-manager..."
    systemctl restart wazuh-manager && log "wazuh-manager reiniciado."
  else
    log "wazuh-manager não está ativo ou systemctl não disponível; reinício manual necessário."
  fi
else
  log "Reinício não solicitado (--restart não usado)."
fi

log "Concluído. Ações aplicadas:"
log " - Ajustes globais inseridos (syscollector, vuln-detector, syscheck, rootcheck)"
log " - agent.conf criados para grupos: linux, windows, servers, workstations (se não existentes)"
log " - Regras de brute-force adicionadas em modo AUDIT-ONLY (IDs: $RF_SSH_ID, $RF_RDP_ID, $RF_GEN_ID)"
log " - Script de active-response e whitelist criados (não ativados a menos que --enable-ar)"
log "Recomendações: rodar em modo audit-only por 7-14 dias, ajustar thresholds e whitelists antes de habilitar bloqueios automáticos."
