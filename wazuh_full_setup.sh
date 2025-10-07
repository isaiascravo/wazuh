#!/usr/bin/env bash
#
# wazuh_full_setup_v2.sh
# Instalação e configuração completa do Wazuh (Ubuntu 24.04)
# para ~50 hosts — coleta rica, limpa e segura.
#
# Autor: @isaiascravo + revisão GPT-5 (Tech & Security Helper)
# Versão: 2.1 (2025-10)
#
# Recursos:
#   - syscollector, vuln-detector, syscheck, rootcheck otimizados
#   - agent.conf por grupo (linux, windows, servers, workstations)
#   - regras de brute-force (AUDIT-ONLY)
#   - script firewall-drop (nftables ou iptables) + whitelist
#   - backups automáticos + validação XML
#   - flags: --dry-run / --enable-ar / --restart
#
# Uso:
#   sudo ./wazuh_full_setup_v2.sh
#   sudo ./wazuh_full_setup_v2.sh --enable-ar --restart
# ============================================================

set -euo pipefail
IFS=$'\n\t'

# ---------------- VARIÁVEIS ----------------
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

RF_SSH_ID=110000
RF_RDP_ID=110001
RF_GEN_ID=110002

# ---------------- PARÂMETROS ----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    --enable-ar) ENABLE_AR=true ;;
    --restart) RESTART=true ;;
    -h|--help)
      echo "Uso: $0 [--dry-run] [--enable-ar] [--restart]"
      exit 0 ;;
    *) echo "Argumento inválido: $1"; exit 1 ;;
  esac
  shift
done

# ---------------- CHECAGENS ----------------
deps=(xmllint grep sed awk mkdir cp mv systemctl)
for b in "${deps[@]}"; do
  command -v "$b" &>/dev/null || { echo "ERRO: comando '$b' não encontrado."; exit 1; }
done

mkdir -p "$BACKUP_DIR"

# ---------------- FUNÇÕES ----------------
log() { echo -e "\e[92m[$(date +%T)]\e[0m $*"; }
warn() { echo -e "\e[93m[$(date +%T)] [WARN]\e[0m $*"; }
err() { echo -e "\e[91m[$(date +%T)] [ERRO]\e[0m $*" >&2; }

insert_block() {
  local tag="$1" block="$2"
  if xmllint --xpath "boolean(//$tag)" "$OSSEC_CONF" &>/dev/null; then
    warn "Bloco <$tag> já existe — pulando."
  elif ! $DRY_RUN; then
    sed -i "/<\/ossec_config>/i\\
$block
" "$OSSEC_CONF"
    log "Inserido <$tag>."
  fi
}

# ---------------- BACKUP ----------------
for f in "$OSSEC_CONF" "$LOCAL_RULES"; do
  [[ -f "$f" ]] && cp -a "$f" "$BACKUP_DIR/$(basename "$f").bak.$TIMESTAMP" && log "Backup: $f"
done

# ---------------- AJUSTES GLOBAIS ----------------
SYS_COLLECTOR='<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>24h</interval>
  <os>yes</os>
  <hardware>yes</hardware>
  <packages>yes</packages>
  <ports all="yes">yes</ports>
  <processes>no</processes>
</wodle>'

VULN_DETECTOR='<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>12h</interval>
  <run_on_start>yes</run_on_start>
  <provider name="canonical">yes</provider>
  <provider name="msu">yes</provider>
  <feed name="nvd" enabled="yes"/>
</vulnerability-detector>'

SYS_CHECK='<syscheck>
  <disabled>no</disabled>
  <scan_on_start>yes</scan_on_start>
  <frequency>10800</frequency>
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin,/var/www</directories>
  <ignore>/tmp,/var/tmp,/run,/var/lib/docker</ignore>
  <skip_nfs>yes</skip_nfs>
</syscheck>'

ROOT_CHECK='<rootcheck>
  <disabled>no</disabled>
</rootcheck>'

insert_block "wodle[@name='syscollector']" "$SYS_COLLECTOR"
insert_block "vulnerability-detector" "$VULN_DETECTOR"
insert_block "syscheck" "$SYS_CHECK"
insert_block "rootcheck" "$ROOT_CHECK"

# ---------------- SHARED CONFIGS ----------------
create_shared_agent_conf() {
  local group="$1" path="$SHARED_DIR/$group/agent.conf"
  mkdir -p "$(dirname "$path")"
  if [[ -f "$path" ]]; then
    warn "$group agent.conf já existe."
    return
  fi
  case "$group" in
    linux)
      cat >"$path"<<'XML'
<agent_config>
  <syscollector><interval>24h</interval></syscollector>
  <syscheck><frequency>10800</frequency><ignore>/tmp,/var/tmp</ignore></syscheck>
  <rootcheck><disabled>no</disabled></rootcheck>
  <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>
</agent_config>
XML
      ;;
    windows)
      cat >"$path"<<'XML'
<agent_config>
  <syscollector><interval>24h</interval></syscollector>
  <localfile><location>Security</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>System</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format></localfile>
</agent_config>
XML
      ;;
  esac
  chmod 640 "$path"
  log "Criado $path"
}

create_shared_agent_conf linux
create_shared_agent_conf windows

# ---------------- REGRAS BRUTEFORCE ----------------
if ! grep -q "### WAZUH_AUTOMATED_BRUTEFORCE_RULES" "$LOCAL_RULES" 2>/dev/null; then
  cat >>"$LOCAL_RULES"<<XML
<!-- ### WAZUH_AUTOMATED_BRUTEFORCE_RULES ### -->
<group name="local,">
  <rule id="$RF_SSH_ID" level="10">
    <match>Failed password|authentication failure</match>
    <same_source_ip>yes</same_source_ip>
    <frequency>5</frequency>
    <timeframe>300</timeframe>
    <description>SSH brute-force detectado (audit-only)</description>
    <group>authentication_failed,bruteforce</group>
  </rule>
  <rule id="$RF_RDP_ID" level="12">
    <match>EventID: 4625</match>
    <same_source_ip>yes</same_source_ip>
    <frequency>5</frequency>
    <timeframe>300</timeframe>
    <description>RDP brute-force detectado (audit-only)</description>
    <group>authentication_failed,bruteforce</group>
  </rule>
</group>
<!-- ### END WAZUH_AUTOMATED_BRUTEFORCE_RULES ### -->
XML
  log "Regras brute-force inseridas."
else
  warn "Regras brute-force já presentes."
fi

# ---------------- FIREWALL SCRIPT (nft/iptables auto) ----------------
mkdir -p "$AR_DIR"
if ! [[ -f "$AR_SCRIPT" ]]; then
  cat >"$AR_SCRIPT"<<'BASH'
#!/usr/bin/env bash
IP="$1"
TIMEOUT="${2:-600}"
TABLE="inet filter"
CHAIN="wazuh-block"
WHITELIST="/var/ossec/active-response/bin/whitelist.txt"

command -v nft >/dev/null 2>&1 && FIREWALL="nft" || FIREWALL="iptables"

if [[ -f "$WHITELIST" && $(grep -E "^$IP" "$WHITELIST") ]]; then
  echo "IP $IP está na whitelist"; exit 0
fi

if [[ "$FIREWALL" == "nft" ]]; then
  nft list table "$TABLE" >/dev/null 2>&1 || nft add table "$TABLE"
  nft list chain "$TABLE" "$CHAIN" >/dev/null 2>&1 || nft add chain "$TABLE" "$CHAIN" "{ type filter hook input priority 0; }"
  nft add rule "$TABLE" "$CHAIN" ip saddr "$IP" drop comment "wazuh-block-$IP"
else
  iptables -C INPUT -s "$IP" -j DROP 2>/dev/null || iptables -I INPUT -s "$IP" -j DROP
fi

(sleep "$TIMEOUT" && { [[ "$FIREWALL" == "nft" ]] && nft delete rule "$TABLE" "$CHAIN" handle "$(nft --handle list chain $TABLE $CHAIN | grep "$IP" | awk '{print $NF}')" || iptables -D INPUT -s "$IP" -j DROP; }) &
BASH
  chmod 750 "$AR_SCRIPT"
  chown root:ossec "$AR_SCRIPT"
  log "Script firewall-drop criado."
fi

# ---------------- WHITELIST ----------------
[[ -f "$WHITELIST" ]] || echo -e "127.0.0.1\n10.0.0.0/8\n192.168.0.0/16" >"$WHITELIST"

# ---------------- ACTIVE-RESPONSE ----------------
if $ENABLE_AR; then
  insert_block "command[name='firewall-drop']" "<command><name>firewall-drop</name><executable>$AR_SCRIPT</executable><timeout_allowed>no</timeout_allowed></command>"
  insert_block "active-response/command[text()='firewall-drop']" "<active-response><command>firewall-drop</command><location>local</location><rules_id>$RF_SSH_ID,$RF_RDP_ID</rules_id><timeout>600</timeout></active-response>"
else
  warn "Active-response não habilitado (--enable-ar ausente)"
fi

# ---------------- VALIDAÇÃO ----------------
xmllint --noout "$OSSEC_CONF" && log "Validação XML OK."

# ---------------- REINÍCIO ----------------
if $RESTART; then
  systemctl restart wazuh-manager && log "wazuh-manager reiniciado."
else
  warn "Use --restart para aplicar as alterações."
fi

log "✅ Setup completo — coleta otimizada e detecção pronta (modo audit-only)."
