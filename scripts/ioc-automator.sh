#!/usr/bin/env bash
# ioc-automator: framework for file + IP IoC processing

set -euo pipefail
IFS=$'\n\t'

# --------------------------------------------------------------------
# Config
# --------------------------------------------------------------------
FILE_IOC_FEED="${FILE_IOC_FEED:-feeds/file_iocs.sample}"
IP_IOC_FEED="${IP_IOC_FEED:-feeds/ip_iocs.sample}"

# Where to search for suspicious files (lab sandbox by default)
SCAN_ROOT="${SCAN_ROOT:-/tmp/ioc-sandbox}"

# Modes:
#   dry        -> only report what would happen
#   delete     -> delete matching files
#   quarantine -> move matching files to QUARANTINE_DIR
MODE="dry"
QUARANTINE_DIR=""
APPLY_FIREWALL=false
ROLLBACK_FIREWALL=false

# --------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      MODE="dry"
      shift
      ;;
    --delete)
      MODE="delete"
      shift
      ;;
    --quarantine)
      MODE="quarantine"
      QUARANTINE_DIR="$2"
      shift 2
      ;;
    --apply-firewall)
      APPLY_FIREWALL=true
      shift
      ;;
    --rollback-firewall)
      ROLLBACK_FIREWALL=true
      shift
      ;;
    *)
      echo "[!] Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ "$MODE" == "quarantine" && -z "${QUARANTINE_DIR:-}" ]]; then
  echo "[!] Quarantine mode requires a directory: --quarantine /path"
  exit 1
fi

# --------------------------------------------------------------------
# Functions
# --------------------------------------------------------------------

load_file_iocs() {
  local feed="$1"
  local line hash fname

  echo "[*] Loading file IoCs from: $feed"

  if [[ ! -f "$feed" ]]; then
    echo "[!] File IoC feed not found: $feed" >&2
    return 1
  fi

  file_iocs=()   # global array: "hash filename"

  while IFS= read -r line; do
    # skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

    # normalize whitespace
    line="$(echo "$line" | tr -s '[:space:]' ' ')"
    hash="$(echo "$line" | awk '{print $1}')"
    fname="$(echo "$line" | awk '{print $2}')"

    [[ -z "$hash" || -z "$fname" ]] && continue

    file_iocs+=("$hash $fname")
  done < "$feed"

  echo "[*] Loaded ${#file_iocs[@]} file IoCs."
}

load_ip_iocs() {
  local feed="$1"
  local line

  echo "[*] Loading IP IoCs from: $feed"

  if [[ ! -f "$feed" ]]; then
    echo "[!] IP IoC feed not found: $feed" >&2
    return 1
  fi

  ip_iocs=()   # global array: each element is an IP or CIDR

  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    ip_iocs+=("$line")
  done < "$feed"

  echo "[*] Loaded ${#ip_iocs[@]} IP IoCs."
}

normalize_ip_iocs() {
  echo
  echo "[*] Normalizing IP IoCs..."

  # Make a temp file
  TMP_IPS="/tmp/ioc-normalized-ips.txt"
  > "$TMP_IPS"

  # Keep only valid IPv4 or IPv6 + optional CIDR
  for ip in "${ip_iocs[@]}"; do
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
      echo "$ip" >> "$TMP_IPS"
    elif [[ "$ip" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
      echo "$ip" >> "$TMP_IPS"
    fi
  done

  # Remove duplicates
  sort -u "$TMP_IPS" -o "$TMP_IPS"

  # Remove private IP ranges (RFC1918)
  grep -v -E "^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\." "$TMP_IPS" > "${TMP_IPS}.clean"

  mv "${TMP_IPS}.clean" "$TMP_IPS"

  # Overwrite ip_iocs array with cleaned list
  mapfile -t ip_iocs < "$TMP_IPS"

echo "[*] Normalized IP IoCs (after dedupe + private removal): ${#ip_iocs[@]} entries"

# Optional: collapse overlapping CIDRs for efficiency
if command -v aggregate >/dev/null 2>&1; then
  echo "[*] Collapsing overlapping networks using 'aggregate'..."
  printf "%s\n" "${ip_iocs[@]}" | aggregate > "$TMP_IPS.agg" || {
    echo "[!] aggregate failed, keeping original list."
  }
  if [[ -s "$TMP_IPS.agg" ]]; then
    mapfile -t ip_iocs < "$TMP_IPS.agg"
    echo "[*] After aggregation: ${#ip_iocs[@]} entries"
  fi
else
  echo "[*] 'aggregate' not installed, skipping CIDR aggregation."
fi

}

print_ipset_plan() {
apply_firewall() {
  echo
  echo "[*] Applying firewall changes using ipset + iptables"

  if ! command -v ipset >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
    echo "[!] ipset or iptables not found. Install them first." >&2
    return 1
  fi

  # Create or flush the set
  sudo ipset create ioc_blocklist hash:net -exist
  sudo ipset flush ioc_blocklist

  for ip in "${ip_iocs[@]}"; do
    sudo ipset add ioc_blocklist "$ip" -exist
  done

  # Add DROP rules if they are not already present
  if ! sudo iptables -C INPUT -m set --match-set ioc_blocklist src -j DROP 2>/dev/null; then
    sudo iptables -I INPUT -m set --match-set ioc_blocklist src -j DROP
  fi

  if ! sudo iptables -C FORWARD -m set --match-set ioc_blocklist src -j DROP 2>/dev/null; then
    sudo iptables -I FORWARD -m set --match-set ioc_blocklist src -j DROP
  fi

  echo "[*] Firewall rules applied. Current ipset summary:"
  sudo ipset list ioc_blocklist | sed -n '1,20p'
}

  echo
  echo "===== Firewall Dry-Run Plan ====="
  echo "[*] Would create ipset: ioc_blocklist"
  echo "ipset create ioc_blocklist hash:net -exist"

  for ip in "${ip_iocs[@]}"; do
    echo "ipset add ioc_blocklist $ip -exist"
  done

  echo
  echo "[*] Would add iptables DROP rule:"
  echo "iptables -I INPUT -m set --match-set ioc_blocklist src -j DROP"
  echo "iptables -I FORWARD -m set --match-set ioc_blocklist src -j DROP"

  echo "===== End of Plan ====="
}

rollback_firewall() {
  echo
  echo "[*] Rolling back firewall changes for ioc_blocklist"

  if command -v iptables >/dev/null 2>&1; then
    # Remove rules if present
    while sudo iptables -C INPUT -m set --match-set ioc_blocklist src -j DROP 2>/dev/null; do
      sudo iptables -D INPUT -m set --match-set ioc_blocklist src -j DROP
    done
    while sudo iptables -C FORWARD -m set --match-set ioc_blocklist src -j DROP 2>/dev/null; do
      sudo iptables -D FORWARD -m set --match-set ioc_blocklist src -j DROP
    done
  fi

  if command -v ipset >/dev/null 2>&1; then
    sudo ipset destroy ioc_blocklist 2>/dev/null || true
  fi

  echo "[*] Rollback complete."
}

scan_files() {
  echo
  echo "[*] Scanning for malicious files under: $SCAN_ROOT"

  if [[ ! -d "$SCAN_ROOT" ]]; then
    echo "[!] Scan root does not exist: $SCAN_ROOT"
    echo "[!] Create it and place test files there for the lab."
    return 0
  fi

  for entry in "${file_iocs[@]}"; do
    local hash fname
    hash="$(echo "$entry" | awk '{print $1}')"
    fname="$(echo "$entry" | awk '{print $2}')"

    echo "  [*] Looking for filename: $fname with SHA256: $hash"

    # find candidate files by name only under SCAN_ROOT
    while IFS= read -r path; do
      [[ -z "$path" ]] && continue

      if [[ -f "$path" ]]; then
        actual_hash="$(sha256sum "$path" | awk '{print $1}')"

        if [[ "$actual_hash" == "$hash" ]]; then
          echo "      [MATCH] $path (name + hash)."

          case "$MODE" in
            dry)
              echo "          Action: would delete or quarantine (dry run)."
              ;;
            delete)
              echo "          Action: deleting file."
              rm -f "$path"
              ;;
            quarantine)
              mkdir -p "$QUARANTINE_DIR"
              echo "          Action: moving to quarantine ($QUARANTINE_DIR)."
              mv "$path" "$QUARANTINE_DIR/"
              ;;
          esac

        else
          echo "      [NO MATCH] $path (hash mismatch, left unchanged)."
        fi
      fi
    done < <(find "$SCAN_ROOT" -type f -name "$fname" 2>/dev/null)

  done

  echo "[*] File scan completed."
}

print_summary() {
  echo
  echo "===== IoC summary ====="
  echo "File IoCs: ${#file_iocs[@]}"
  echo "IP IoCs:   ${#ip_iocs[@]}"
  echo "Scan root: $SCAN_ROOT"
  echo "Mode:      $MODE"
  if [[ "$MODE" == "quarantine" ]]; then
    echo "Quarantine dir: $QUARANTINE_DIR"
  fi
  echo "======================="
}

main() {
  if "$ROLLBACK_FIREWALL"; then
    rollback_firewall
    return 0
  fi

  load_file_iocs "$FILE_IOC_FEED"
  load_ip_iocs "$IP_IOC_FEED"
  normalize_ip_iocs
  print_summary
  print_ipset_plan

  if "$APPLY_FIREWALL"; then
    apply_firewall
  fi

  scan_files
}

main
