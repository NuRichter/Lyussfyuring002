#!/usr/bin/env bash
# -------------------------------------------------------------------
# Lyussfyuring002 :: recon.sh
# full passive+active recon pipeline
# requires: Arch Linux or Kali Linux
# -------------------------------------------------------------------

set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
MAG='\033[0;35m'
RST='\033[0m'

LYUSS_BIN="./lyuss"
OUT_DIR="./recon_out"
WORDLIST="/usr/share/wordlists/dirb/common.txt"

usage() {
  cat <<EOF
Usage: $0 [options] <target>

Options:
  -o <dir>      output directory (default: ./recon_out/<target>)
  -w <wordlist> wordlist for fuzzing (default: /usr/share/wordlists/dirb/common.txt)
  -k <key>      Shodan API key
  -p            passive mode only (no active fuzzing)
  -h            show this help

Example:
  $0 -k YOUR_SHODAN_KEY example.com
EOF
  exit 1
}

log_info()  { echo -e "${CYN}[*]${RST} $*"; }
log_ok()    { echo -e "${GRN}[+]${RST} $*"; }
log_warn()  { echo -e "${YLW}[!]${RST} $*"; }
log_error() { echo -e "${RED}[x]${RST} $*" >&2; }

check_distro() {
  if [[ -f /etc/arch-release ]]; then
    log_ok "distro: Arch Linux"
  elif grep -qi 'kali' /etc/os-release 2>/dev/null; then
    log_ok "distro: Kali Linux"
  else
    log_warn "unsupported distro: Lyussfyuring002 is designed for Arch or Kali Linux"
    read -rp "continue anyway? [y/N] " yn
    [[ "$yn" =~ ^[Yy]$ ]] || exit 1
  fi
}

check_deps() {
  local missing=()
  for dep in curl whois dig nmap ruby go; do
    command -v "$dep" &>/dev/null || missing+=("$dep")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "missing dependencies: ${missing[*]}"
    log_info  "install on Arch: sudo pacman -S ${missing[*]}"
    log_info  "install on Kali: sudo apt install ${missing[*]}"
    exit 1
  fi
  log_ok "all dependencies present"
}

build_go() {
  if [[ ! -x "$LYUSS_BIN" ]]; then
    log_info "building lyuss binary..."
    go build -o "$LYUSS_BIN" ./cmd/lyuss/
    log_ok "build complete: $LYUSS_BIN"
  fi
}

PASSIVE=false
SHODAN_KEY=""
TARGET=""

while getopts "o:w:k:ph" opt; do
  case "$opt" in
    o) OUT_DIR="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    k) SHODAN_KEY="$OPTARG" ;;
    p) PASSIVE=true ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

TARGET="${1:-}"
[[ -z "$TARGET" ]] && { log_error "target required"; usage; }

OUTD="${OUT_DIR}/${TARGET//:/_}"
mkdir -p "$OUTD"

log_info "output directory: $OUTD"

banner() {
  echo -e "${MAG}"
  cat <<'BANNER'
  _                        _____
 | |    _   _ _   _ ___ ___|  ___/\_   _ _ __(_)_ __   __ _
 | |   | | | | | | / __/ __| |_  / /  | | '__| | '_ \ / _` |
 | |___| |_| | |_| \__ \__ \  _|/ /   | | |  | | | | | (_| |
 |_____|\__, |\__,_|___/___/_| /_/    |_|_|  |_|_| |_|\__, |
        |___/                                           |___/
  Lyussfyuring002 :: recon.sh
BANNER
  echo -e "${RST}"
}

banner
check_distro
check_deps
build_go

# 1. WHOIS
log_info "step 1/7: WHOIS"
whois "$TARGET" > "$OUTD/whois.txt" 2>/dev/null && log_ok "whois saved"

# 2. DNS
log_info "step 2/7: DNS enumeration"
{
  echo "=== A ==="
  dig +short A "$TARGET"
  echo "=== MX ==="
  dig +short MX "$TARGET"
  echo "=== NS ==="
  dig +short NS "$TARGET"
  echo "=== TXT ==="
  dig +short TXT "$TARGET"
  echo "=== CNAME ==="
  dig +short CNAME "$TARGET"
} > "$OUTD/dns.txt"
log_ok "DNS records saved"

# 3. OSINT Harvest
log_info "step 3/7: OSINT harvest (Go)"
"$LYUSS_BIN" harvest "$TARGET" --passive > "$OUTD/harvest.txt" 2>&1 || true
log_ok "harvest saved"

# 4. OWASP Scan
log_info "step 4/7: OWASP TOP 10 scan"
"$LYUSS_BIN" owasp "https://${TARGET}" --full > "$OUTD/owasp.txt" 2>&1 || true
log_ok "OWASP findings saved"

# 5. Nikto (Ruby)
log_info "step 5/7: Nikto-style scan (Ruby)"
if command -v ruby &>/dev/null; then
  ruby ruby/nikto_scan.rb -o "$OUTD/nikto.json" "https://${TARGET}" > "$OUTD/nikto.txt" 2>&1 || true
  log_ok "Nikto scan saved"
fi

# 6. Shodan
if [[ -n "$SHODAN_KEY" ]]; then
  log_info "step 6/7: Shodan lookup"
  "$LYUSS_BIN" shodan "hostname:${TARGET}" --api-key "$SHODAN_KEY" > "$OUTD/shodan.txt" 2>&1 || true
  log_ok "Shodan results saved"
else
  log_warn "step 6/7: Shodan skipped (no API key)"
fi

# 7. Fuzzing (skip if passive)
if [[ "$PASSIVE" == false ]]; then
  log_info "step 7/7: directory fuzzing"
  if [[ -f "$WORDLIST" ]]; then
    "$LYUSS_BIN" fuzz "https://${TARGET}" --wordlist "$WORDLIST" --threads 40 > "$OUTD/fuzz.txt" 2>&1 || true
    log_ok "fuzzing results saved"
  else
    log_warn "wordlist not found: $WORDLIST"
  fi
else
  log_info "step 7/7: fuzzing skipped (passive mode)"
fi

echo ""
log_ok "recon complete. results in: $OUTD"
ls -lh "$OUTD"
