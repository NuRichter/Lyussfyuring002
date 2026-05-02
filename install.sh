#!/usr/bin/env bash
# -------------------------------------------------------------------
# Lyussfyuring002 :: install.sh
# dependency installer for Arch Linux and Kali Linux
# -------------------------------------------------------------------

set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
RST='\033[0m'

log_info()  { echo -e "${CYN}[*]${RST} $*"; }
log_ok()    { echo -e "${GRN}[+]${RST} $*"; }
log_warn()  { echo -e "${YLW}[!]${RST} $*"; }
log_error() { echo -e "${RED}[x]${RST} $*" >&2; }

detect_distro() {
  if [[ -f /etc/arch-release ]]; then
    echo "arch"
  elif grep -qi 'kali' /etc/os-release 2>/dev/null; then
    echo "kali"
  else
    echo "unknown"
  fi
}

install_arch() {
  log_info "installing dependencies via pacman..."
  sudo pacman -Sy --noconfirm \
    go ruby whois bind-tools nmap curl git zip

  log_info "installing Ruby gems..."
  sudo gem install colorize --no-document
  log_ok "Arch Linux setup complete"
}

install_kali() {
  log_info "installing dependencies via apt..."
  sudo apt update -q
  sudo apt install -y \
    golang-go ruby ruby-dev whois dnsutils nmap curl git zip build-essential

  log_info "installing Ruby gems..."
  sudo gem install colorize --no-document
  log_ok "Kali Linux setup complete"
}

build_binary() {
  log_info "building lyuss Go binary..."
  go build -ldflags="-s -w" -o lyuss ./cmd/lyuss/
  log_ok "binary built: ./lyuss"
}

DISTRO=$(detect_distro)

case "$DISTRO" in
  arch)
    log_ok "detected: Arch Linux"
    install_arch
    ;;
  kali)
    log_ok "detected: Kali Linux"
    install_kali
    ;;
  *)
    log_warn "unsupported distro. only Arch Linux and Kali Linux are supported."
    log_warn "attempting to continue anyway..."
    ;;
esac

build_binary

chmod +x shell/*.sh ruby/*.rb

log_ok "Lyussfyuring002 is ready."
echo ""
echo "  usage:"
echo "    ./lyuss --help"
echo "    ./shell/recon.sh example.com"
echo "    ruby ruby/nikto_scan.rb https://example.com"
echo "    ruby ruby/maltego_map.rb example.com"
echo "    ruby ruby/osint_framework.rb --type domain example.com"
