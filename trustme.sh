#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  TrustMe — Bash Launcher & Installer
#  Usage: ./trustme.sh [domain] [options]
#  Install: ./trustme.sh --install
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ─── Colors ────────────────────────────────────────────────────
G='\033[38;5;46m'; G2='\033[38;5;118m'; A='\033[38;5;214m'
R='\033[38;5;196m'; B='\033[38;5;39m';  M='\033[38;5;240m'
W='\033[97m'; BOLD='\033[1m'; RST='\033[0m'
OK="${G}[✓]${RST}"; ERR="${R}[✗]${RST}"; WARN="${A}[!]${RST}"; INFO="${B}[i]${RST}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUSTME_PY="${SCRIPT_DIR}/trustme.py"
PYTHON_CMD=""

# ─── Banner ────────────────────────────────────────────────────
banner() {
  echo -e "${G}"
  echo '  ████████╗██████╗ ██╗   ██╗███████╗████████╗███╗   ███╗███████╗'
  echo '     ██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝████╗ ████║██╔════╝'
  echo '     ██║   ██████╔╝██║   ██║███████╗   ██║   ██╔████╔██║█████╗  '
  echo '     ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║╚██╔╝██║██╔══╝  '
  echo '     ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║███████╗'
  echo '     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝'
  echo -e "${M}  Automated Web Reconnaissance & Intelligence Tool v2.4"
  echo -e "  Bash Launcher — $(date '+%Y-%m-%d %H:%M:%S')${RST}"
  echo ""
}

# ─── Help ──────────────────────────────────────────────────────
usage() {
  echo -e "${W}${BOLD}USAGE:${RST}"
  echo -e "  ${G}./trustme.sh${RST} ${B}<domain>${RST} [options]"
  echo -e "  ${G}./trustme.sh${RST} ${A}--install${RST}"
  echo ""
  echo -e "${W}${BOLD}OPTIONS:${RST}"
  echo -e "  ${B}-o, --output DIR${RST}      Output directory (default: ./reports)"
  echo -e "  ${B}-p, --ports LIST${RST}      Comma-separated ports to scan"
  echo -e "  ${B}--no-subdomains${RST}        Skip subdomain enumeration"
  echo -e "  ${B}--no-dns${RST}               Skip DNS enumeration"
  echo -e "  ${B}--no-vuln${RST}              Skip vulnerability checks"
  echo -e "  ${B}--no-color${RST}             Disable colored output"
  echo -e "  ${B}--full${RST}                 Full scan (nmap + extended wordlist)"
  echo -e "  ${B}--json${RST}                 Save JSON report"
  echo -e "  ${B}--quiet${RST}                Minimal output"
  echo -e "  ${B}--install${RST}              Install dependencies"
  echo -e "  ${B}--update${RST}               Update tool"
  echo -e "  ${B}-h, --help${RST}             Show this help"
  echo ""
  echo -e "${W}${BOLD}EXAMPLES:${RST}"
  echo -e "  ${M}./trustme.sh example.com${RST}"
  echo -e "  ${M}./trustme.sh example.com --full --json${RST}"
  echo -e "  ${M}./trustme.sh example.com -o /tmp/reports -p 80,443,8080${RST}"
  echo -e "  ${M}./trustme.sh example.com --no-subdomains --no-color > report.txt${RST}"
  echo ""
}

# ─── Check Python ──────────────────────────────────────────────
find_python() {
  for cmd in python3 python3.12 python3.11 python3.10 python3.9 python; do
    if command -v "$cmd" &>/dev/null; then
      ver=$("$cmd" -c "import sys; print(sys.version_info[:2])" 2>/dev/null)
      if "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (3,6) else 1)" 2>/dev/null; then
        PYTHON_CMD="$cmd"
        return 0
      fi
    fi
  done
  return 1
}

# ─── Detect package manager ────────────────────────────────────
detect_pm() {
  if command -v apt-get &>/dev/null; then echo "apt"
  elif command -v apt &>/dev/null;     then echo "apt"
  elif command -v dnf &>/dev/null;     then echo "dnf"
  elif command -v yum &>/dev/null;     then echo "yum"
  elif command -v pacman &>/dev/null;  then echo "pacman"
  elif command -v zypper &>/dev/null;  then echo "zypper"
  elif command -v brew &>/dev/null;    then echo "brew"
  else echo "unknown"
  fi
}

# ─── Install dependencies ──────────────────────────────────────
install_deps() {
  echo -e "${INFO} Detecting system..."
  PM=$(detect_pm)
  echo -e "${OK} Package manager: ${G}${PM}${RST}"
  
  SUDO=""
  if [[ $EUID -ne 0 ]] && command -v sudo &>/dev/null; then
    SUDO="sudo"
  fi

  echo -e "${INFO} Installing system dependencies..."
  
  case "$PM" in
    apt)
      $SUDO apt-get update -qq
      $SUDO apt-get install -y python3 python3-pip whois dnsutils nmap curl wget net-tools 2>/dev/null || true
      ;;
    dnf|yum)
      $SUDO $PM install -y python3 python3-pip whois bind-utils nmap curl wget net-tools 2>/dev/null || true
      ;;
    pacman)
      $SUDO pacman -S --noconfirm python python-pip whois bind-tools nmap curl wget net-tools 2>/dev/null || true
      ;;
    zypper)
      $SUDO zypper install -y python3 python3-pip whois bind-utils nmap curl wget 2>/dev/null || true
      ;;
    brew)
      brew install python3 whois nmap 2>/dev/null || true
      ;;
    *)
      echo -e "${WARN} Unknown package manager. Install manually: python3, whois, nmap, dig"
      ;;
  esac

  echo -e "${INFO} Checking Python pip packages..."
  if find_python; then
    # These are stdlib in Python 3 — just verify
    $PYTHON_CMD -c "import socket, ssl, json, subprocess, concurrent.futures, urllib.request" 2>/dev/null \
      && echo -e "${OK} Python stdlib modules available" \
      || echo -e "${WARN} Some modules missing"
  fi

  echo ""
  echo -e "${OK} Installation complete!"
  echo ""
  check_tools
}

# ─── Check tools ──────────────────────────────────────────────
check_tools() {
  echo -e "${W}${BOLD}Tool Availability:${RST}"
  local tools=("python3:required" "dig:recommended" "whois:recommended" "nmap:optional" "curl:optional")
  for entry in "${tools[@]}"; do
    tool="${entry%%:*}"
    level="${entry##*:}"
    if command -v "$tool" &>/dev/null; then
      ver=$(command -v "$tool" | head -1)
      echo -e "  ${OK} ${G}${tool}${RST} ${M}(${level})${RST}"
    else
      if [[ "$level" == "required" ]]; then
        echo -e "  ${ERR} ${R}${tool}${RST} ${M}(${level} — MISSING!)${RST}"
      else
        echo -e "  ${WARN} ${A}${tool}${RST} ${M}(${level} — not found)${RST}"
      fi
    fi
  done
  echo ""
}

# ─── Validate target ──────────────────────────────────────────
validate_target() {
  local target="$1"
  # Strip protocol
  target="${target#https://}"
  target="${target#http://}"
  target="${target%%/*}"
  
  # Basic domain validation (hyphen must be last in bracket expression)
  if [[ ! "$target" =~ ^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$ ]]; then
    echo -e "${ERR} Invalid target: ${R}${target}${RST}"
    echo -e "  ${M}Use format: example.com or sub.example.com${RST}"
    exit 1
  fi
  echo "$target"
}

# ─── Pre-flight checks ────────────────────────────────────────
preflight() {
  # Check Python
  if ! find_python; then
    echo -e "${ERR} Python 3.6+ not found!"
    echo -e "  ${M}Run: ${G}./trustme.sh --install${RST}"
    exit 1
  fi
  echo -e "  ${OK} Python: ${G}${PYTHON_CMD}${RST}"
  
  # Check trustme.py exists
  if [[ ! -f "$TRUSTME_PY" ]]; then
    echo -e "${ERR} trustme.py not found at: ${R}${TRUSTME_PY}${RST}"
    echo -e "  ${M}Ensure trustme.py is in the same directory as this script${RST}"
    exit 1
  fi
  echo -e "  ${OK} trustme.py: ${G}found${RST}"
}

# ─── Main logic ───────────────────────────────────────────────
main() {
  # No args — show help
  if [[ $# -eq 0 ]]; then
    banner
    usage
    exit 0
  fi

  # Handle flags that don't need a target
  case "${1:-}" in
    --install|-i)
      banner
      install_deps
      exit 0
      ;;
    --check)
      banner
      find_python && echo -e "  ${OK} Python: ${G}${PYTHON_CMD}${RST}" || echo -e "  ${ERR} Python not found"
      check_tools
      exit 0
      ;;
    --update)
      echo -e "${INFO} Pulling latest version..."
      if command -v git &>/dev/null && [[ -d "${SCRIPT_DIR}/.git" ]]; then
        cd "$SCRIPT_DIR" && git pull
        echo -e "${OK} Updated!"
      else
        echo -e "${WARN} Not a git repo. Download latest from GitHub."
      fi
      exit 0
      ;;
    -h|--help|help)
      banner
      usage
      exit 0
      ;;
  esac

  # Target required from here
  TARGET_RAW="$1"
  shift

  banner
  preflight
  echo ""

  # Validate and clean target
  TARGET=$(validate_target "$TARGET_RAW")

  # Build Python args, forwarding all remaining args
  EXTRA_ARGS=("$@")

  # Run the Python scanner
  echo -e "  ${G}Launching TrustMe scan on:${RST} ${B}${TARGET}${RST}"
  echo -e "  ${M}Press Ctrl+C to abort${RST}"
  echo ""

  exec "$PYTHON_CMD" "$TRUSTME_PY" "$TARGET" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
}

# ─── Trap Ctrl+C ─────────────────────────────────────────────
trap 'echo -e "\n\n  ${A}[!] Scan interrupted by user${RST}\n"; exit 130' INT

main "$@"
