#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# llm-sneak installer
# Usage:  bash install.sh
#         curl -sSL https://raw.githubusercontent.com/safellm/llm-sneak/main/install.sh | bash
# ─────────────────────────────────────────────────────────────────────────────
set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
DIM="\033[2m"
RESET="\033[0m"

clear_line() { printf "\r\033[K"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}   _ _                                _    ${RESET}"
echo -e "${BOLD}${CYAN}  | | |_ __ ___      ___ _ __   ___  __ _| | __${RESET}"
echo -e "${BOLD}${CYAN}  | | | '_ \` _ \\ ___/ __| '_ \\ / _ \\/ _\` | |/ /${RESET}"
echo -e "${BOLD}${CYAN}  | | | | | | | |___\\__ \\ | | |  __/ (_| |   < ${RESET}"
echo -e "${BOLD}${CYAN}  |_|_|_| |_| |_|   |___/_| |_|\\___|\\__,_|_|\\_\\${RESET}"
echo ""
echo -e "  ${BOLD}LLM Security Scanner${RESET}  ${DIM}— Like Nmap, but for AI${RESET}"
echo -e "  ${DIM}https://github.com/safellm/llm-sneak${RESET}"
echo ""
echo "  ─────────────────────────────────────────────"
echo ""

# ── Check Python 3.10+ ────────────────────────────────────────────────────────
PYTHON=""
for py in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$py" &>/dev/null; then
        VER=$($py -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
            PYTHON="$py"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "${RED}  ✗  Python 3.10+ not found${RESET}"
    echo ""
    echo "  Install Python 3.11+ and re-run:"
    echo "    Ubuntu/Debian:  sudo apt install python3.11"
    echo "    macOS (Homebrew): brew install python@3.12"
    echo "    Windows: https://python.org/downloads/"
    exit 1
fi

echo -e "${GREEN}  ✓${RESET}  Python: $($PYTHON --version)"

# ── Detect install method ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v pipx &>/dev/null; then
    echo -e "${GREEN}  ✓${RESET}  Using ${BOLD}pipx${RESET} (isolated install — recommended)"
    echo ""
    echo -e "  ${YELLOW}→${RESET}  Installing llm-sneak..."
    pipx install "$SCRIPT_DIR" --force
    INSTALL_METHOD="pipx"

elif command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
    PIP=$(command -v pip3 || command -v pip)
    echo -e "${GREEN}  ✓${RESET}  Using ${BOLD}pip${RESET}"
    echo ""
    echo -e "  ${YELLOW}→${RESET}  Installing llm-sneak..."
    
    # Try --user install first (no sudo)
    if "$PIP" install --user --quiet "$SCRIPT_DIR" 2>/dev/null; then
        INSTALL_METHOD="pip-user"
    else
        "$PIP" install --quiet "$SCRIPT_DIR"
        INSTALL_METHOD="pip-system"
    fi
else
    echo -e "${RED}  ✗  pip not found${RESET}"
    echo ""
    echo "  Install pip first:"
    echo "    curl https://bootstrap.pypa.io/get-pip.py | $PYTHON"
    exit 1
fi

# ── PATH check ────────────────────────────────────────────────────────────────
echo ""
LOCAL_BIN="$HOME/.local/bin"
if [ "$INSTALL_METHOD" = "pip-user" ] && [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
    echo -e "${YELLOW}  ⚠${RESET}  Add this to your ${BOLD}~/.bashrc${RESET} or ${BOLD}~/.zshrc${RESET} then restart your terminal:"
    echo ""
    echo -e "     ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
    echo ""
    echo "  Then run:  llm-sneak --version"
    echo ""
    exit 0
fi

# ── Verify ────────────────────────────────────────────────────────────────────
if command -v llm-sneak &>/dev/null; then
    echo -e "${GREEN}  ${BOLD}✓  Installation complete!${RESET}"
    echo ""
    echo -e "  ${DIM}$(llm-sneak --version)${RESET}"
else
    echo -e "${YELLOW}  ⚠  Installed, but llm-sneak not yet in PATH.${RESET}"
    echo "     Try opening a new terminal."
    exit 0
fi

# ── Quick start ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo ""
echo -e "  ${CYAN}# Scan local Ollama (free, no API key)${RESET}"
echo "  llm-sneak http://localhost:11434"
echo ""
echo -e "  ${CYAN}# Full scan with model fingerprinting${RESET}"
echo "  llm-sneak -A --model llama3 http://localhost:11434"
echo ""
echo -e "  ${CYAN}# Vulnerability scan (OWASP LLM Top 10)${RESET}"
echo "  llm-sneak --script vuln --model llama3 http://localhost:11434"
echo ""
echo -e "  ${CYAN}# Scan OpenAI with your API key${RESET}"
echo "  llm-sneak -sV --api-key sk-... https://api.openai.com"
echo ""
echo -e "  ${CYAN}# All flags${RESET}"
echo "  llm-sneak --help"
echo ""
echo -e "  ${DIM}Docs: https://github.com/safellm/llm-sneak${RESET}"
echo ""
