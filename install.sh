#!/usr/bin/env bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
echo "╦ ╦╦ ╦╦╔═╗╔═╗╔═╗╦═╗╔═╗╔═╗╦╦═╗"
echo "║║║╠═╣║╚═╗╠═╝║╣ ╠╦╝╠═╝╠═╣║╠╦╝"
echo "╚╩╝╩ ╩╩╚═╝╩  ╚═╝╩╚═╩  ╩ ╩╩╩╚═"
echo -e "${NC}"
echo -e "${CYAN}CVE-2025-36911 Security Research Tool${NC}"
echo ""

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 not found. Please install Python 3.10+${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
REQUIRED_VERSION="3.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python $REQUIRED_VERSION+ required (found $PYTHON_VERSION)${NC}"
    exit 1
fi

echo -e "${GREEN}[1/4]${NC} Python $PYTHON_VERSION detected"

if [ ! -d "venv" ]; then
    echo -e "${GREEN}[2/4]${NC} Creating virtual environment..."
    python3 -m venv venv
else
    echo -e "${GREEN}[2/4]${NC} Virtual environment exists"
fi

echo -e "${GREEN}[3/4]${NC} Activating virtual environment..."
source venv/bin/activate

echo -e "${GREEN}[4/4]${NC} Installing dependencies..."
pip install --upgrade pip -q
pip install -e . -q

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo -e "  ${CYAN}source venv/bin/activate${NC}    # Activate environment"
echo -e "  ${CYAN}whisperpair-tui${NC}             # Launch TUI interface"
echo -e "  ${CYAN}whisperpair scan${NC}            # CLI: Scan for devices"
echo -e "  ${CYAN}whisperpair demo${NC}            # CLI: View demo info"
echo ""
echo -e "${RED}LEGAL: Only use on devices you own or are authorized to test.${NC}"
echo -e "${RED}See LEGAL.md for details on UK Computer Misuse Act 1990.${NC}"
