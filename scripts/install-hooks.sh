#!/usr/bin/env bash
#
# VerdictSec Git Hooks Installer
#
# Installs VerdictSec security hooks into your git repository.
#
# Usage:
#   ./scripts/install-hooks.sh              # Install in current repo
#   ./scripts/install-hooks.sh /path/to/repo # Install in specific repo
#
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Determine script directory (for finding hooks)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_DIR="$SCRIPT_DIR/hooks"

# Determine target repository
if [ $# -ge 1 ]; then
    TARGET_REPO="$1"
else
    TARGET_REPO="$(pwd)"
fi

# Validate target is a git repository
if [ ! -d "$TARGET_REPO/.git" ]; then
    echo -e "${RED}Error: $TARGET_REPO is not a git repository${NC}"
    exit 1
fi

GIT_HOOKS_DIR="$TARGET_REPO/.git/hooks"

echo -e "${CYAN}━━━ VerdictSec Git Hooks Installer ━━━${NC}"
echo -e "Repository: ${YELLOW}$TARGET_REPO${NC}"
echo ""

# Function to install a hook
install_hook() {
    local hook_name="$1"
    local source="$HOOKS_DIR/$hook_name"
    local target="$GIT_HOOKS_DIR/$hook_name"

    if [ ! -f "$source" ]; then
        echo -e "${RED}✗ Hook not found: $source${NC}"
        return 1
    fi

    # Check if hook already exists
    if [ -f "$target" ]; then
        # Check if it's our hook
        if grep -q "VerdictSec" "$target" 2>/dev/null; then
            echo -e "${YELLOW}→ Updating $hook_name (VerdictSec hook exists)${NC}"
        else
            echo -e "${YELLOW}⚠ $hook_name hook already exists (backing up to $hook_name.backup)${NC}"
            cp "$target" "$target.backup"
        fi
    fi

    cp "$source" "$target"
    chmod +x "$target"
    echo -e "${GREEN}✓ Installed $hook_name${NC}"
}

# Install hooks
echo -e "${YELLOW}Installing hooks...${NC}"
echo ""

install_hook "pre-commit"
install_hook "pre-push"

echo ""
echo -e "${GREEN}━━━ Installation Complete ━━━${NC}"
echo ""
echo -e "Installed hooks:"
echo -e "  • ${CYAN}pre-commit${NC}: Secrets + SAST (on staged Go files)"
echo -e "  • ${CYAN}pre-push${NC}: Full security scan"
echo ""
echo -e "To uninstall:"
echo -e "  rm $GIT_HOOKS_DIR/pre-commit $GIT_HOOKS_DIR/pre-push"
echo ""
echo -e "To bypass hooks temporarily:"
echo -e "  git commit --no-verify"
echo -e "  git push --no-verify"
