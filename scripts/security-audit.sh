#!/bin/bash
# =============================================================================
# Security Audit Script
# Run periodically (daily/weekly) via cron to detect vulnerabilities.
# Results are printed to stdout; pipe to notification tools as needed.
#
# Cron example (daily at 2 AM):
#   0 2 * * * cd /path/to/ethsig && ./scripts/security-audit.sh 2>&1 | tee /var/log/ethsig-security-audit.log
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ISSUES_FOUND=0
REPORT=""

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ISSUES_FOUND=$((ISSUES_FOUND + 1)); }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; ISSUES_FOUND=$((ISSUES_FOUND + 1)); }

add_report() { REPORT="${REPORT}\n$1"; }

cd "$PROJECT_DIR"

echo "=============================================="
echo " ethsig Security Audit"
echo " Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "=============================================="
echo ""

# =============================================================================
# 1. Go Dependency Vulnerability Check
# =============================================================================
echo "--- [1/4] Dependency Vulnerabilities (govulncheck) ---"
if command -v govulncheck &> /dev/null; then
    VULN_OUTPUT=$(govulncheck ./... 2>&1) || true
    if echo "$VULN_OUTPUT" | grep -q "Vulnerability"; then
        log_error "Vulnerable dependencies found!"
        echo "$VULN_OUTPUT"
        add_report "[CRITICAL] govulncheck: Vulnerable dependencies detected"
    else
        log_info "No known vulnerabilities in dependencies"
    fi
else
    log_warn "govulncheck not installed. Install: go install golang.org/x/vuln/cmd/govulncheck@latest"
    add_report "[SKIP] govulncheck not installed"
fi
echo ""

# =============================================================================
# 2. Static Security Analysis
# =============================================================================
echo "--- [2/4] Static Security Analysis (gosec) ---"
if command -v gosec &> /dev/null; then
    GOSEC_OUTPUT=$(gosec -quiet -fmt=json -exclude-dir=vendor -exclude=G304,G703,G104 ./... 2>&1) || true
    ISSUE_COUNT=$(echo "$GOSEC_OUTPUT" | grep -c '"severity"' 2>/dev/null || echo "0")
    if [ "$ISSUE_COUNT" -gt 0 ]; then
        log_warn "gosec found $ISSUE_COUNT potential issues"
        echo "$GOSEC_OUTPUT" | grep -A2 '"severity"' || true
        add_report "[HIGH] gosec: $ISSUE_COUNT security issues found"
    else
        log_info "No security issues found by gosec"
    fi
else
    log_warn "gosec not installed. Install: go install github.com/securego/gosec/v2/cmd/gosec@latest"
    add_report "[SKIP] gosec not installed"
fi
echo ""

# =============================================================================
# 3. Go Module Integrity
# =============================================================================
echo "--- [3/4] Go Module Integrity ---"
echo -n "Checking go.sum integrity... "
if go mod verify 2>&1 | grep -q "verified"; then
    echo -e "${GREEN}OK${NC}"
else
    VERIFY_OUTPUT=$(go mod verify 2>&1)
    if echo "$VERIFY_OUTPUT" | grep -qi "error\|mismatch"; then
        log_error "Module integrity check failed!"
        echo "$VERIFY_OUTPUT"
        add_report "[CRITICAL] go mod verify: Module tampering detected"
    else
        echo -e "${GREEN}OK${NC}"
    fi
fi
echo ""

# =============================================================================
# 4. Outdated Direct Dependencies
# =============================================================================
echo "--- [4/4] Dependency Freshness ---"
echo -n "Checking for outdated dependencies... "
OUTDATED=$(go list -m -u all 2>/dev/null | grep '\[' | head -20 || true)
if [ -n "$OUTDATED" ]; then
    OUTDATED_COUNT=$(echo "$OUTDATED" | wc -l)
    echo -e "${YELLOW}$OUTDATED_COUNT dependencies have updates available${NC}"
    echo "$OUTDATED"
    add_report "[INFO] $OUTDATED_COUNT dependencies have available updates"
else
    echo -e "${GREEN}All dependencies up to date${NC}"
fi
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=============================================="
echo " Audit Summary"
echo "=============================================="
if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}All checks passed. No issues found.${NC}"
else
    echo -e "${RED}$ISSUES_FOUND issue(s) require attention:${NC}"
    echo -e "$REPORT"
fi
echo ""
echo "Audit completed at $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

exit $(( ISSUES_FOUND > 0 ? 1 : 0 ))
