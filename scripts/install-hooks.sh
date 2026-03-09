#!/bin/bash
# =============================================================================
# Install Git Hooks for Security Checks
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
# Resolve the actual git dir (handles submodules where .git is a file)
GIT_DIR="$(cd "$PROJECT_DIR" && git rev-parse --git-dir)"
if [[ "$GIT_DIR" != /* ]]; then
    GIT_DIR="$PROJECT_DIR/$GIT_DIR"
fi
HOOKS_DIR="$GIT_DIR/hooks"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# =============================================================================
# Check prerequisites
# =============================================================================
check_tools() {
    local missing=()

    if ! command -v go &> /dev/null; then
        missing+=("go")
    fi
    if ! command -v gosec &> /dev/null; then
        missing+=("gosec (install: go install github.com/securego/gosec/v2/cmd/gosec@latest)")
    fi
    if ! command -v govulncheck &> /dev/null; then
        missing+=("govulncheck (install: go install golang.org/x/vuln/cmd/govulncheck@latest)")
    fi
    if ! command -v gitleaks &> /dev/null; then
        missing+=("gitleaks (install: go install github.com/zricethezav/gitleaks/v8@latest)")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_warn "Missing tools (hooks will skip unavailable checks):"
        for tool in "${missing[@]}"; do
            echo "  - $tool"
        done
    fi
}

# =============================================================================
# Install pre-commit hook
# =============================================================================
install_pre_commit() {
    local hook_path="$HOOKS_DIR/pre-commit"

    cat > "$hook_path" << 'HOOK_EOF'
#!/bin/bash
# =============================================================================
# Pre-commit hook: Security checks before every commit
# Installed by: scripts/install-hooks.sh
# =============================================================================
set -e

# Ensure goenv and GOPATH/bin are on PATH (hooks run in minimal shell)
export PATH="$HOME/.goenv/shims:$HOME/.goenv/bin:$(go env GOPATH 2>/dev/null)/bin:$PATH"
export GOTOOLCHAIN=local

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILED=0

echo "=== Running pre-commit security checks ==="

# 1. Check for error suppression (project rule: _ = xxx is forbidden)
echo -n "Checking for suppressed errors... "
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' | grep -v '_test\.go$' | grep -v 'vendor/' || true)
if [ -n "$STAGED_GO_FILES" ]; then
    SUPPRESSED=$(echo "$STAGED_GO_FILES" | xargs grep -n '_ =' 2>/dev/null | grep -v '_ = .*(/\*\|//\|range\|,)' || true)
    if [ -n "$SUPPRESSED" ]; then
        echo -e "${RED}FAIL${NC}"
        echo "Found suppressed errors (forbidden by project rules):"
        echo "$SUPPRESSED"
        FAILED=1
    else
        echo -e "${GREEN}OK${NC}"
    fi
else
    echo -e "${GREEN}OK (no staged Go files)${NC}"
fi

# 2. Static security analysis with gosec
if command -v gosec &> /dev/null; then
    echo -n "Running gosec... "
    if gosec -quiet -exclude-dir=vendor -exclude=G304,G703,G104 ./... 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "gosec found security issues. Run 'gosec ./...' for details."
        FAILED=1
    fi
else
    echo -e "${YELLOW}SKIP (gosec not installed)${NC}"
fi

# 3. Dependency vulnerability check with govulncheck
if command -v govulncheck &> /dev/null; then
    echo -n "Running govulncheck... "
    GOVULN_OUTPUT=$(govulncheck -format json ./... 2>/dev/null)
    GOVULN_EXIT=$?
    if [ $GOVULN_EXIT -eq 0 ]; then
        echo -e "${GREEN}OK${NC}"
    else
        # Check if all findings are stdlib-only (no available fix via go get)
        NON_STDLIB=$(echo "$GOVULN_OUTPUT" | python3 -c "
import sys, json
has_non_stdlib = False
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    finding = obj.get('finding')
    if finding:
        traces = finding.get('trace', [])
        if traces and traces[0].get('module', '') != 'stdlib':
            has_non_stdlib = True
            break
print('yes' if has_non_stdlib else 'no')
" 2>/dev/null)
        if [ "$NON_STDLIB" = "no" ]; then
            echo -e "${YELLOW}WARN${NC}"
            echo "govulncheck: stdlib-only vulnerabilities (no fix available yet). Run 'govulncheck ./...' for details."
        else
            echo -e "${RED}FAIL${NC}"
            echo "govulncheck found vulnerable dependencies. Run 'govulncheck ./...' for details."
            FAILED=1
        fi
    fi
else
    echo -e "${YELLOW}SKIP (govulncheck not installed)${NC}"
fi

# 4. Go vet
echo -n "Running go vet... "
if go vet ./... 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAILED=1
fi

# 5. Check for plaintext secrets in staged files
echo -n "Checking for plaintext secrets... "
SECRETS_FOUND=$(git diff --cached --diff-filter=ACM -U0 -- ':!*_test.go' | grep -v '^@@' | grep -iE '(private_key|password|secret|token)\s*[:=]\s*"[^$\{]' | grep -v '_env' | grep -v 'example' | grep -v '#' || true)
if [ -n "$SECRETS_FOUND" ]; then
    echo -e "${RED}FAIL${NC}"
    echo "Possible plaintext secrets detected in staged changes:"
    echo "$SECRETS_FOUND"
    FAILED=1
else
    echo -e "${GREEN}OK${NC}"
fi

# 6. Gitleaks: scan staged changes for secrets
GITLEAKS_BIN=$(command -v gitleaks 2>/dev/null || true)
if [ -n "$GITLEAKS_BIN" ]; then
    echo -n "Running gitleaks... "
    GITLEAKS_OUTPUT=$(gitleaks protect --staged --no-banner --exit-code 1 2>&1) || GITLEAKS_EXIT=$?
    GITLEAKS_EXIT=${GITLEAKS_EXIT:-0}
    if [ $GITLEAKS_EXIT -eq 0 ]; then
        echo -e "${GREEN}OK${NC}"
    elif echo "$GITLEAKS_OUTPUT" | grep -q "leaks found"; then
        echo -e "${RED}FAIL${NC}"
        echo "gitleaks found secrets in staged changes. Run 'gitleaks protect --staged -v' for details."
        FAILED=1
    else
        echo -e "${YELLOW}SKIP (gitleaks unavailable or error)${NC}"
    fi
else
    echo -e "${YELLOW}SKIP (gitleaks not installed)${NC}"
fi

# 7. Run tests
echo -n "Running tests... "
if go test ./... -timeout 300s 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "Tests failed. Run 'go test -v ./...' for details."
    FAILED=1
fi

echo "=== Pre-commit checks complete ==="

if [ $FAILED -ne 0 ]; then
    echo -e "${RED}Some checks failed. Commit blocked.${NC}"
    echo "Fix the issues above or use 'git commit --no-verify' to skip (NOT recommended)."
    exit 1
fi
HOOK_EOF

    chmod +x "$hook_path"
    log_info "Installed pre-commit hook"
}

# =============================================================================
# Install pre-push hook
# =============================================================================
install_pre_push() {
    local hook_path="$HOOKS_DIR/pre-push"

    cat > "$hook_path" << 'HOOK_EOF'
#!/bin/bash
# =============================================================================
# Pre-push hook: Full test suite before pushing
# Installed by: scripts/install-hooks.sh
# =============================================================================
set -e

# Ensure goenv and GOPATH/bin are on PATH (hooks run in minimal shell)
export PATH="$HOME/.goenv/shims:$HOME/.goenv/bin:$(go env GOPATH 2>/dev/null)/bin:$PATH"
export GOTOOLCHAIN=local

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "=== Running pre-push checks ==="

# 1. Run full test suite with race detection
echo "Running tests with race detection..."
if ! go test -race ./... -timeout 300s 2>&1; then
    echo -e "${RED}Tests failed. Push blocked.${NC}"
    exit 1
fi
echo -e "${GREEN}Tests passed${NC}"

echo "=== Pre-push checks complete ==="
HOOK_EOF

    chmod +x "$hook_path"
    log_info "Installed pre-push hook"
}

# =============================================================================
# Main
# =============================================================================
log_info "Installing git hooks for ethsig..."

# Ensure hooks directory exists
mkdir -p "$HOOKS_DIR"

check_tools
install_pre_commit
install_pre_push

log_info "Git hooks installed successfully!"
log_info "Hooks location: $HOOKS_DIR"
echo ""
echo "Installed hooks:"
echo "  pre-commit : error suppression check, gosec, govulncheck, go vet, plaintext secrets, gitleaks, tests"
echo "  pre-push   : full test suite with race detection"
echo ""
echo "To skip hooks (NOT recommended): git commit --no-verify"
