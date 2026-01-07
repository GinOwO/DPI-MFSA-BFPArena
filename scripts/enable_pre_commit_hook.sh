#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cat > "$PROJECT_DIR/.git/hooks/pre-commit" << 'EOF'
#!/bin/bash
CHANGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(c|h|cpp)$' || true)
if [ -n "$CHANGED" ]; then
	clang-format --dry-run --Werror $CHANGED
fi
EOF
chmod +x "$PROJECT_DIR/.git/hooks/pre-commit"
echo "Pre-commit hook installed."
