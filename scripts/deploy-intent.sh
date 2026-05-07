#!/bin/bash
# ClawVault 快速部署脚本
# 用法: ./scripts/deploy-intent.sh
set -e

REMOTE_HOST="10.10.70.182"
REMOTE_USER="ubuntu"
REMOTE_PASS="ubuntu"
REMOTE_DIR="/home/ubuntu/open_source/ClawVault"
LOCAL_BASE="$(cd "$(dirname "$0")/.." && pwd)"

FILES=(
    "src/claw_vault/proxy/interceptor.py"
    "src/claw_vault/detector/intent.py"
    "src/claw_vault/detector/intent_llm.py"
    "src/claw_vault/config.py"
    "src/claw_vault/dashboard/api.py"
    "src/claw_vault/dashboard/static/index.html"
    "config/config.yaml"
)

echo "=== ClawVault Deploy ==="
echo "Target: ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}"

for FILE in "${FILES[@]}"; do
    LOCAL_FILE="${LOCAL_BASE}/${FILE}"
    if [ -f "$LOCAL_FILE" ]; then
        echo "  -> ${FILE}"
        /usr/bin/expect -c "
            set timeout 30
            spawn scp -o StrictHostKeyChecking=no \"${LOCAL_FILE}\" \"${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/${FILE}\"
            expect {
                \"*assword*\" { send \"${REMOTE_PASS}\r\"; exp_continue }
                eof
            }
        " 2>&1 | grep -v "^spawn" || true
    else
        echo "  SKIP (not found): ${FILE}"
    fi
done

echo "Clearing pyc cache..."
/usr/bin/expect -c "
    set timeout 20
    spawn ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${REMOTE_HOST}
    expect {
        \"*assword*\" { send \"${REMOTE_PASS}\r\"; exp_continue }
        \"\\\$*\" { }
    }
    send \"find ${REMOTE_DIR}/src -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null; find ${REMOTE_DIR}/src -name '*.pyc' -delete 2>/dev/null; echo OK\r\"
    expect \"\\\$*\"
    send \"exit\r\"
    expect eof
" 2>&1 | grep -E "OK|find" || true

echo "=== Done. Restart service: clawvault restart ==="
