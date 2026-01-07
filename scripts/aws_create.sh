#!/bin/bash
# Create ZDPI recv and send EC2 instances, write .env, update SSH config.
# Usage: bash scripts/aws_create.sh [--scp-key <path>]
#
#   --scp-key <path>   SCP a GitHub SSH key to both instances (e.g. ~/.ssh/id_ed25519_github)
#                      Note: this is separate from the EC2 identity key (zdpi-key.pem)
#
# Requires: aws CLI configured, zdpi-key key pair in ap-southeast-2.
set -euo pipefail

unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy

if ! aws sts get-caller-identity &>/dev/null; then
    echo "ERROR: Not logged in to AWS. Run: aws configure"
    exit 1
fi

REGION="ap-southeast-2"
AMI="ami-095e8c26af3940dc2"   # Ubuntu 24.04, ap-southeast-2
INSTANCE_TYPE="c5n.large"
KEY_NAME="zdpi-key"
SSH_KEY="$HOME/.ssh/zdpi-key.pem"
CACHE_FILE="$HOME/.cache/zdpi/instances"
GH_KEY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --scp-key) GH_KEY="$2"; shift ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
    shift
done

echo "=== ZDPI AWS Instance Creator ==="
echo "Region: $REGION  Type: $INSTANCE_TYPE"
echo ""

# ── Get security group ────────────────────────────────────────────────────────
SG=$(aws ec2 describe-security-groups --region "$REGION" \
    --query "SecurityGroups[0].GroupId" --output text)
echo "Security group: $SG"

# ── Launch instances ──────────────────────────────────────────────────────────
echo "Launching 2 instances..."
INSTANCE_IDS=$(aws ec2 run-instances \
    --image-id "$AMI" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG" \
    --count 2 \
    --region "$REGION" \
    --query "Instances[].[InstanceId]" \
    --output text)

RECV_ID=$(echo "$INSTANCE_IDS" | awk 'NR==1')
SEND_ID=$(echo "$INSTANCE_IDS" | awk 'NR==2')
echo "  recv: $RECV_ID"
echo "  send: $SEND_ID"

# ── Save instance IDs to cache ────────────────────────────────────────────────
mkdir -p "$(dirname "$CACHE_FILE")"
cat > "$CACHE_FILE" << EOF
RECV_ID=$RECV_ID
SEND_ID=$SEND_ID
REGION=$REGION
EOF
echo "  Instance IDs saved to $CACHE_FILE"

# ── Wait for running state ────────────────────────────────────────────────────
echo ""
echo "Waiting for instances to start..."
aws ec2 wait instance-running \
    --instance-ids "$RECV_ID" "$SEND_ID" \
    --region "$REGION"
echo "  [OK] both running"

# ── Get public/private IPs ────────────────────────────────────────────────────
get_ip() {
    aws ec2 describe-instances --instance-ids "$1" --region "$REGION" \
        --query "Reservations[0].Instances[0].[$2]" --output text
}

RECV_PUBLIC=$(get_ip "$RECV_ID" PublicIpAddress)
RECV_PRIVATE=$(get_ip "$RECV_ID" PrivateIpAddress)
SEND_PUBLIC=$(get_ip "$SEND_ID" PublicIpAddress)
SEND_PRIVATE=$(get_ip "$SEND_ID" PrivateIpAddress)

echo "  recv: $RECV_PUBLIC (private: $RECV_PRIVATE)"
echo "  send: $SEND_PUBLIC (private: $SEND_PRIVATE)"

# ── Update ~/.ssh/config ──────────────────────────────────────────────────────
echo ""
echo "Updating ~/.ssh/config..."
touch ~/.ssh/config
chmod 600 ~/.ssh/config

update_ssh_host() {
    local ALIAS=$1 HOST=$2
    local BLOCK="Host $ALIAS
    HostName $HOST
    User ubuntu
    IdentityFile $SSH_KEY
    StrictHostKeyChecking no
    ForwardAgent yes"

    if grep -q "^Host $ALIAS$" ~/.ssh/config 2>/dev/null; then
        # Update only the HostName line inside this specific Host block
        # Use awk to find the block and replace only its HostName line
        awk -v alias="$ALIAS" -v newhost="$HOST" '
            /^Host / { in_block = ($2 == alias) }
            in_block && /^[[:space:]]+HostName / { print "    HostName " newhost; next }
            { print }
        ' ~/.ssh/config > ~/.ssh/config.tmp && mv ~/.ssh/config.tmp ~/.ssh/config
    else
        printf '\n%s\n' "$BLOCK" >> ~/.ssh/config
    fi
}

update_ssh_host recv "$RECV_PUBLIC"
update_ssh_host send "$SEND_PUBLIC"
echo "  [OK] recv -> $RECV_PUBLIC"
echo "  [OK] send -> $SEND_PUBLIC"

# ── Wait for SSH ──────────────────────────────────────────────────────────────
echo ""
echo "Waiting for SSH on both instances..."
for HOST in "$RECV_PUBLIC" "$SEND_PUBLIC"; do
    until ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
              ubuntu@"$HOST" echo ok &>/dev/null; do
        sleep 3
    done
    echo "  [OK] $HOST"
done

# ── Get MACs ──────────────────────────────────────────────────────────────────
echo "Getting MAC addresses..."
RECV_MAC=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$RECV_PUBLIC" \
    "ip link show ens5 | grep 'link/ether' | awk '{print \$2}'")
SEND_MAC=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$SEND_PUBLIC" \
    "ip link show ens5 | grep 'link/ether' | awk '{print \$2}'")

echo "  recv MAC: $RECV_MAC"
echo "  send MAC: $SEND_MAC"

# ── SCP GitHub key (optional) ─────────────────────────────────────────────────
if [ -n "$GH_KEY" ]; then
    if [ ! -f "$GH_KEY" ]; then
        echo "ERROR: key file not found: $GH_KEY"; exit 1
    fi
    GH_KEY_PUB="${GH_KEY}.pub"
    echo ""
    echo "SCPing GitHub key to both instances..."
    for HOST in "$RECV_PUBLIC" "$SEND_PUBLIC"; do
        scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
            "$GH_KEY" ubuntu@"$HOST":~/.ssh/
        [ -f "$GH_KEY_PUB" ] && scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
            "$GH_KEY_PUB" ubuntu@"$HOST":~/.ssh/
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$HOST" bash << ENDSSH
chmod 600 ~/.ssh/$(basename "$GH_KEY")
grep -q 'Host github.com' ~/.ssh/config 2>/dev/null || printf 'Host github.com\n  IdentityFile ~/.ssh/%s\n  StrictHostKeyChecking no\n' '$(basename "$GH_KEY")' >> ~/.ssh/config
ENDSSH
        echo "  [OK] $HOST"
    done
fi

# ── Write .env ────────────────────────────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_DIR/.env"

echo ""
echo "==========================================="
echo "  Writing to $ENV_FILE"
echo "==========================================="
cat > "$ENV_FILE" << EOF
RECV_PUBLIC=$RECV_PUBLIC
RECV_PRIVATE=$RECV_PRIVATE
RECV_MAC=$RECV_MAC

SEND_PUBLIC=$SEND_PUBLIC
SEND_PRIVATE=$SEND_PRIVATE
SEND_MAC=$SEND_MAC
EOF

cat "$ENV_FILE"
echo "==========================================="
echo ""
echo "Instance IDs (saved to $CACHE_FILE):"
echo "  recv: $RECV_ID"
echo "  send: $SEND_ID"
echo ""
echo "Next steps on each instance:"
echo "  git clone git@github.com:GinOwO/DPI-MFSA-BFPArena.git && cd DPI-MFSA-BFPArena && bash scripts/setup.sh"
echo ""
echo "Then to run:"
echo "  bash scripts/run.sh -r   (recv)"
echo "  bash scripts/run.sh -s   (send)"
