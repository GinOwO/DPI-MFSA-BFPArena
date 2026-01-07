#!/bin/bash
# Terminate ZDPI EC2 instances.
# Reads instance IDs from ~/.cache/zdpi/instances if available,
# otherwise falls back to listing all running instances in the region.
# Usage: bash scripts/aws_kill.sh
set -euo pipefail

unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy

if ! aws sts get-caller-identity &>/dev/null; then
    echo "ERROR: Not logged in to AWS. Run: aws configure"
    exit 1
fi

REGION="ap-southeast-2"
CACHE_FILE="$HOME/.cache/zdpi/instances"

if [ -f "$CACHE_FILE" ]; then
    source "$CACHE_FILE"
    echo "Found cached instances:"
    echo "  recv: $RECV_ID"
    echo "  send: $SEND_ID"
    echo ""
    read -rp "Terminate both? [y/N] " confirm
    [ "$confirm" != "y" ] && echo "Aborted." && exit 0

    aws ec2 terminate-instances \
        --instance-ids "$RECV_ID" "$SEND_ID" \
        --region "$REGION" \
        --query "TerminatingInstances[].[InstanceId,CurrentState.Name]" \
        --output table

    rm -f "$CACHE_FILE"
    echo "Cache file removed."
else
    echo "No cache file found listing all running instances in $REGION..."
    IDS=$(aws ec2 describe-instances --region "$REGION" \
        --filters "Name=instance-state-name,Values=running,stopped" \
        --query "Reservations[].Instances[].[InstanceId,PublicIpAddress,InstanceType]" \
        --output text)

    if [ -z "$IDS" ]; then
        echo "No running instances found."
        exit 0
    fi

    echo "Instances to terminate:"
    echo "$IDS" | awk '{printf "  %s  %s  (%s)\n", $1, $2, $3}'
    echo ""
    read -rp "Terminate all? [y/N] " confirm
    [ "$confirm" != "y" ] && echo "Aborted." && exit 0

    INSTANCE_IDS=$(echo "$IDS" | awk '{print $1}' | tr '\n' ' ')
    # shellcheck disable=SC2086
    aws ec2 terminate-instances --instance-ids $INSTANCE_IDS --region "$REGION" \
        --query "TerminatingInstances[].[InstanceId,CurrentState.Name]" \
        --output table
fi

echo "Done."
