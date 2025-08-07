#!/bin/bash

# Upgrade monitoring script for cephadm upgrade tests
# Monitors upgrade/downgrade completion by checking both upgrade status and daemon versions

set -e

TARGET_VERSION="$1"
OPERATION="$2"  # "upgrade" or "downgrade"
BASE_IMAGE_NAME="${3:-base}"
TARGET_IMAGE_NAME="${4:-target}"
TIMEOUT="${5:-2400}"
CEPHADM_PATH="${6:-./cephadm}"
SUDO="${7:-sudo}"

if [ -z "$TARGET_VERSION" ] || [ -z "$OPERATION" ]; then
    echo "Usage: $0 <target_version> <upgrade|downgrade> [base_image_name] [target_image_name] [timeout_seconds] [cephadm_path] [sudo_cmd]"
    exit 1
fi

echo "=== CEPH Upgrade Monitor Started ==="
echo "Base image: $BASE_IMAGE_NAME"
echo "Target image: $TARGET_IMAGE_NAME"
echo "Operation: $OPERATION to $TARGET_VERSION"
echo "Timeout: ${TIMEOUT}s"
echo "Using cephadm: $CEPHADM_PATH"
echo "Start time: $(date)"

echo "=== Capturing Baseline Version ==="
$SUDO $CEPHADM_PATH shell -- ceph versions
baseline_version=$($SUDO $CEPHADM_PATH shell -- ceph versions --format json | jq -r ".overall | keys[0]")
echo "Baseline version: $baseline_version"

echo "=== Starting Upgrade Monitoring ==="
start_time=$(date +%s)

while true; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    
    echo ""
    echo "=== Upgrade Status (Elapsed: ${elapsed}s) ==="
    echo "Time: $(date)"
    
    echo "--- Orchestrator Upgrade Status ---"
    upgrade_status=$($SUDO $CEPHADM_PATH shell -- ceph orch upgrade status --format json)
    echo "$upgrade_status"
    
    echo "--- Daemon Versions ---"
    $SUDO $CEPHADM_PATH shell -- ceph versions
    
    in_progress=$(echo "$upgrade_status" | jq -r ".in_progress")
    version_count=$($SUDO $CEPHADM_PATH shell -- ceph versions --format json | jq ".overall | length")
    
    echo "Upgrade in progress: $in_progress"
    echo "Number of different versions running: $version_count"
    
    if [ "$in_progress" = "false" ] && [ "$version_count" -eq 1 ]; then
        current_version=$($SUDO $CEPHADM_PATH shell -- ceph versions --format json | jq -r ".overall | keys[0]")
        echo "All daemons now on: $current_version"
        
        if [ "$current_version" != "$baseline_version" ]; then
            echo ""
            echo "=== SUCCESS: Upgrade Completed ==="
            echo "From: $baseline_version"
            echo "To:   $current_version"
            echo "Base image: $BASE_IMAGE_NAME"
            echo "Target image: $TARGET_IMAGE_NAME"
            echo "Total time: ${elapsed}s"
            echo "End time: $(date)"
            break
        else
            echo ""
            echo "=== SUCCESS: Already on Target Version ==="
            echo "Current version: $current_version"
            echo "Base image: $BASE_IMAGE_NAME"
            echo "Target image: $TARGET_IMAGE_NAME"
            echo "Total time: ${elapsed}s"
            echo "End time: $(date)"
            break
        fi
    else
        echo "Upgrade still in progress or daemons on mixed versions"
        if [ "$version_count" -gt 1 ]; then
            echo "--- Version Breakdown ---"
            $SUDO $CEPHADM_PATH shell -- ceph versions --format json | jq ".overall"
        fi
    fi
    
    if echo "$upgrade_status" | jq -r ".message" | grep -q -i "error\|fail"; then
        echo ""
        echo "=== ERROR: Upgrade Failed ==="
        echo "Upgrade status shows error or failure"
        echo "$upgrade_status"
        exit 1
    fi
    
    if [ $elapsed -ge $TIMEOUT ]; then
        echo ""
        echo "=== ERROR: Upgrade Timeout ==="
        echo "Upgrade did not complete within $TIMEOUT seconds"
        echo "Current status:"
        echo "$upgrade_status"
        $SUDO $CEPHADM_PATH shell -- ceph versions
        exit 1
    fi
    
    echo "Waiting 60 seconds before next check..."
    sleep 60
done

echo ""
echo "=== Final Verification ==="
$SUDO $CEPHADM_PATH shell -- ceph health detail
$SUDO $CEPHADM_PATH shell -- ceph orch ps
$SUDO $CEPHADM_PATH shell -- ceph status

echo ""
echo "=== Upgrade Monitor Completed Successfully ==="