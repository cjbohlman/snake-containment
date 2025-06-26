#!/bin/bash
set -e

# Parse inputs
SCAN_PATH=${1:-"."}
SCANNERS=${2:-"secrets,ip_address"}
FORMAT=${3:-"sarif"}
FAIL_ON_FINDINGS=${4:-"true"}
SEVERITY_THRESHOLD=${5:-"medium"}

echo "🐍 Starting Snake Containment Security Scan"
echo "Path: $SCAN_PATH"
echo "Scanners: $SCANNERS"
echo "Format: $FORMAT"
echo "Fail on findings: $FAIL_ON_FINDINGS"
echo "Severity threshold: $SEVERITY_THRESHOLD"

# Create output directory
mkdir -p /tmp/results

# Convert comma-separated scanners to individual -s flags
SCANNER_ARGS=""
IFS=',' read -ra SCANNER_ARRAY <<< "$SCANNERS"
for scanner in "${SCANNER_ARRAY[@]}"; do
    SCANNER_ARGS="$SCANNER_ARGS -s $(echo $scanner | xargs)"
done

# Run the scan
OUTPUT_FILE="/tmp/results/snake-containment-results.$FORMAT"

echo "Running: snake-containment scan $SCAN_PATH $SCANNER_ARGS --format $FORMAT --output $OUTPUT_FILE"

# Add debugging
echo "Current directory: $(pwd)"
echo "Files in current directory: $(ls -la)"

if snake-containment scan "$SCAN_PATH" $SCANNER_ARGS --format "$FORMAT" --output "$OUTPUT_FILE"; then
    SCAN_SUCCESS=true
    echo "✅ Scan completed successfully"
else
    SCAN_SUCCESS=false
    echo "❌ Scan failed with exit code $?"
fi

# Debug output file
echo "Checking output file: $OUTPUT_FILE"
if [[ -f "$OUTPUT_FILE" ]]; then
    echo "✅ Output file exists, size: $(wc -c < "$OUTPUT_FILE") bytes"
    echo "Content of output file:"
    echo "===================="
    cat "$OUTPUT_FILE"
    echo "===================="
else
    echo "❌ Output file does not exist"
    echo "Files in /tmp/results/:"
    ls -la /tmp/results/ || echo "Directory doesn't exist"
fi

# Count findings from the output
if [[ "$FORMAT" == "json" && -f "$OUTPUT_FILE" ]]; then
    FINDINGS_COUNT=$(python3 -c "
import json
try:
    with open('$OUTPUT_FILE', 'r') as f:
        data = json.load(f)
    print(data.get('summary', {}).get('total_findings', 0))
except:
    print(0)
" 2>/dev/null || echo "0")
elif [[ "$FORMAT" == "sarif" && -f "$OUTPUT_FILE" ]]; then
    # Count SARIF results properly
    FINDINGS_COUNT=$(python3 -c "
import json
try:
    with open('$OUTPUT_FILE', 'r') as f:
        data = json.load(f)
    total = 0
    for run in data.get('runs', []):
        total += len(run.get('results', []))
    print(total)
except:
    print(0)
" 2>/dev/null || echo "0")
else
    # For text format, count lines or use basic parsing
    if [[ -f "$OUTPUT_FILE" ]]; then
        FINDINGS_COUNT=$(grep -c "Found\|Detected" "$OUTPUT_FILE" 2>/dev/null || echo "0")
    else
        FINDINGS_COUNT="0"
    fi
fi

echo "Found $FINDINGS_COUNT findings"
echo "Debug: FINDINGS_COUNT='$FINDINGS_COUNT' (length: ${#FINDINGS_COUNT})"

# Validate findings count is a number
if ! [[ "$FINDINGS_COUNT" =~ ^[0-9]+$ ]]; then
    echo "⚠️  Invalid findings count, defaulting to 0"
    FINDINGS_COUNT="0"
fi

# Set GitHub Action outputs (with better error handling)
if [[ -n "$GITHUB_OUTPUT" ]]; then
    {
        echo "findings-count=$FINDINGS_COUNT"
        echo "sarif-file=$OUTPUT_FILE"
    } >> "$GITHUB_OUTPUT" 2>&1 && echo "✅ GitHub outputs set successfully" || echo "❌ Failed to set GitHub outputs"
else
    echo "⚠️  GITHUB_OUTPUT not available"
fi

echo "Debug info:"
echo "FINDINGS_COUNT: '$FINDINGS_COUNT'"
echo "OUTPUT_FILE: '$OUTPUT_FILE'"

# Copy SARIF file to expected location for GitHub upload
if [[ "$FORMAT" == "sarif" && -f "$OUTPUT_FILE" ]]; then
    echo "📊 SARIF results available for GitHub Security tab"
    # Copy to the workspace directory which is shared between container and host
    WORKSPACE_SARIF="/github/workspace/snake-containment.sarif"
    if cp "$OUTPUT_FILE" "$WORKSPACE_SARIF" 2>/dev/null; then
        echo "✅ SARIF file copied to $WORKSPACE_SARIF"
        if [[ -n "$GITHUB_OUTPUT" ]]; then
            echo "sarif-file=$WORKSPACE_SARIF" >> "$GITHUB_OUTPUT" 2>&1 || true
        fi
    else
        echo "❌ Failed to copy SARIF file to workspace"
    fi
fi

# Display results
echo ""
echo "📋 Scan Results:"
cat "$OUTPUT_FILE"

# Fail the action if requested and findings were discovered
if [[ "$FAIL_ON_FINDINGS" == "true" && "$FINDINGS_COUNT" -gt 0 ]]; then
    echo ""
    echo "❌ Action failed: $FINDINGS_COUNT security findings discovered"
    exit 1
elif [[ "$SCAN_SUCCESS" == "false" ]]; then
    echo ""
    echo "❌ Action failed: Scanner encountered an error"
    exit 1
else
    echo ""
    echo "✅ Scan completed successfully"
    exit 0
fi