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

if snake-containment scan "$SCAN_PATH" $SCANNER_ARGS --format "$FORMAT" --output "$OUTPUT_FILE"; then
    SCAN_SUCCESS=true
else
    SCAN_SUCCESS=false
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
else
    # For text/sarif, count lines or use basic parsing
    if [[ -f "$OUTPUT_FILE" ]]; then
        FINDINGS_COUNT=$(grep -c "Found\|Detected" "$OUTPUT_FILE" 2>/dev/null || echo "0")
    else
        FINDINGS_COUNT="0"
    fi
fi

echo "Found $FINDINGS_COUNT findings"

# Set GitHub Action outputs (only if GITHUB_OUTPUT exists)
if [[ -n "$GITHUB_OUTPUT" ]]; then
    echo "findings-count=$FINDINGS_COUNT" >> "$GITHUB_OUTPUT"
    echo "sarif-file=$OUTPUT_FILE" >> "$GITHUB_OUTPUT"
fi

# Copy SARIF file to expected location for GitHub upload
if [[ "$FORMAT" == "sarif" && -f "$OUTPUT_FILE" ]]; then
    echo "📊 SARIF results available for GitHub Security tab"
    # Copy to a standard location that GitHub can access
    cp "$OUTPUT_FILE" "/tmp/snake-containment.sarif" 2>/dev/null || true
    if [[ -n "$GITHUB_OUTPUT" ]]; then
        echo "sarif-file=/tmp/snake-containment.sarif" >> "$GITHUB_OUTPUT"
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