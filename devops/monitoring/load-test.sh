#!/bin/bash

# Load test script for Verify API
# Generates metrics for Prometheus/Grafana monitoring

set -e

# Configuration
API_URL="${API_URL:-http://localhost:8086}"
ITERATIONS="${ITERATIONS:-10}"
SLEEP_BETWEEN="${SLEEP_BETWEEN:-1}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Verify API Load Test${NC}"
echo "API URL: $API_URL"
echo "Iterations: $ITERATIONS"
echo "Sleep between requests: ${SLEEP_BETWEEN}s"
echo ""

# Test counters
SUCCESS=0
FAILED=0

# Test functions
test_health() {
    echo -n "Testing health endpoint... "
    if curl -s -f "${API_URL}/api/v1/health" > /dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((SUCCESS++))
    else
        echo -e "${RED}✗${NC}"
        ((FAILED++))
    fi
}

test_metrics() {
    echo -n "Testing metrics endpoint... "
    if curl -s -f "${API_URL}/actuator/prometheus" > /dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((SUCCESS++))
    else
        echo -e "${RED}✗${NC}"
        ((FAILED++))
    fi
}

test_pades_verification() {
    echo -n "Testing PAdES verification... "
    # Create a simple test PDF (minimal valid PDF)
    echo "%PDF-1.4" > /tmp/test.pdf
    echo "1 0 obj" >> /tmp/test.pdf
    echo "endobj" >> /tmp/test.pdf
    
    if curl -s -f -X POST "${API_URL}/api/v1/verify/pades" \
        -F "signedDocument=@/tmp/test.pdf" \
        -F "level=SIMPLE" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        ((SUCCESS++))
    else
        echo -e "${YELLOW}⚠ (expected to fail with invalid PDF)${NC}"
        ((SUCCESS++)) # Count as success for metrics generation
    fi
    rm -f /tmp/test.pdf
}

test_xades_verification() {
    echo -n "Testing XAdES verification... "
    # Create a simple test XML
    echo '<?xml version="1.0"?><root>test</root>' > /tmp/test.xml
    
    if curl -s -f -X POST "${API_URL}/api/v1/verify/xades" \
        -F "signedDocument=@/tmp/test.xml" \
        -F "level=SIMPLE" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        ((SUCCESS++))
    else
        echo -e "${YELLOW}⚠ (expected to fail with invalid signature)${NC}"
        ((SUCCESS++)) # Count as success for metrics generation
    fi
    rm -f /tmp/test.xml
}

test_timestamp_verification() {
    echo -n "Testing timestamp verification... "
    # Create a simple test token (will fail but generates metrics)
    echo "test" > /tmp/test.tst
    
    if curl -s -f -X POST "${API_URL}/api/v1/verify/timestamp" \
        -F "timestampToken=@/tmp/test.tst" \
        -F "validateCertificate=false" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        ((SUCCESS++))
    else
        echo -e "${YELLOW}⚠ (expected to fail with invalid token)${NC}"
        ((SUCCESS++)) # Count as success for metrics generation
    fi
    rm -f /tmp/test.tst
}

test_error_generation() {
    echo -n "Testing error generation (404)... "
    if curl -s -f "${API_URL}/api/v1/invalid-endpoint" > /dev/null 2>&1; then
        echo -e "${RED}✗${NC}"
        ((FAILED++))
    else
        echo -e "${GREEN}✓ (404 as expected)${NC}"
        ((SUCCESS++))
    fi
}

# Main loop
for i in $(seq 1 $ITERATIONS); do
    echo ""
    echo -e "${YELLOW}--- Iteration $i/$ITERATIONS ---${NC}"
    
    test_health
    test_metrics
    
    # Every 3rd iteration, test verification endpoints
    if [ $((i % 3)) -eq 0 ]; then
        test_pades_verification
        test_xades_verification
        test_timestamp_verification
    fi
    
    # Every 5th iteration, generate some errors
    if [ $((i % 5)) -eq 0 ]; then
        test_error_generation
    fi
    
    if [ $i -lt $ITERATIONS ]; then
        sleep $SLEEP_BETWEEN
    fi
done

# Summary
echo ""
echo -e "${GREEN}=== Summary ===${NC}"
echo "Total requests: $((SUCCESS + FAILED))"
echo -e "Successful: ${GREEN}$SUCCESS${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""
echo "Check Grafana dashboard for metrics: http://localhost:3000"
echo "Prometheus targets: http://localhost:9090/targets"

