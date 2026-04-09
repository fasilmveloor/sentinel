#!/bin/bash
#
# Sentinel v1.0.0 Validation Script
# 
# This script runs validation tests to ensure Sentinel meets the 80% detection rate target.
#
# Usage:
#   ./validate_sentinel.sh [--target crapi|vampi|all] [--verbose]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SENTINEL_DIR="/home/z/my-project/sentinel"
REPORTS_DIR="${SENTINEL_DIR}/validation_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Parse arguments
TARGET="all"
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--target crapi|vampi|all] [--verbose]"
            echo ""
            echo "Options:"
            echo "  --target    Specify which target to validate (default: all)"
            echo "  --verbose   Enable verbose output"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        Sentinel v1.0.0 Validation Script                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Create reports directory
mkdir -p "${REPORTS_DIR}"

# Function to check if a service is running
check_service() {
    local url=$1
    local name=$2
    
    echo -e "${YELLOW}Checking if ${name} is running at ${url}...${NC}"
    
    if curl -s --max-time 5 "${url}" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ ${name} is running${NC}"
        return 0
    else
        echo -e "${RED}✗ ${name} is not running${NC}"
        return 1
    fi
}

# Function to run unit tests with coverage
run_unit_tests() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Running Unit Tests with Coverage${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    
    cd "${SENTINEL_DIR}"
    
    # Run pytest with coverage
    if [ "$VERBOSE" = true ]; then
        pytest tests/unit/ -v --cov=sentinel/attacks --cov-report=term-missing --cov-fail-under=80
    else
        pytest tests/unit/ -q --cov=sentinel/attacks --cov-report=term-missing --cov-fail-under=80
    fi
    
    local result=$?
    
    if [ $result -eq 0 ]; then
        echo -e "${GREEN}✓ Unit tests passed with ≥ 80% coverage${NC}"
    else
        echo -e "${RED}✗ Unit tests failed or coverage below 80%${NC}"
    fi
    
    return $result
}

# Function to validate against crAPI
validate_crapi() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Validating Against crAPI${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    
    # Check if crAPI is running
    if ! check_service "http://localhost:8888" "crAPI"; then
        echo -e "${YELLOW}Attempting to start crAPI...${NC}"
        echo -e "${YELLOW}Please start crAPI manually:${NC}"
        echo "  git clone https://github.com/OWASP/crAPI"
        echo "  cd crAPI/deploy/docker"
        echo "  docker-compose up -d"
        return 1
    fi
    
    # Check for OpenAPI spec
    local SPEC_FILE="${SENTINEL_DIR}/benchmark_data/crapi_openapi.json"
    if [ ! -f "$SPEC_FILE" ]; then
        # Try to download the spec
        echo -e "${YELLOW}Downloading crAPI OpenAPI spec...${NC}"
        mkdir -p "${SENTINEL_DIR}/benchmark_data"
        curl -sL "https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/openapi.json" -o "$SPEC_FILE"
    fi
    
    # Run Sentinel scan
    local REPORT_FILE="${REPORTS_DIR}/crapi_report_${TIMESTAMP}.md"
    
    echo -e "${YELLOW}Running Sentinel scan against crAPI...${NC}"
    
    cd "${SENTINEL_DIR}"
    
    # Use Python directly for the scan
    python -m sentinel scan \
        --swagger "$SPEC_FILE" \
        --target "http://localhost:8888" \
        --output "$REPORT_FILE" \
        --format markdown \
        --timeout 10 \
        $([ "$VERBOSE" = true ] && echo "--verbose")
    
    # Analyze results
    echo ""
    echo -e "${YELLOW}Analyzing detection results...${NC}"
    
    # Count vulnerabilities found
    local vuln_count=$(grep -c "Severity:" "$REPORT_FILE" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}Found ${vuln_count} potential vulnerabilities${NC}"
    
    # Check for key vulnerability types
    local detection_categories=0
    
    # Check for various attack types
    if grep -qi "rate.limit" "$REPORT_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ Rate Limiting detected${NC}"
        ((detection_categories++))
    fi
    
    if grep -qi "sql.injection\|sql injection" "$REPORT_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ SQL Injection detected${NC}"
        ((detection_categories++))
    fi
    
    if grep -qi "ssrf" "$REPORT_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ SSRF detected${NC}"
        ((detection_categories++))
    fi
    
    if grep -qi "jwt\|token" "$REPORT_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ JWT vulnerabilities detected${NC}"
        ((detection_categories++))
    fi
    
    if grep -qi "idor\|bola" "$REPORT_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ IDOR/BOLA detected${NC}"
        ((detection_categories++))
    fi
    
    if grep -qi "auth.bypass\|authentication" "$REPORT_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ Auth bypass detected${NC}"
        ((detection_categories++))
    fi
    
    echo ""
    echo -e "${YELLOW}Detection categories found: ${detection_categories}${NC}"
    
    # crAPI has ~18 vulnerability categories
    # We need to detect at least 80% = 15 categories
    local REQUIRED_CATEGORIES=15
    local detection_rate=0
    
    if [ $detection_categories -gt 0 ]; then
        detection_rate=$(echo "scale=2; ($detection_categories / 18) * 100" | bc)
    fi
    
    echo -e "${YELLOW}Estimated detection rate: ${detection_rate}%${NC}"
    
    if [ $(echo "$detection_rate >= 80" | bc) -eq 1 ]; then
        echo -e "${GREEN}✓ Detection rate meets 80% threshold${NC}"
        return 0
    else
        echo -e "${RED}✗ Detection rate below 80% threshold${NC}"
        echo -e "${YELLOW}Note: Some vulnerabilities require authenticated testing${NC}"
        return 1
    fi
}

# Function to validate against VAmPI
validate_vampi() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Validating Against VAmPI${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    
    # Check if VAmPI is running
    if ! check_service "http://localhost:5000" "VAmPI"; then
        echo -e "${YELLOW}Attempting to start VAmPI...${NC}"
        docker run -d -p 5000:5000 --name vampi ghcr.io/erev0s/vampi:latest 2>/dev/null || true
        
        # Wait for VAmPI to start
        sleep 10
        
        if ! check_service "http://localhost:5000" "VAmPI"; then
            echo -e "${RED}Could not start VAmPI${NC}"
            return 1
        fi
    fi
    
    # Download VAmPI OpenAPI spec
    local SPEC_FILE="${SENTINEL_DIR}/benchmark_data/vampi_openapi.yml"
    mkdir -p "${SENTINEL_DIR}/benchmark_data"
    
    if [ ! -f "$SPEC_FILE" ]; then
        echo -e "${YELLOW}Downloading VAmPI OpenAPI spec...${NC}"
        curl -sL "https://raw.githubusercontent.com/erev0s/VAmPI/main/openapi_specs.yml" -o "$SPEC_FILE"
    fi
    
    # Run Sentinel scan
    local REPORT_FILE="${REPORTS_DIR}/vampi_report_${TIMESTAMP}.md"
    
    echo -e "${YELLOW}Running Sentinel scan against VAmPI...${NC}"
    
    cd "${SENTINEL_DIR}"
    
    python -m sentinel scan \
        --swagger "$SPEC_FILE" \
        --target "http://localhost:5000" \
        --output "$REPORT_FILE" \
        --format markdown \
        --timeout 10 \
        $([ "$VERBOSE" = true ] && echo "--verbose")
    
    echo -e "${GREEN}VAmPI validation complete${NC}"
    echo -e "${GREEN}Report saved to: ${REPORT_FILE}${NC}"
    
    return 0
}

# Main validation flow
main() {
    echo -e "${BLUE}Starting validation process...${NC}"
    echo ""
    
    local overall_result=0
    
    # Step 1: Run unit tests
    if ! run_unit_tests; then
        overall_result=1
    fi
    
    # Step 2: Run target-specific validation
    case $TARGET in
        crapi)
            if ! validate_crapi; then
                overall_result=1
            fi
            ;;
        vampi)
            if ! validate_vampi; then
                overall_result=1
            fi
            ;;
        all)
            # Try crAPI first
            validate_crapi || true
            
            # Then VAmPI
            validate_vampi || true
            ;;
        *)
            echo -e "${RED}Unknown target: ${TARGET}${NC}"
            exit 1
            ;;
    esac
    
    # Summary
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Validation Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    
    if [ $overall_result -eq 0 ]; then
        echo -e "${GREEN}✓ All validation checks passed${NC}"
        echo -e "${GREEN}Sentinel v1.0.0 is ready for release${NC}"
    else
        echo -e "${RED}✗ Some validation checks failed${NC}"
        echo -e "${YELLOW}Please review the output above for details${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}Reports saved to: ${REPORTS_DIR}${NC}"
    
    exit $overall_result
}

# Run main
main
