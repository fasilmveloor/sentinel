# Sentinel v1.0.0 Validation Guide

This document provides instructions for validating Sentinel v1.0.0 against known vulnerable applications to achieve the 80% detection rate target.

## Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Git

## Validation Targets

Sentinel v1.0.0 should be validated against the following vulnerable applications:

### 1. crAPI (OWASP Community Resource API)

crAPI is an intentionally vulnerable API with 18+ known vulnerabilities.

**Setup:**
```bash
# Clone crAPI
git clone https://github.com/OWASP/crAPI

# Start crAPI using Docker
cd crAPI/deploy/docker
docker-compose -f docker-compose.yml up -d

# Wait for services to be ready (about 60 seconds)
docker-compose logs -f crapi-community
```

**Expected Detection Categories:**
- ✅ Rate Limiting (Challenge 6)
- ✅ Unauthenticated Access (Challenge 14)
- ✅ JWT Vulnerabilities (Challenge 15)
- ⚠️ BOLA/IDOR (requires authenticated testing)
- ⚠️ Mass Assignment
- ⚠️ SQL Injection
- ⚠️ NoSQL Injection
- ⚠️ SSRF

### 2. VAmPI (Vulnerable API)

**Setup:**
```bash
docker run -d -p 5000:5000 ghcr.io/erev0s/vampi:latest
```

### 3. Juice Shop (OWASP)

**Setup:**
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

## Running Validation

### Quick Validation Script

```bash
# Run the validation script
./scripts/validate_sentinel.sh
```

### Manual Validation

#### crAPI Validation

```bash
# Ensure crAPI is running on localhost:8888
curl http://localhost:8888

# Run Sentinel against crAPI
sentinel scan \
  --swagger /home/z/my-project/sentinel/benchmark_data/crapi_openapi.json \
  --target http://localhost:8888 \
  --output crapi_validation_report.md \
  --format markdown \
  --verbose

# Check detection rate
python3 scripts/calculate_detection_rate.py --target crapi --report crapi_validation_report.md
```

#### VAmPI Validation

```bash
# Run Sentinel against VAmPI
sentinel scan \
  --swagger https://raw.githubusercontent.com/erev0s/VAmPI/main/openapi_specs.yml \
  --target http://localhost:5000 \
  --output vampi_validation_report.md \
  --format markdown
```

## Detection Rate Calculation

The detection rate is calculated as:

```
Detection Rate = (Vulnerability Categories Found / Total Known Categories) × 100%
```

### crAPI Categories (18 total)

| Category | OWASP API Top 10 | Detection Status |
|----------|-----------------|------------------|
| BOLA (IDOR) | API1:2023 | ⚠️ Needs authenticated testing |
| Broken Auth | API2:2023 | ⚠️ Enhanced detection |
| Mass Assignment | API6:2023 | ✅ Implemented |
| Rate Limiting | API4:2023 | ✅ Implemented |
| BFLA | API5:2023 | ✅ Implemented |
| Injection (SQL) | API3:2023 | ✅ Enhanced |
| Injection (NoSQL) | API3:2023 | ✅ Implemented |
| SSRF | API10:2021 | ✅ Enhanced |
| JWT | API2:2023 | ✅ Implemented |
| Excessive Data | API3:2023 | ✅ Implemented |
| Unauthenticated Access | API7:2023 | ✅ Implemented |

## Required Detection Rate: 80%

To pass validation, Sentinel must detect at least 80% of known vulnerability categories:
- **Minimum categories required:** 15 out of 18 for crAPI
- **Target:** 15+ categories detected

## Test Coverage Requirements

Unit test coverage for attack modules must be ≥ 80%.

```bash
# Run tests with coverage
cd /home/z/my-project/sentinel
pytest --cov=sentinel/attacks --cov-report=html tests/unit/

# View coverage report
open htmlcov/index.html
```

## Validation Checklist

- [ ] crAPI running on localhost:8888
- [ ] VAmPI running on localhost:5000 (optional)
- [ ] All attack modules pass unit tests
- [ ] Test coverage ≥ 80%
- [ ] crAPI detection rate ≥ 80%
- [ ] No critical errors in scan output
- [ ] Reports generated successfully

## Troubleshooting

### crAPI not starting

```bash
# Check logs
docker-compose logs

# Restart services
docker-compose down
docker-compose up -d
```

### Low Detection Rate

1. Ensure you're using authenticated testing where required
2. Check that all attack modules are enabled
3. Verify the OpenAPI spec is correctly parsed
4. Review verbose output for errors

### Test Failures

```bash
# Run specific test
pytest tests/unit/test_injection_ssrf_enhanced.py -v

# Run with detailed output
pytest tests/unit/test_attacks.py -v --tb=long
```

## Release Criteria

Sentinel v1.0.0 may be released when:

1. ✅ All unit tests pass
2. ✅ Test coverage ≥ 80%
3. ✅ crAPI detection rate ≥ 80%
4. ✅ No critical or high-severity bugs in core modules
5. ✅ Documentation complete
