.PHONY: install test clean run-server help benchmark benchmark-status

help:
        @echo "Sentinel - AI-powered API Security Testing Tool"
        @echo ""
        @echo "Usage:"
        @echo "  make install         Install dependencies"
        @echo "  make test            Run Sentinel against test API"
        @echo "  make run-server      Start vulnerable test API"
        @echo "  make clean           Clean up generated files"
        @echo ""
        @echo "Benchmark Commands:"
        @echo "  make benchmark       Run all benchmarks (one at a time)"
        @echo "  make benchmark-crapi Run crAPI benchmark only"
        @echo "  make benchmark-juice-shop Run Juice Shop benchmark only"
        @echo "  make benchmark-status Check if Docker is running"
        @echo ""

install:
        pip install -r requirements.txt

run-server:
        cd test_server && python vulnerable_api.py

test:
        python -m sentinel scan --swagger examples/sample_api.yaml --target http://localhost:8000 --verbose

clean:
        rm -f sentinel_report.md
        find . -type d -name "__pycache__" -exec rm -rf {} +
        find . -type f -name "*.pyc" -delete
        rm -rf benchmark-results/

# Benchmark commands (runs one container at a time)
benchmark:
        python scripts/run_benchmarks.py

benchmark-crapi:
        python scripts/run_benchmarks.py --target crapi

benchmark-juice-shop:
        python scripts/run_benchmarks.py --target juice-shop

benchmark-dvwa:
        python scripts/run_benchmarks.py --target dvwa

benchmark-webgoat:
        python scripts/run_benchmarks.py --target webgoat

benchmark-vampi:
        python scripts/run_benchmarks.py --target vampi

benchmark-status:
        @docker info > /dev/null 2>&1 && echo "✅ Docker is running" || echo "❌ Docker is not running"
