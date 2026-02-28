.PHONY: install test clean run-server help

help:
	@echo "Sentinel - AI-powered API Security Testing Tool"
	@echo ""
	@echo "Usage:"
	@echo "  make install     Install dependencies"
	@echo "  make test        Run Sentinel against test API"
	@echo "  make run-server  Start vulnerable test API"
	@echo "  make clean       Clean up generated files"
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
