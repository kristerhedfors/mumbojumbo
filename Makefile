# Mumbojumbo Master Makefile
# Builds all clients and runs comprehensive test suite

.PHONY: all test clean build-clients test-python test-clients help

# Default target
all: build-clients test

help:
	@echo "Mumbojumbo Build and Test Targets:"
	@echo ""
	@echo "  make all             - Build all clients and run full test suite"
	@echo "  make build-clients   - Build all client binaries (C, Go, Rust)"
	@echo "  make test            - Run complete test suite (Python + all clients)"
	@echo "  make test-python     - Run Python server tests only"
	@echo "  make test-clients    - Run client build and execution tests"
	@echo "  make clean           - Clean all build artifacts"
	@echo ""

# Build all client binaries
build-clients: build-c build-go build-rust build-nodejs

build-c:
	@echo "==> Building C client..."
	$(MAKE) -C clients/c clean
	$(MAKE) -C clients/c all
	@echo ""

build-go:
	@echo "==> Building Go client..."
	cd clients/go && go mod tidy && go build -o mumbojumbo-client
	@echo ""

build-rust:
	@echo "==> Building Rust client..."
	cd clients/rust && cargo build
	@echo ""

build-nodejs:
	@echo "==> Checking Node.js client dependencies..."
	@test -d clients/nodejs/node_modules || (cd clients/nodejs && npm install)
	@echo ""

# Test targets
test: test-python test-clients
	@echo ""
	@echo "==> All tests completed successfully!"
	@echo ""

test-python:
	@echo "==> Running Python server tests..."
	./venv/bin/pytest tests/ --tb=no -q
	@echo ""

test-clients: build-clients
	@echo "==> Running client build and execution tests..."
	./venv/bin/pytest tests/test_client_builds.py -v
	@echo ""

# Clean all build artifacts
clean: clean-c clean-go clean-rust
	@echo "==> Cleaning Python cache..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo ""

clean-c:
	@echo "==> Cleaning C client..."
	$(MAKE) -C clients/c clean
	@echo ""

clean-go:
	@echo "==> Cleaning Go client..."
	cd clients/go && rm -f mumbojumbo-client
	@echo ""

clean-rust:
	@echo "==> Cleaning Rust client..."
	cd clients/rust && cargo clean
	@echo ""
