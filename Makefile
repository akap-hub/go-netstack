# Go TCP/IP Stack Makefile

BINARY = tcp-ip-stack
SRC_DIR = src

# Default target
all: build

# Build the main application
build:
	cd $(SRC_DIR) && go build -o ../$(BINARY) .

# Run the main application with interactive CLI
run: build
	./$(BINARY)

# Run integration tests
test:
	cd $(SRC_DIR) && go test -v

# Run specific test suites
test-integration:
	cd $(SRC_DIR) && go test -v -run TestFullSystemIntegration

test-data:
	cd $(SRC_DIR) && go test -v -run TestDataTransmission

test-flood:
	cd $(SRC_DIR) && go test -v -run TestPacketFlooding

test-stress:
	cd $(SRC_DIR) && go test -v -run TestSystemStress

# Clean built binaries
clean:
	rm -f $(BINARY) go-tcp-ip-test

# Format Go code
fmt:
	cd $(SRC_DIR) && go fmt *.go

# Check for Go errors
check:
	cd $(SRC_DIR) && go vet *.go

# Development workflow: format, check, build, test
dev: fmt check build test

# Show help
help:
	@echo "Available targets:"
	@echo "  build           - Build the main application"
	@echo "  run             - Build and run the interactive CLI"
	@echo "  test            - Run all integration tests"
	@echo "  test-integration - Run full system integration test"
	@echo "  test-data       - Run data transmission test"
	@echo "  test-flood      - Run packet flooding test"
	@echo "  test-stress     - Run stress test"
	@echo "  clean           - Remove built binaries"
	@echo "  fmt             - Format Go code"
	@echo "  check           - Run Go vet"
	@echo "  dev             - Complete development workflow"
	@echo "  help            - Show this help message"

.PHONY: all build run test test-integration test-data test-flood test-stress clean fmt check dev help