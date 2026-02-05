.PHONY: build test lint clean install

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Build the binary
build:
	go build $(LDFLAGS) -o bin/si-gen ./cmd/si-gen

# Install to GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd/si-gen

# Run tests
test:
	go test -v -race -coverprofile=coverage.out ./...

# Run tests with coverage report
test-coverage: test
	go tool cover -html=coverage.out -o coverage.html

# Run linter
lint:
	golangci-lint run ./...

# Format code
fmt:
	go fmt ./...
	goimports -w .

# Download dependencies
deps:
	go mod download
	go mod tidy

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Run the generate command (for development)
run-generate:
	go run ./cmd/si-gen generate --verbose

# Run the validate command (for development)
run-validate:
	go run ./cmd/si-gen validate --verbose

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/si-gen-linux-amd64 ./cmd/si-gen
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/si-gen-linux-arm64 ./cmd/si-gen
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/si-gen-darwin-amd64 ./cmd/si-gen
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/si-gen-darwin-arm64 ./cmd/si-gen
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/si-gen-windows-amd64.exe ./cmd/si-gen

# Help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  install       - Install to GOPATH/bin"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  deps          - Download and tidy dependencies"
	@echo "  clean         - Clean build artifacts"
	@echo "  build-all     - Build for all platforms"
	@echo "  help          - Show this help"
