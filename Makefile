.PHONY: build run test clean docker-build docker-up docker-down

# Environment variables
APP_NAME=auth-service
BUILD_DIR=bin

# Build the application
build:
	@echo "Building $(APP_NAME)..."
	go build -o $(BUILD_DIR)/$(APP_NAME) main.go

# Run the application
run:
	@echo "Running $(APP_NAME)..."
	go run main.go

# Test targets
.PHONY: test test-unit test-integration test-coverage test-race

# Run all tests
test:
	@echo "Running all tests..."
	go test -v ./...

# Run unit tests only (exclude integration tests)
test-unit:
	@echo "Running unit tests..."
	go test -v ./... -short

# Run integration tests only
test-integration:
	@echo "Running integration tests..."
	go test -v ./... -run Integration

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated at coverage.html"

# Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	go test -race -v ./...

# Tidy up module dependencies
tidy:
	@echo "Tidying dependencies..."
	go mod tidy

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run

# Generate mock implementations for testing
mocks:
	@echo "Generating mocks..."
	mockgen -destination=mocks/mock_user_repository.go -package=mocks github.com/regiwitanto/auth-service/internal/repository UserRepository
	mockgen -destination=mocks/mock_token_repository.go -package=mocks github.com/regiwitanto/auth-service/internal/repository TokenRepository
	mockgen -destination=mocks/mock_auth_usecase.go -package=mocks github.com/regiwitanto/auth-service/internal/usecase AuthUseCase

# Migration tasks
migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir migrations -seq $${name}

migrate-up:
	migrate -path migrations -database "$(DB_URL)" up

migrate-down:
	migrate -path migrations -database "$(DB_URL)" down

# Docker tasks
docker-build:
	@echo "Building Docker image..."
	docker build -t $(APP_NAME) .

docker-up:
	@echo "Starting Docker containers..."
	docker-compose up -d

docker-down:
	@echo "Stopping Docker containers..."
	docker-compose down
