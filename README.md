# Auth Service

A microservice-ready authentication service built with Go and Echo framework, following Clean Architecture and DDD principles.

## Features

- User registration and authentication
- JWT-based authentication with access and refresh tokens
- Token management with Redis
- PostgreSQL for user data storage
- Containerized with Docker and Docker Compose
- Clean Architecture with clear separation of concerns

## Project Structure

```
auth-service/
├── .env.example             # Example environment variables
├── config/                  # Configuration files
│   ├── config.go            # Configuration loader
│   └── config.yaml          # Default configuration
├── internal/                # Internal packages
│   ├── domain/              # Domain models and interfaces
│   ├── repository/          # Data access layer
│   ├── usecase/             # Business logic layer
│   └── delivery/            # Presentation layer (HTTP handlers)
├── Dockerfile               # Docker build instructions
├── docker-compose.yml       # Docker Compose services definition
├── go.mod                   # Go module file
├── go.sum                   # Go dependencies checksum
├── main.go                  # Application entry point
└── Makefile                 # Build and development tasks
```

## Getting Started

### Prerequisites

- Go 1.21 or higher
- Docker and Docker Compose (for containerized deployment)
- PostgreSQL (local or containerized)
- Redis (local or containerized)

### Local Development Setup

1. Clone this repository:
   ```
   git clone https://github.com/regiwitanto/auth-service.git
   cd auth-service
   ```

2. Copy the example environment file and update with your settings:
   ```
   cp .env.example .env
   ```

3. Install dependencies:
   ```
   go mod download
   ```

4. Run the application:
   ```
   make run
   ```

### Docker Setup

1. Build and start the containers:
   ```
   make docker-up
   ```

2. Stop the containers:
   ```
   make docker-down
   ```

## API Endpoints

### Auth Routes

- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - User logout

### Protected Routes

- `GET /api/v1/user/me` - Get user profile (requires authentication)

### Health Check

- `GET /health` - Service health check

## Development

### Available Make Commands

- `make build` - Build the application
- `make run` - Run the application
- `make test` - Run tests
- `make test-coverage` - Run tests with coverage report
- `make tidy` - Tidy up module dependencies
- `make clean` - Clean build artifacts
- `make fmt` - Format code
- `make lint` - Lint code
- `make mocks` - Generate mock implementations for testing
- `make docker-build` - Build Docker image
- `make docker-up` - Start Docker containers
- `make docker-down` - Stop Docker containers

## License

[MIT](LICENSE)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
