# Auth Service

A production-ready authentication microservice built with Go and Echo framework, following Clean Architecture principles. This service provides secure user authentication with JWT tokens, Redis for token management, and PostgreSQL for persistent storage.

## Features

- User registration and authentication
- JWT-based auth with access and refresh tokens
- Rate limiting protection
- Token management with Redis
- PostgreSQL for user data persistence
- Containerized with Docker
- Clean Architecture design

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│   HTTP Delivery  │     │     Use Cases    │     │    Repository     │     │    Data Store    │
│   (Controllers)  │────>│  (Business Logic)│────>│   (Data Access)   │────>│  (PostgreSQL/    │
│                  │     │                  │     │                   │     │      Redis)      │
└──────────────────┘     └──────────────────┘     └───────────────────┘     └──────────────────┘
        │                                                                            ▲
        │                                                                            │
        └────────────────────────────────────────────────────────────────────────────┘
                                  [Protected by JWT Authentication]
```

## Project Structure

```
auth-service/
├── .env.example             # Example environment variables
├── .env.test                # Test environment variables
├── config/                  # Configuration management
├── internal/                # Internal packages
│   ├── domain/              # Domain models and interfaces
│   ├── repository/          # Data access layer
│   ├── usecase/             # Business logic layer
│   ├── delivery/            # HTTP handlers and middleware
│   └── testutil/            # Testing utilities and mocks
├── tests/                   # Integration tests
├── Dockerfile               # Docker build instructions
├── docker-compose.yml       # Docker Compose services
├── main.go                  # Application entry point
└── Makefile                 # Build and development tasks
```

## Quick Start

### Prerequisites

- Go 1.21 or higher
- Docker and Docker Compose (for containerized deployment)

### Local Development Setup

1. Clone the repository and navigate to the project directory

2. Copy the example environment file and update with your settings:
   ```
   cp .env.example .env
   ```

3. Start the required services (PostgreSQL, Redis) using Docker Compose:
   ```
   docker-compose up -d postgres redis
   ```

4. Run the application:
   ```
   make run
   ```

### Docker Setup

Run the complete application stack in containers:
```
make docker-up
```

## API Examples

### Register a new user
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "Password123!",
    "email": "user@example.com"
  }'
```

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "Password123!"
  }'
```
Response contains access and refresh tokens.

### Get user profile (protected route)
```bash
curl -X GET http://localhost:8080/api/v1/user/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `APP_ENV` | Application environment | `development` |
| `HTTP_PORT` | HTTP server port | `8080` |
| `DB_HOST` | PostgreSQL hostname | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_USER` | PostgreSQL username | `postgres` |
| `DB_PASSWORD` | PostgreSQL password | `postgres` |
| `DB_NAME` | PostgreSQL database | `auth_service` |
| `REDIS_HOST` | Redis hostname | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `REDIS_PASSWORD` | Redis password | `` |
| `ACCESS_TOKEN_SECRET` | JWT access token secret | `access_secret` |
| `REFRESH_TOKEN_SECRET` | JWT refresh token secret | `refresh_secret` |
| `ACCESS_TOKEN_EXPIRY` | JWT access token expiry | `15m` |
| `REFRESH_TOKEN_EXPIRY` | JWT refresh token expiry | `7d` |
| `RATE_LIMIT` | API rate limit | `10` |

## Development

### Available Make Commands

- `make build` - Build the application binary
- `make run` - Run the application locally
- `make test` - Run all tests
- `make test-unit` - Run unit tests only
- `make test-integration` - Run integration tests only
- `make test-coverage` - Generate test coverage report
- `make test-fix` - Fix common test issues
- `make clean` - Clean build artifacts
- `make fmt` - Format code
- `make lint` - Lint code
- `make mocks` - Generate mock implementations
- `make docker-build` - Build Docker image
- `make docker-up` - Start all Docker containers
- `make docker-down` - Stop all Docker containers

## Testing

The project includes comprehensive test coverage following Go's standard testing conventions:

- **Unit Tests**: Test individual components with mocked dependencies
- **Integration Tests**: Test component interactions with real dependencies

### Running Tests

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests only
make test-integration

# Generate test coverage report
make test-coverage
```

Integration tests connect to real databases using `.env.test` configuration. These tests can be skipped in CI environments by setting the `CI=true` environment variable.

## Troubleshooting

### Common Issues

1. **Database connection errors**:
   - Ensure PostgreSQL is running and credentials in `.env` match
   - Verify the database exists: `CREATE DATABASE auth_service;`

2. **Redis connection issues**:
   - Check Redis is running and accessible on the configured port
   - Verify password settings if Redis auth is enabled

3. **Failed tests**:
   - Ensure test environment is properly set up with `.env.test`
   - Run `make test-fix` to resolve common test issues

## License

[MIT](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
