# Auth Service

A clean, production-ready authentication microservice built with Go and Echo framework. Provides JWT-based authentication with Redis token management and PostgreSQL storage.

## Features

- User registration and authentication
- JWT access and refresh tokens
- IP-based rate limiting protection
- Role-based access control (RBAC)
- PostgreSQL for user data
- Redis for token management
- Clean Architecture design

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│   HTTP Delivery  │     │     Use Cases    │     │    Repository     │     │    Data Store    │
│   (Controllers)  │────>│  (Business Logic)│────>│   (Data Access)   │────>│  (PostgreSQL/    │
│                  │     │                  │     │                   │     │      Redis)      │
└──────────────────┘     └──────────────────┘     └───────────────────┘     └──────────────────┘
```

## Project Structure

```
auth-service/
├── config/                 # Configuration
├── internal/               # Private code
│   ├── delivery/           # HTTP handlers/middleware
│   ├── domain/             # Business entities
│   ├── mocks/              # Mock implementations for testing
│   ├── repository/         # Data access
│   ├── testutil/           # Testing utilities
│   └── usecase/            # Business logic
├── .env.example            # Example environment variables
├── .env.test               # Test environment variables
├── Dockerfile              # Container configuration
├── docker-compose.yml      # Multi-container setup
├── go.mod                  # Go module definition
├── go.sum                  # Go module checksums
├── main.go                 # Entry point
└── Makefile                # Build commands
```

## Quick Start

### Prerequisites

- Go 1.21+
- Docker and Docker Compose

### Local Development

1. Clone the repository
2. Configure environment:
   ```
   cp .env.example .env
   ```
3. Start dependencies:
   ```
   docker-compose up -d postgres redis
   ```
4. Run the application:
   ```
   make run
   ```

### Docker Setup

Run everything in containers:
```
docker-compose up -d
```

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Create new user |
| POST | `/api/v1/auth/login` | Authenticate user |
| POST | `/api/v1/auth/refresh` | Get new access token |
| POST | `/api/v1/auth/logout` | Invalidate tokens |

### User Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/user/me` | Get user profile |

### Admin Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/users` | Get all users |
| GET | `/api/v1/admin/stats` | Get system stats |

## Example Requests

### Registration

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "securepassword",
    "first_name": "Test",
    "last_name": "User"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword"
  }'
```

### Common Commands

```bash
# Run the application
make run

# Run all tests
make test

# Run unit tests only
make test-unit

# Format code
make fmt

# Generate test coverage report
make test-coverage

# Clean build artifacts
make clean
```

## Configuration

Key environment variables:
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: PostgreSQL settings
- `REDIS_HOST`, `REDIS_PORT`: Redis settings
- `JWT_SECRET`: Secret for signing JWTs
- `SERVER_PORT`: HTTP server port

See `.env.example` for all configuration options.

## Troubleshooting

1. **Database connection errors**:
   - Ensure PostgreSQL is running and credentials in `.env` match
   - Verify the database exists and is accessible

2. **Redis connection issues**:
   - Check Redis is running and accessible on the configured port
   - Verify password settings if Redis auth is enabled

3. **Authentication issues**:
   - Verify that JWT_SECRET is properly configured
   - Check that token expiration times are appropriate

## License

[MIT](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
