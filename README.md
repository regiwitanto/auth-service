# Auth Service

Authentication microservice built with Go and Echo framework. Provides JWT-based authentication with Redis token management and PostgreSQL storage.

## Features

- User registration and authentication
- JWT access and refresh tokens
- Password reset functionality
- IP-based rate limiting protection
- Role-based access control (RBAC)
- PostgreSQL for user data
- Redis for token management

## Quick Start

### Prerequisites

- Go 1.21+
- Docker and Docker Compose

### Setup

1. Configure environment:
   ```
   cp .env.example .env
   ```

2. Choose your preferred method to run:

   **Local Development:**
   ```
   docker-compose up -d postgres redis
   make run
   ```

   **Docker Setup:**
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
| POST | `/api/v1/auth/forgot-password` | Request password reset |
| POST | `/api/v1/auth/reset-password` | Reset password with token |

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

```bash
# Registration
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword",
    "username": "testuser"
  }'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword"
  }'
```

## Commands & Configuration

```bash
make run            # Run the application
make test           # Run all tests
make fmt            # Format code
```

Key environment variables:
- Database: `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` 
- Redis: `REDIS_HOST`, `REDIS_PORT`
- JWT: `JWT_SECRET`

See `.env.example` for all options.

## Troubleshooting

- **Database/Redis**: Verify connections and credentials in `.env`
- **Authentication**: Check JWT_SECRET configuration

## License

[MIT](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
