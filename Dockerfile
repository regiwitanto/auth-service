# Build stage
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/auth-service main.go

# Final stage
FROM alpine:3.19

# Install necessary packages
RUN apk --no-cache add ca-certificates tzdata

# Set timezone
ENV TZ=UTC

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /bin/auth-service .
COPY --from=builder /app/config/config.yaml ./config/

# Expose the application port
EXPOSE 3007

# Run the application
ENTRYPOINT ["./auth-service"]
