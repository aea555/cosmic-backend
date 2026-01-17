# Stage 1: Build
FROM rust:1.92-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs for dependency caching
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src
COPY migrations ./migrations

# Build the application
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/cosmic-backend /app/cosmic-backend

# Copy migrations for runtime execution
COPY --from=builder /app/migrations /app/migrations

# Create non-root user for security
RUN useradd -r -s /bin/false cosmic && \
    chown -R cosmic:cosmic /app

USER cosmic

EXPOSE 8080

CMD ["/app/cosmic-backend"]
