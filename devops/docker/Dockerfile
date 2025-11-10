# Multi-stage Dockerfile for Verify API
# Stage 1: Build
FROM maven:3.8-openjdk-8 AS builder

WORKDIR /build

# Copy pom.xml (for dependency resolution)
COPY pom.xml .

# Download dependencies (cache layer)
RUN mvn dependency:go-offline -B

# Copy rest of source code
COPY src ./src

# Build application
RUN mvn clean package -DskipTests -B

# Stage 2: Runtime
FROM eclipse-temurin:8-jre

LABEL maintainer="Mersel <info@mersel.io>"
LABEL description="Mersel DSS Verify API - Dijital İmza Doğrulama Servisi"
LABEL version="0.1.0"

# Install required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user (security best practice)
RUN groupadd -r verifyapi && useradd -r -g verifyapi verifyapi

# Create directories
RUN mkdir -p /app/logs /app/certs /app/config && \
    chown -R verifyapi:verifyapi /app

WORKDIR /app

# Copy jar from builder stage
COPY --from=builder /build/target/mersel-dss-verify-api-*.jar /app/app.jar

# Copy configuration files
COPY --chown=verifyapi:verifyapi src/main/resources/application.properties /app/config/
COPY --chown=verifyapi:verifyapi src/main/resources/logback-spring.xml /app/config/

# Switch to non-root user
USER verifyapi

# Expose ports
EXPOSE 8086

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8086/actuator/health || exit 1

# Environment variables with defaults
ENV SERVER_PORT=8086 \
    LOG_PATH=/app/logs \
    JAVA_OPTS="-Xmx512m -Xms256m" \
    SPRING_PROFILES_ACTIVE=production

# Run application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar /app/app.jar"]

