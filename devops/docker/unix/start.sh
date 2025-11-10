#!/bin/bash

# Verify API Docker Compose Starter
# Usage: ./start.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$DOCKER_DIR"

echo "🚀 Starting Verify API with Docker Compose..."
echo "📁 Working directory: $DOCKER_DIR"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running!"
    echo "Please start Docker Desktop and try again."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Error: docker-compose not found!"
    echo "Please install docker-compose and try again."
    exit 1
fi

# Pull latest images
echo "📦 Pulling latest images..."
docker-compose pull

# Start services
echo "🐳 Starting services..."
docker-compose up -d

# Wait for services to be ready
echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check health
echo ""
echo "🏥 Checking service health..."
echo ""

# Check Verify API
if curl -sf http://localhost:8086/actuator/health > /dev/null 2>&1; then
    echo "✅ Verify API is healthy!"
else
    echo "⚠️  Verify API is not ready yet (this is normal, wait a bit)"
fi

# Check Prometheus
if curl -sf http://localhost:9090/-/healthy > /dev/null 2>&1; then
    echo "✅ Prometheus is healthy!"
else
    echo "⚠️  Prometheus is not ready yet"
fi

# Check Grafana
if curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
    echo "✅ Grafana is healthy!"
else
    echo "⚠️  Grafana is not ready yet"
fi

echo ""
echo "🎉 Verify API Stack Started!"
echo ""
echo "📍 Access Points:"
echo "   - Verify API:  http://localhost:8086"
echo "   - Health:      http://localhost:8086/actuator/health"
echo "   - API Docs:    http://localhost:8086/api-docs"
echo "   - Prometheus:  http://localhost:9090"
echo "   - Grafana:     http://localhost:3000 (admin/admin)"
echo ""
echo "📊 Useful Commands:"
echo "   - View logs:   docker-compose logs -f verify-api"
echo "   - Stop:        docker-compose stop"
echo "   - Restart:     docker-compose restart"
echo "   - Remove:      docker-compose down"
echo ""

