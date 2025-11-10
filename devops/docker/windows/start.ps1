# Verify API Docker Compose Starter (PowerShell)
# Usage: .\start.ps1

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$dockerDir = Split-Path -Parent $scriptDir

Set-Location $dockerDir

Write-Host "🚀 Starting Verify API with Docker Compose..." -ForegroundColor Green
Write-Host "📁 Working directory: $dockerDir" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
try {
    docker info | Out-Null
} catch {
    Write-Host "❌ Error: Docker is not running!" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and try again." -ForegroundColor Yellow
    exit 1
}

# Check if docker-compose is available
if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Error: docker-compose not found!" -ForegroundColor Red
    Write-Host "Please install docker-compose and try again." -ForegroundColor Yellow
    exit 1
}

# Pull latest images
Write-Host "📦 Pulling latest images..." -ForegroundColor Yellow
docker-compose pull

# Start services
Write-Host "🐳 Starting services..." -ForegroundColor Yellow
docker-compose up -d

# Wait for services to be ready
Write-Host ""
Write-Host "⏳ Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check health
Write-Host ""
Write-Host "🏥 Checking service health..." -ForegroundColor Yellow
Write-Host ""

# Check Verify API
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8086/actuator/health" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Verify API is healthy!" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️  Verify API is not ready yet (this is normal, wait a bit)" -ForegroundColor Yellow
}

# Check Prometheus
try {
    $response = Invoke-WebRequest -Uri "http://localhost:9090/-/healthy" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Prometheus is healthy!" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️  Prometheus is not ready yet" -ForegroundColor Yellow
}

# Check Grafana
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000/api/health" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Grafana is healthy!" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️  Grafana is not ready yet" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 Verify API Stack Started!" -ForegroundColor Green
Write-Host ""
Write-Host "📍 Access Points:" -ForegroundColor Cyan
Write-Host "   - Verify API:  http://localhost:8086"
Write-Host "   - Health:      http://localhost:8086/actuator/health"
Write-Host "   - API Docs:    http://localhost:8086/api-docs"
Write-Host "   - Prometheus:  http://localhost:9090"
Write-Host "   - Grafana:     http://localhost:3000 (admin/admin)"
Write-Host ""
Write-Host "📊 Useful Commands:" -ForegroundColor Cyan
Write-Host "   - View logs:   docker-compose logs -f verify-api"
Write-Host "   - Stop:        docker-compose stop"
Write-Host "   - Restart:     docker-compose restart"
Write-Host "   - Remove:      docker-compose down"
Write-Host ""

