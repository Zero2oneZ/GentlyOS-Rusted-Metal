#!/bin/bash
# GentlyOS Docker Build Script
# Creates production-ready Docker images

set -e

VERSION="${GENTLY_VERSION:-1.1.1}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REGISTRY="${DOCKER_REGISTRY:-ghcr.io/gentlyos}"

cd "${PROJECT_ROOT}"

echo "Building GentlyOS Docker images v${VERSION}..."

# Build main image
docker build \
    --tag "gentlyos:${VERSION}" \
    --tag "gentlyos:latest" \
    --tag "${REGISTRY}/gentlyos:${VERSION}" \
    --tag "${REGISTRY}/gentlyos:latest" \
    --build-arg VERSION="${VERSION}" \
    --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --build-arg VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
    --file Dockerfile \
    .

# Build minimal image (no dev tools)
docker build \
    --tag "gentlyos:${VERSION}-minimal" \
    --tag "${REGISTRY}/gentlyos:${VERSION}-minimal" \
    --file Dockerfile.minimal \
    .

# Build with CUDA support (for studio edition)
if [ -f Dockerfile.cuda ]; then
    docker build \
        --tag "gentlyos:${VERSION}-cuda" \
        --tag "${REGISTRY}/gentlyos:${VERSION}-cuda" \
        --file Dockerfile.cuda \
        .
fi

echo ""
echo "Docker images built:"
docker images | grep gentlyos | head -10

# Export for offline use
mkdir -p "${PROJECT_ROOT}/dist"
docker save "gentlyos:${VERSION}" | gzip > "${PROJECT_ROOT}/dist/gentlyos-${VERSION}-docker.tar.gz"
echo "Exported: dist/gentlyos-${VERSION}-docker.tar.gz"

# Generate docker-compose for easy deployment
cat > "${PROJECT_ROOT}/dist/docker-compose.yml" << EOF
# GentlyOS v${VERSION} - Docker Compose
# Usage: docker-compose up -d

version: '3.8'

services:
  gentlyos:
    image: gentlyos:${VERSION}
    container_name: gentlyos
    restart: unless-stopped
    ports:
      - "3000:3000"   # MCP Server
      - "4001:4001"   # IPFS Swarm
      - "8080:8080"   # Health/Metrics
    volumes:
      - gentlyos-data:/data
      - gentlyos-config:/home/gently/.gentlyos
    environment:
      - GENTLY_LOG_LEVEL=info
      - RUST_LOG=info
    healthcheck:
      test: ["CMD", "gently", "status"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  gentlyos-data:
  gentlyos-config:
EOF

echo "Generated: dist/docker-compose.yml"
