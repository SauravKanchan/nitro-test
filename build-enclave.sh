#!/bin/bash
# build-enclave.sh - Script to build AWS Nitro Enclave image

set -e

# Configuration
IMAGE_NAME="nitro-attestation"
EIF_NAME="app.eif"
DOCKER_TAG="latest"

echo "🔨 Building Docker image for Nitro Enclave..."

# Build the Docker image
docker build -t "${IMAGE_NAME}:${DOCKER_TAG}" .

echo "✅ Docker image built successfully: ${IMAGE_NAME}:${DOCKER_TAG}"

echo "🔨 Building Nitro Enclave image (.eif)..."

# Build the enclave image file
nitro-cli build-enclave \
    --docker-uri "${IMAGE_NAME}:${DOCKER_TAG}" \
    --output-file "${EIF_NAME}"

echo "✅ Enclave image built successfully: ${EIF_NAME}"

# Show the EIF info
echo "📋 Enclave image information:"
nitro-cli describe-eif --eif-path "${EIF_NAME}"

echo ""
echo "🚀 Ready to run enclave with:"
echo "   nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path ${EIF_NAME}"