#!/bin/bash
# build-enclave.sh - Script to build AWS Nitro Enclave image

set -e

# Configuration
IMAGE_NAME="nitro-attestation"
EIF_NAME="app.eif"
DOCKER_TAG="latest"

# Check for running enclaves and terminate them
echo "🔍 Checking for running enclaves..."
RUNNING_ENCLAVES=$(sudo nitro-cli describe-enclaves 2>/dev/null || echo "[]")

if [ "$RUNNING_ENCLAVES" != "[]" ] && [ "$(echo "$RUNNING_ENCLAVES" | jq '. | length')" -gt 0 ]; then
    echo "🛑 Found running enclaves, terminating them..."
    sudo nitro-cli terminate-enclave --all
    echo "✅ All enclaves terminated"
    
    # Wait a moment for cleanup
    sleep 2
else
    echo "✅ No running enclaves found"
fi

echo "🔨 Building Docker image for Nitro Enclave..."

# Build the Docker image
docker build -t "${IMAGE_NAME}:${DOCKER_TAG}" .

echo "✅ Docker image built successfully: ${IMAGE_NAME}:${DOCKER_TAG}"

echo "🔨 Building Nitro Enclave image (.eif)..."

# Check if EIF file already exists and remove it
if [ -f "${EIF_NAME}" ]; then
    echo "🗑️  Removing existing EIF file: ${EIF_NAME}"
    rm -f "${EIF_NAME}"
    echo "✅ Old EIF file removed"
fi

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
echo "nitro-cli run-enclave --cpu-count 2 --memory 1920 --eif-path ${EIF_NAME} --debug-mode"