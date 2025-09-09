#!/bin/bash
# startup.sh - Automatic startup script for AWS Nitro Enclave

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [STARTUP] $1" >&2
}

log "🚀 Enclave startup script started"

# Check if required files exist
if [ ! -f "/app/enclave_app.py" ]; then
    log "❌ ERROR: enclave_app.py not found"
    exit 1
fi

if [ ! -f "/app/vsock_server.py" ]; then
    log "❌ ERROR: vsock_server.py not found"
    exit 1
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    log "❌ ERROR: python3 not found"
    exit 1
fi

# Check if NSM device is available
if [ ! -c "/dev/nsm" ]; then
    log "⚠️  WARNING: /dev/nsm device not found - attestation may fail"
else
    log "✅ NSM device found at /dev/nsm"
fi

# Test Python imports
log "🔍 Testing Python dependencies..."
if ! python3 -c "import aws_nsm_interface, cbor2, socket, json; print('Dependencies OK')" 2>/dev/null; then
    log "❌ ERROR: Python dependencies check failed"
    exit 1
fi

log "✅ Python dependencies check passed"

# Change to application directory
cd /app || {
    log "❌ ERROR: Cannot change to /app directory"
    exit 1
}

# Start vsock server
log "🔥 Starting vsock server on port 9000..."
log "📝 Command: python3 enclave_app.py --vsock"

# Start the vsock server with error handling
exec python3 enclave_app.py --vsock 2>&1 | while IFS= read -r line; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [VSOCK] $line" >&2
done

# This line should never be reached due to exec, but just in case
log "❌ ERROR: Vsock server exited unexpectedly"
exit 1