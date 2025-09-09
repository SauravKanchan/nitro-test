#!/bin/bash
# startup.sh - Robust startup script for AWS Nitro Enclave

# Set error handling - DON'T exit on errors, just log them
set +e

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [STARTUP] $1" >&2
}

log "🚀 Enclave startup script started"

# Function to start fallback mode (keep container alive)
start_fallback() {
    log "🛡️  Starting fallback mode - container will stay alive"
    log "📝 You can manually start vsock server with: python3 /app/enclave_app.py --vsock"
    while true; do
        sleep 3600
    done
}

# Check if required files exist
log "🔍 Checking required files..."
if [ ! -f "/app/enclave_app.py" ]; then
    log "❌ ERROR: enclave_app.py not found"
    start_fallback
fi

if [ ! -f "/app/vsock_server.py" ]; then
    log "❌ ERROR: vsock_server.py not found"  
    start_fallback
fi

log "✅ Required files found"

# Check if Python is available
log "🔍 Checking Python availability..."
if ! command -v python3 &> /dev/null; then
    log "❌ ERROR: python3 not found"
    start_fallback
fi

log "✅ Python3 found"

# Check if NSM device is available
if [ ! -c "/dev/nsm" ]; then
    log "⚠️  WARNING: /dev/nsm device not found - attestation may fail in production"
    log "ℹ️  This is normal in debug mode"
else
    log "✅ NSM device found at /dev/nsm"
fi

# Test Python imports with detailed error reporting
log "🔍 Testing Python dependencies..."
python3 -c "
import sys
try:
    import aws_nsm_interface
    print('✅ aws_nsm_interface imported successfully', file=sys.stderr)
except Exception as e:
    print(f'❌ Failed to import aws_nsm_interface: {e}', file=sys.stderr)
    
try:
    import cbor2
    print('✅ cbor2 imported successfully', file=sys.stderr)
except Exception as e:
    print(f'❌ Failed to import cbor2: {e}', file=sys.stderr)
    
try:
    import socket, json, threading, time
    print('✅ Standard libraries imported successfully', file=sys.stderr)
except Exception as e:
    print(f'❌ Failed to import standard libraries: {e}', file=sys.stderr)
" 2>&1 | while IFS= read -r line; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [DEPS] $line" >&2
done

# Check if basic import test passes
if ! python3 -c "import aws_nsm_interface, cbor2, socket, json" 2>/dev/null; then
    log "❌ ERROR: Python dependencies check failed - starting fallback mode"
    start_fallback
fi

log "✅ Python dependencies check passed"

# Change to application directory
if ! cd /app; then
    log "❌ ERROR: Cannot change to /app directory - starting fallback mode"
    start_fallback
fi

log "✅ Changed to /app directory"

# Start vsock server with robust error handling
log "🔥 Attempting to start vsock server on port 9000..."
log "📝 Command: python3 enclave_app.py --vsock"

# Try to start vsock server, but fall back if it fails
(
    python3 enclave_app.py --vsock 2>&1 | while IFS= read -r line; do
        echo "$(date '+%Y-%m-%d %H:%M:%S') [VSOCK] $line" >&2
    done
) &

VSOCK_PID=$!
log "📊 Vsock server started with PID: $VSOCK_PID"

# Monitor the vsock server process
sleep 5

if kill -0 $VSOCK_PID 2>/dev/null; then
    log "✅ Vsock server is running successfully"
    # Wait for the vsock server process
    wait $VSOCK_PID
    log "⚠️  Vsock server exited, starting fallback mode"
    start_fallback
else
    log "❌ Vsock server failed to start, starting fallback mode"
    start_fallback
fi