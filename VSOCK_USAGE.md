# Vsock Communication Usage Guide

This document explains how to use the vsock communication system for automated attestation document transfer between the AWS Nitro Enclave and parent instance.

## Overview

The vsock (Virtual Socket) system provides a robust communication channel that eliminates the need for manual copy/paste of attestation documents. The enclave runs a server that responds to attestation requests from the parent instance.

## Architecture

```
┌─────────────────────┐    Vsock     ┌─────────────────────┐
│   Parent Instance   │◄──────────►│   Nitro Enclave     │
│                     │   Port 9000  │                     │
│  vsock_client.py    │              │  vsock_server.py    │
│  verifier.py        │              │  enclave_app.py     │
└─────────────────────┘              └─────────────────────┘
```

## Quick Start

### 1. Build and Start Enclave with Vsock Server

```bash
# Build enclave (includes vsock server automatically)
./build-enclave.sh

# Start enclave (automatically starts vsock server on port 9000)
nitro-cli run-enclave --cpu-count 1 --memory 1920 --eif-path app.eif

# Verify enclave is running
sudo nitro-cli describe-enclaves
```

### 2. Test Connection from Parent

```bash
# Test basic connectivity
python3 vsock_client.py --ping

# Get enclave status
python3 vsock_client.py --status
```

### 3. Request and Verify Attestations

```bash
# Basic attestation
python3 vsock_client.py --verify

# Attestation with ephemeral key
python3 vsock_client.py --verify --generate-key

# Custom attestation
python3 vsock_client.py --verify --user-data "my-session-token" --nonce "challenge-123" --generate-key

# Save to file
python3 vsock_client.py --attest --generate-key --save attestation.b64
```

## Detailed Usage

### Vsock Client Commands

**Connection Testing:**
```bash
# Test connection (should return "Pong!")
python3 vsock_client.py --ping

# Get enclave status and uptime
python3 vsock_client.py --status

# Use specific enclave CID (auto-detected by default)
python3 vsock_client.py --cid 18 --ping
```

**Attestation Requests:**
```bash
# Basic attestation (manual verification needed)
python3 vsock_client.py --attest

# Attestation with automatic verification
python3 vsock_client.py --verify

# Attestation with ephemeral keypair generation
python3 vsock_client.py --verify --generate-key

# Custom user data and nonce
python3 vsock_client.py --verify \
  --user-data "session-12345" \
  --nonce "challenge-abc" \
  --generate-key

# Save attestation to file
python3 vsock_client.py --attest --generate-key --save my_attestation.b64

# JSON output for automation
python3 vsock_client.py --verify --generate-key --json
```

**Advanced Options:**
```bash
# Custom timeout and port
python3 vsock_client.py --timeout 60 --port 9001 --verify

# Manual CID specification
python3 vsock_client.py --cid 25 --verify
```

### Enclave Server Modes

The enclave supports multiple operation modes:

**Automatic Vsock Server (Default):**
```bash
# Enclave automatically starts vsock server when launched
nitro-cli run-enclave --cpu-count 1 --memory 1920 --eif-path app.eif
```

**Manual Server Start (if needed):**
```bash
# Connect to enclave console
nitro-cli console --enclave-name $(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# Inside enclave - start server manually on custom port
python3 /app/enclave_app.py --vsock 9001
```

**Other Modes (for testing):**
```bash
# Interactive daemon mode
python3 /app/enclave_app.py --daemon

# One-shot attestation
python3 /app/enclave_app.py --generate-key
```

## Protocol Details

### Request Format (JSON)

The client sends JSON requests to the enclave:

```json
{
  "command": "attest",
  "user_data": "hello-from-enclave",
  "nonce": "optional-nonce",
  "generate_key": true
}
```

**Available Commands:**
- `ping` - Test connectivity
- `status` - Get server status
- `attest` - Request attestation document

### Response Format (JSON)

The enclave responds with JSON:

```json
{
  "success": true,
  "attestation_document": "base64-encoded-cose-document",
  "user_data": "hello-from-enclave",
  "nonce": "optional-nonce",
  "has_public_key": true,
  "document_size": 1234,
  "timestamp": 1674123456789
}
```

## Integration Examples

### Python Script Integration

```python
#!/usr/bin/env python3
from vsock_client import VsockAttestationClient

# Create client (auto-detects enclave CID)
client = VsockAttestationClient(enclave_cid=None)  

# Test connection
if not client.ping():
    print("Enclave not reachable")
    exit(1)

# Request attestation with verification
response = client.request_and_verify(
    user_data="my-app-session-token",
    nonce="unique-challenge",
    generate_key=True
)

if response["verified"]:
    print(f"✅ Enclave verified: {response['verification']['module_id']}")
    
    # Extract public key for encryption
    if response["has_public_key"]:
        # Use the public key from verification result
        enclave_pubkey = response["verification"]["public_key"]
        # ... encrypt data to enclave
else:
    print(f"❌ Verification failed: {response.get('verification_error')}")
```

### Bash Script Integration

```bash
#!/bin/bash
# Request attestation and save to file
python3 vsock_client.py --verify --generate-key --save /tmp/attestation.b64 --json > /tmp/response.json

# Check if verification succeeded
if jq -r '.verified' /tmp/response.json | grep -q true; then
    echo "✅ Attestation verified successfully"
    MODULE_ID=$(jq -r '.verification.module_id' /tmp/response.json)
    echo "Module ID: $MODULE_ID"
else
    echo "❌ Attestation verification failed"
    exit 1
fi
```

## Troubleshooting

### Common Issues

**"Connection refused" errors:**
```bash
# Check if enclave is running
sudo nitro-cli describe-enclaves

# Check if vsock server started (look at console logs)
nitro-cli console --enclave-name $(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

**"No running enclaves found":**
```bash
# Start the enclave first
nitro-cli run-enclave --cpu-count 1 --memory 1920 --eif-path app.eif

# Or check if it terminated due to build issues
sudo nitro-cli describe-enclaves
```

**Timeout issues:**
```bash
# Increase timeout
python3 vsock_client.py --timeout 60 --verify

# Check enclave console for errors
nitro-cli console --enclave-name <enclave-id>
```

**Auto-detection failures:**
```bash
# Manually specify CID
ENCLAVE_CID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')
python3 vsock_client.py --cid $ENCLAVE_CID --verify
```

### Debug Mode

For debugging, you can run the enclave in debug mode:

```bash
# Start enclave in debug mode (PCRs will be all zeros - not for production!)
nitro-cli run-enclave --cpu-count 1 --memory 1920 --eif-path app.eif --debug-mode

# Connect to console to see detailed logs
nitro-cli console --enclave-name $(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

## Production Considerations

### Security

- **Never use `--debug-mode`** in production (PCR measurements will be invalid)
- **Validate PCR values** in production verification
- **Use unique nonces** to prevent replay attacks
- **Implement rate limiting** for attestation requests

### Performance

- **Connection pooling**: The vsock server handles multiple concurrent connections
- **Caching**: Consider caching attestation documents for short periods
- **Resource limits**: Monitor enclave CPU and memory usage

### Monitoring

```bash
# Monitor enclave status
watch 'sudo nitro-cli describe-enclaves'

# Test connectivity periodically
python3 vsock_client.py --ping

# Check attestation document freshness
python3 vsock_client.py --status --json | jq '.uptime'
```

## Advanced Usage

### Custom Protocol Implementation

You can extend the protocol by modifying `vsock_server.py` and `vsock_client.py`:

1. Add new commands to the server's `process_request()` method
2. Add corresponding client methods
3. Update the request/response schema

### Multiple Enclaves

```bash
# Run multiple enclaves on different ports
nitro-cli run-enclave --cpu-count 1 --memory 1920 --eif-path app1.eif
nitro-cli run-enclave --cpu-count 1 --memory 1920 --eif-path app2.eif

# Connect to specific enclave
python3 vsock_client.py --cid 18 --verify  # First enclave
python3 vsock_client.py --cid 19 --verify  # Second enclave
```

This vsock system provides a production-ready, automated way to generate and verify attestation documents without manual intervention!