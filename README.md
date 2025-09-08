# AWS Nitro Enclaves Attestation Document Generator & Verifier

This project implements Python code to generate and verify AWS Nitro Enclaves attestation documents, providing cryptographic proof that code is running inside a genuine AWS Nitro Enclave.

## Overview

- **`enclave_app.py`** - Runs inside the enclave to generate attestation documents using the NSM API
- **`verifier.py`** - Runs on the parent instance to verify attestation documents  
- **`test_attestation.py`** - Comprehensive test suite
- **`requirements.txt`** - Python dependencies

## Prerequisites

- AWS EC2 instance with Nitro Enclaves enabled (M5n, M5dn, R5n, R5dn, C5n, C6i, etc.)
- `nitro-cli` installed and configured
- Docker for building enclave images
- Python 3.8+

## Quick Start

### 1. Install Dependencies

**On parent instance:**
```bash
pip install python-cose cryptography cbor2 pytest
```

**For enclave image (in Dockerfile):**
```bash
pip install aws-nsm-interface cryptography cbor2
```

### 2. Build Enclave Image

Create a `Dockerfile`:
```dockerfile
FROM amazonlinux:2

# Install Python and dependencies
RUN yum update -y && yum install -y python3 python3-pip
RUN pip3 install aws-nsm-interface cryptography cbor2

# Copy enclave application
COPY enclave_app.py /app/
WORKDIR /app

# Run the enclave app
CMD ["python3", "enclave_app.py"]
```

Build the enclave image:
```bash
docker build -t nitro-attestation .
nitro-cli build-enclave --docker-uri nitro-attestation --output-file app.eif
```

### 3. Run Enclave

```bash
nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path app.eif
```

### 4. Generate Attestation Document

**Inside the enclave:**
```bash
# Basic usage
python3 enclave_app.py

# Generate with ephemeral keypair
python3 enclave_app.py --generate-key

# Custom user data and nonce
python3 enclave_app.py --generate-key "my-custom-data" "my-nonce-123"
```

The enclave will output a base64-encoded attestation document to stdout.

### 5. Verify Attestation Document

**On parent instance:**
```bash
# Verify from stdin
echo "your-base64-attestation-doc" | python3 verifier.py

# Verify from file  
python3 verifier.py attestation.txt

# Get detailed JSON output
python3 verifier.py --json < attestation.txt
```

## Usage Examples

### Complete Workflow

1. **Terminal 1 (Parent):** Start enclave
```bash
nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path app.eif
```

2. **Terminal 2 (Enclave Console):** Connect to enclave
```bash
nitro-cli console --enclave-name $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

3. **In Enclave:** Generate attestation
```bash
python3 enclave_app.py --generate-key > /tmp/attestation.b64
```

4. **Terminal 1 (Parent):** Copy and verify
```bash
# Get the attestation document from enclave
nitro-cli console --enclave-name $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID') --disconnect

# Verify the document
python3 verifier.py /path/to/attestation.b64
```

### Advanced Usage

**Custom user data and nonce:**
```bash
# In enclave
python3 enclave_app.py --generate-key "session-token-xyz" "nonce-abc123"

# On parent (with validation)
python3 verifier.py --expected-user-data "session-token-xyz" attestation.txt
```

## Testing

Run the test suite:
```bash
pytest test_attestation.py -v
```

Run with coverage:
```bash
pytest test_attestation.py --cov=verifier --cov-report=html
```

## Files Description

### `enclave_app.py`
- Requests attestation documents from NSM (`/dev/nsm`)
- Optionally generates ephemeral ECDSA P-384 keypairs
- Supports custom user data and nonces
- Outputs base64-encoded COSE documents

### `verifier.py`  
- Parses COSE_Sign1 documents with CBOR payloads
- Validates X.509 certificate chains to AWS Nitro Root
- Verifies COSE signatures using ES384
- Checks timestamp freshness and semantic constraints
- Supports JSON output for integration

### `test_attestation.py`
- Unit tests for all verification components
- Mock document generation for testing
- Error handling and edge case validation
- Integration test framework (requires real enclave)

## Security Considerations

### Certificate Validation
- Uses hardcoded AWS Nitro Root certificate as trust anchor
- Validates full certificate chain including intermediates
- Enforces certificate validity periods (typically ~3 hours)
- Verifies ECDSA P-384 signatures throughout chain

### COSE Signature Verification  
- Only accepts ES384 algorithm (ECDSA P-384 with SHA-384)
- Validates COSE headers and signature format
- Uses leaf certificate public key for verification

### Freshness Checks
- Enforces maximum document age (default 5 minutes)
- Validates timestamp against certificate validity
- Configurable time skew tolerance

### PCR Validation
The verifier extracts PCR (Platform Configuration Register) measurements but does not enforce specific values by default. For production use:

```python
# Example PCR validation
expected_pcrs = {
    0: bytes.fromhex("your-expected-pcr0-hash"),  # EIF hash
    1: bytes.fromhex("your-expected-pcr1-hash"),  # Kernel hash  
    2: bytes.fromhex("your-expected-pcr2-hash"),  # User app hash
}
```

## Troubleshooting

### Common Issues

**"NSM device not found"**
- Ensure running inside genuine Nitro Enclave
- Check `/dev/nsm` permissions (run as root if needed)
- Verify enclave has sufficient resources allocated

**"Certificate chain validation failed"**
- Check system clock synchronization
- Verify AWS Nitro Root certificate is current
- Ensure network connectivity for intermediate cert validation

**"COSE signature verification failed"**  
- Document may be corrupted or tampered
- Check base64 encoding/decoding
- Verify certificate matches document signing key

### Debug Mode

Add debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Avoid `--debug-mode` for production enclaves as PCR measurements will be all zeros.

## Integration

### Programmatic Usage

```python
from verifier import verify_attestation_document

try:
    result = verify_attestation_document(
        b64_doc=attestation_b64,
        expected_user_data=b"my-session-token",
        expected_nonce=b"challenge-123",
        max_age_seconds=300
    )
    
    # Extract public key for encryption
    enclave_pubkey = result.get("public_key")
    module_id = result.get("module_id")
    
    print(f"✅ Verified enclave {module_id}")
    
except AttestationError as e:
    print(f"❌ Verification failed: {e}")
```

### Vsock Communication (Optional)

For automated enclave-parent communication:

```python
# In enclave (vsock server)
import socket
sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
sock.bind((socket.VMADDR_CID_ANY, 9000))
# Send attestation document over vsock

# On parent (vsock client)  
import socket
sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
sock.connect((enclave_cid, 9000))
# Receive and verify attestation document
```

## References

- [AWS Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/)
- [NSM API Repository](https://github.com/aws/aws-nitro-enclaves-nsm-api)
- [aws-nsm-interface Python Library](https://github.com/donkersgoed/aws-nsm-interface)
- [Attestation Validation Blog](https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/)

## License

This project is provided as-is for educational and reference purposes.