#!/usr/bin/env python3
"""
Enclave application for generating AWS Nitro Enclaves attestation documents.
This runs inside the enclave and uses the NSM (Nitro Secure Module) API.
"""

import base64
import sys
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from aws_nsm_interface.client import Nsm


def generate_ephemeral_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate an ephemeral ECDSA P-384 keypair inside the enclave."""
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key_der = private_key.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key_der


def get_attestation_document(
    user_data: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
    public_key: Optional[bytes] = None
) -> bytes:
    """Request an attestation document from the Nitro Secure Module."""
    try:
        with Nsm() as nsm:
            doc = nsm.get_attestation_doc(
                user_data=user_data,
                nonce=nonce,
                public_key=public_key,
            )
            return doc
    except Exception as e:
        print(f"Error getting attestation document: {e}", file=sys.stderr)
        raise


def main():
    """Main entry point for the enclave application."""
    # Default values
    USER_DATA = b"hello-from-enclave"
    NONCE = None
    
    # Option to generate ephemeral keypair
    generate_key = len(sys.argv) > 1 and sys.argv[1] == "--generate-key"
    
    public_key_der = None
    if generate_key:
        print("Generating ephemeral keypair inside enclave...", file=sys.stderr)
        private_key, public_key_der = generate_ephemeral_keypair()
        print(f"Public key generated ({len(public_key_der)} bytes DER)", file=sys.stderr)
    
    # Custom user data and nonce from environment or args
    if len(sys.argv) > 2:
        USER_DATA = sys.argv[2].encode('utf-8')
    if len(sys.argv) > 3:
        NONCE = sys.argv[3].encode('utf-8')
    
    print(f"Requesting attestation document with:", file=sys.stderr)
    print(f"  user_data: {USER_DATA}", file=sys.stderr)
    print(f"  nonce: {NONCE}", file=sys.stderr)
    print(f"  public_key: {'Yes' if public_key_der else 'None'}", file=sys.stderr)
    
    try:
        # Request attestation document
        doc = get_attestation_document(
            user_data=USER_DATA,
            nonce=NONCE,
            public_key=public_key_der
        )
        
        print(f"Attestation document generated ({len(doc)} bytes)", file=sys.stderr)
        
        # Output base64-encoded document to stdout
        b64_doc = base64.b64encode(doc).decode('ascii')
        print(b64_doc)
        
    except Exception as e:
        print(f"Failed to generate attestation document: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()