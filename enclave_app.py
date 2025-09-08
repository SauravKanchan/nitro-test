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


def run_daemon_mode():
    """Run in daemon mode, waiting for commands on stdin."""
    print("🔥 Enclave daemon mode started. Send commands:", file=sys.stderr)
    print("  'attest' - Generate attestation document", file=sys.stderr)
    print("  'attest-key' - Generate attestation with ephemeral key", file=sys.stderr)
    print("  'attest-custom <user_data> <nonce>' - Custom attestation", file=sys.stderr)
    print("  'exit' - Exit daemon mode", file=sys.stderr)
    print("  'help' - Show this help", file=sys.stderr)
    print("Ready for commands...", file=sys.stderr)
    
    while True:
        try:
            line = input().strip()
            if not line:
                continue
                
            parts = line.split()
            command = parts[0].lower()
            
            if command == 'exit':
                print("Exiting daemon mode.", file=sys.stderr)
                break
            elif command == 'help':
                print("Available commands:", file=sys.stderr)
                print("  attest, attest-key, attest-custom <user_data> <nonce>, exit, help", file=sys.stderr)
            elif command == 'attest':
                generate_attestation(user_data=b"hello-from-enclave")
            elif command == 'attest-key':
                generate_attestation(user_data=b"hello-from-enclave", generate_key=True)
            elif command == 'attest-custom':
                user_data = parts[1].encode('utf-8') if len(parts) > 1 else b"custom-data"
                nonce = parts[2].encode('utf-8') if len(parts) > 2 else None
                generate_attestation(user_data=user_data, nonce=nonce, generate_key=True)
            else:
                print(f"Unknown command: {command}. Type 'help' for available commands.", file=sys.stderr)
                
        except EOFError:
            print("EOF received, exiting daemon mode.", file=sys.stderr)
            break
        except KeyboardInterrupt:
            print("Interrupt received, exiting daemon mode.", file=sys.stderr)
            break
        except Exception as e:
            print(f"Error in daemon mode: {e}", file=sys.stderr)


def generate_attestation(user_data=b"hello-from-enclave", nonce=None, generate_key=False):
    """Generate a single attestation document."""
    try:
        public_key_der = None
        if generate_key:
            print("Generating ephemeral keypair inside enclave...", file=sys.stderr)
            private_key, public_key_der = generate_ephemeral_keypair()
            print(f"Public key generated ({len(public_key_der)} bytes DER)", file=sys.stderr)
        
        print(f"Requesting attestation document with:", file=sys.stderr)
        print(f"  user_data: {user_data}", file=sys.stderr)
        print(f"  nonce: {nonce}", file=sys.stderr)
        print(f"  public_key: {'Yes' if public_key_der else 'None'}", file=sys.stderr)
        
        # Request attestation document
        doc = get_attestation_document(
            user_data=user_data,
            nonce=nonce,
            public_key=public_key_der
        )
        
        print(f"Attestation document generated ({len(doc)} bytes)", file=sys.stderr)
        
        # Output base64-encoded document to stdout
        b64_doc = base64.b64encode(doc).decode('ascii')
        print(b64_doc)
        
    except Exception as e:
        print(f"Failed to generate attestation document: {e}", file=sys.stderr)


def main():
    """Main entry point for the enclave application."""
    # Check for daemon mode
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        run_daemon_mode()
        return
    
    # Default values
    USER_DATA = b"hello-from-enclave"
    NONCE = None
    
    # Option to generate ephemeral keypair
    generate_key = len(sys.argv) > 1 and sys.argv[1] == "--generate-key"
    
    # Custom user data and nonce from environment or args
    if len(sys.argv) > 2:
        USER_DATA = sys.argv[2].encode('utf-8')
    if len(sys.argv) > 3:
        NONCE = sys.argv[3].encode('utf-8')
    
    # Generate single attestation document
    generate_attestation(user_data=USER_DATA, nonce=NONCE, generate_key=generate_key)


if __name__ == "__main__":
    main()