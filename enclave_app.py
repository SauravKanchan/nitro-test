#!/usr/bin/env python3
"""
Enclave application for generating AWS Nitro Enclaves attestation documents.
This runs inside the enclave and uses the NSM (Nitro Secure Module) API.
"""

import base64
import sys
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import aws_nsm_interface


def generate_ephemeral_keypair() -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
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
    file_desc = None
    try:
        # Open NSM device
        file_desc = aws_nsm_interface.open_nsm_device()
        
        # Build parameter dict, excluding None values
        params = {}
        if user_data is not None:
            params['user_data'] = user_data
        if nonce is not None:
            params['nonce'] = nonce
        if public_key is not None:
            params['public_key'] = public_key
        
        # Get attestation document
        result = aws_nsm_interface.get_attestation_doc(file_desc, **params)
        
        # Extract document from result dict
        if isinstance(result, dict):
            if 'document' in result:
                doc = result['document']
            else:
                raise ValueError("No 'document' key in attestation result")
        else:
            doc = result  # Maybe it returns the document directly
        
        # Close NSM device
        aws_nsm_interface.close_nsm_device(file_desc)
        
        return doc
        
    except Exception as e:
        # Ensure we close file descriptor on error
        if file_desc is not None:
            try:
                aws_nsm_interface.close_nsm_device(file_desc)
            except:
                pass
        
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


def run_vsock_server(port=9000):
    """Run the vsock server mode."""
    print(f"🔥 Starting vsock server on port {port}...", file=sys.stderr)
    try:
        from vsock_server import VsockAttestationServer
        server = VsockAttestationServer(port)
        server.start()
    except ImportError:
        print("❌ vsock_server.py not found. Make sure it's in the same directory.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to start vsock server: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point for the enclave application."""
    # Parse command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        # Check for daemon mode
        if command == "--daemon":
            run_daemon_mode()
            return
            
        # Check for vsock server mode
        elif command == "--vsock" or command == "--vsock-server":
            port = 9000
            if len(sys.argv) > 2:
                try:
                    port = int(sys.argv[2])
                except ValueError:
                    print(f"Invalid port: {sys.argv[2]}", file=sys.stderr)
                    sys.exit(1)
            run_vsock_server(port)
            return
            
        # Check for help
        elif command in ["-h", "--help"]:
            print("AWS Nitro Enclave Attestation App", file=sys.stderr)
            print("", file=sys.stderr)
            print("Usage:", file=sys.stderr)
            print("  python3 enclave_app.py [options]", file=sys.stderr)
            print("", file=sys.stderr)
            print("Options:", file=sys.stderr)
            print("  --generate-key              Generate attestation with ephemeral key", file=sys.stderr)
            print("  --daemon                    Run in interactive daemon mode", file=sys.stderr)
            print("  --vsock [port]             Run vsock server (default port: 9000)", file=sys.stderr)
            print("  --vsock-server [port]      Same as --vsock", file=sys.stderr)
            print("  -h, --help                 Show this help message", file=sys.stderr)
            print("", file=sys.stderr)
            print("Examples:", file=sys.stderr)
            print("  python3 enclave_app.py --generate-key", file=sys.stderr)
            print("  python3 enclave_app.py --daemon", file=sys.stderr)
            print("  python3 enclave_app.py --vsock 9000", file=sys.stderr)
            print("  python3 enclave_app.py --generate-key \"my-data\" \"my-nonce\"", file=sys.stderr)
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