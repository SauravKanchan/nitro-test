#!/usr/bin/env python3
"""
Vsock client for AWS Nitro Enclave - runs on parent instance.
Connects to enclave to request attestation documents.
"""

import socket
import json
import argparse
import sys
import time
from typing import Dict, Any, Optional

# Import verifier for automatic validation
try:
    from verifier import verify_attestation_document, AttestationError
    HAS_VERIFIER = True
except ImportError:
    HAS_VERIFIER = False
    print("Warning: verifier.py not available, auto-verification disabled", file=sys.stderr)


class VsockAttestationClient:
    """Vsock client for requesting attestations from enclave."""
    
    def __init__(self, enclave_cid: int, port: int = 9000, timeout: int = 30):
        self.enclave_cid = enclave_cid
        self.port = port
        self.timeout = timeout
        
    def send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send a request to the enclave and return the response."""
        try:
            # Create vsock socket
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect to enclave
            print(f"🔗 Connecting to enclave CID {self.enclave_cid} on port {self.port}...", file=sys.stderr)
            sock.connect((self.enclave_cid, self.port))
            print("✅ Connected to enclave", file=sys.stderr)
            
            # Send request
            request_json = json.dumps(request)
            request_data = request_json.encode('utf-8') + b'\n'
            sock.sendall(request_data)
            
            # Receive response
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if response_data.endswith(b'\n'):
                    break
                    
            if not response_data:
                raise Exception("Empty response from enclave")
                
            # Parse JSON response
            response = json.loads(response_data.decode('utf-8').strip())
            
            sock.close()
            return response
            
        except socket.timeout:
            raise Exception(f"Timeout connecting to enclave (waited {self.timeout}s)")
        except socket.error as e:
            raise Exception(f"Socket error: {e}")
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON response: {e}")
        except Exception as e:
            raise Exception(f"Request failed: {e}")
            
    def ping(self) -> bool:
        """Test connection to enclave."""
        try:
            response = self.send_request({"command": "ping"})
            return response.get("success", False)
        except Exception as e:
            print(f"❌ Ping failed: {e}", file=sys.stderr)
            return False
            
    def get_status(self) -> Dict[str, Any]:
        """Get enclave status."""
        return self.send_request({"command": "status"})
        
    def request_attestation(
        self,
        user_data: str = "hello-from-enclave",
        nonce: Optional[str] = None,
        generate_key: bool = False
    ) -> Dict[str, Any]:
        """Request an attestation document from the enclave."""
        request = {
            "command": "attest",
            "user_data": user_data,
            "nonce": nonce,
            "generate_key": generate_key
        }
        
        print(f"📋 Requesting attestation with:", file=sys.stderr)
        print(f"  user_data: {user_data}", file=sys.stderr)
        print(f"  nonce: {nonce}", file=sys.stderr)
        print(f"  generate_key: {generate_key}", file=sys.stderr)
        
        response = self.send_request(request)
        
        if not response.get("success", False):
            raise Exception(f"Attestation request failed: {response.get('error', 'Unknown error')}")
            
        return response
        
    def request_and_verify(
        self,
        user_data: str = "hello-from-enclave",
        nonce: Optional[str] = None,
        generate_key: bool = False,
        save_to_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """Request attestation and automatically verify it."""
        # Request attestation
        response = self.request_attestation(user_data, nonce, generate_key)
        
        attestation_b64 = response.get("attestation_document")
        if not attestation_b64:
            raise Exception("No attestation document in response")
            
        print(f"✅ Received attestation document ({response.get('document_size', 0)} bytes)", file=sys.stderr)
        
        # Save to file if requested
        if save_to_file:
            with open(save_to_file, 'w') as f:
                f.write(attestation_b64)
            print(f"💾 Saved attestation document to {save_to_file}", file=sys.stderr)
            
        # Verify if verifier is available
        if HAS_VERIFIER:
            try:
                print("🔍 Verifying attestation document...", file=sys.stderr)
                
                # Prepare expected values for verification
                expected_user_data = user_data.encode('utf-8') if user_data else None
                expected_nonce = nonce.encode('utf-8') if nonce else None
                
                verification_result = verify_attestation_document(
                    b64_doc=attestation_b64,
                    expected_user_data=expected_user_data,
                    expected_nonce=expected_nonce,
                    max_age_seconds=300
                )
                
                print("✅ Attestation document verified successfully!", file=sys.stderr)
                print(f"  Module ID: {verification_result.get('module_id')}", file=sys.stderr)
                print(f"  Timestamp: {verification_result.get('timestamp')}", file=sys.stderr)
                print(f"  PCRs: {len(verification_result.get('pcrs', {}))} measurements", file=sys.stderr)
                
                # Combine response with verification result
                response["verification"] = verification_result
                response["verified"] = True
                
            except AttestationError as e:
                print(f"❌ Attestation verification failed: {e}", file=sys.stderr)
                response["verification_error"] = str(e)
                response["verified"] = False
        else:
            print("ℹ️  Auto-verification skipped (verifier not available)", file=sys.stderr)
            response["verified"] = None
            
        return response


def get_enclave_cid() -> int:
    """Get the CID of the running enclave."""
    try:
        import subprocess
        import json as json_module
        
        # Run nitro-cli describe-enclaves
        result = subprocess.run(
            ["sudo", "nitro-cli", "describe-enclaves"],
            capture_output=True,
            text=True,
            check=True
        )
        
        enclaves = json_module.loads(result.stdout)
        if not enclaves:
            raise Exception("No running enclaves found")
            
        # Return CID of first enclave
        cid = enclaves[0]["EnclaveCID"]
        print(f"📍 Found enclave with CID: {cid}", file=sys.stderr)
        return cid
        
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to get enclave info: {e}")
    except (json_module.JSONDecodeError, KeyError, IndexError) as e:
        raise Exception(f"Failed to parse enclave info: {e}")
    except FileNotFoundError:
        raise Exception("nitro-cli command not found")


def main():
    """Main entry point for the vsock client."""
    parser = argparse.ArgumentParser(description="Vsock client for Nitro Enclave attestation")
    
    parser.add_argument("--cid", type=int, help="Enclave CID (auto-detected if not specified)")
    parser.add_argument("--port", type=int, default=9000, help="Vsock port (default: 9000)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    
    # Commands
    parser.add_argument("--ping", action="store_true", help="Test connection to enclave")
    parser.add_argument("--status", action="store_true", help="Get enclave status")
    parser.add_argument("--attest", action="store_true", help="Request attestation document")
    
    # Attestation options
    parser.add_argument("--user-data", default="hello-from-enclave", help="User data for attestation")
    parser.add_argument("--nonce", help="Nonce for attestation")
    parser.add_argument("--generate-key", action="store_true", help="Generate ephemeral key")
    parser.add_argument("--save", help="Save attestation document to file")
    parser.add_argument("--verify", action="store_true", help="Automatically verify attestation")
    
    # Output format
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    args = parser.parse_args()
    
    # Auto-detect CID if not provided
    if args.cid is None:
        try:
            args.cid = get_enclave_cid()
        except Exception as e:
            print(f"❌ Failed to auto-detect enclave CID: {e}", file=sys.stderr)
            print("Please specify --cid manually", file=sys.stderr)
            sys.exit(1)
    
    # Create client
    client = VsockAttestationClient(args.cid, args.port, args.timeout)
    
    try:
        # Execute commands
        if args.ping:
            success = client.ping()
            if success:
                print("🏓 Pong! Connection successful")
            else:
                print("❌ Ping failed")
                sys.exit(1)
                
        elif args.status:
            status = client.get_status()
            if args.json:
                print(json.dumps(status, indent=2))
            else:
                if status.get("success"):
                    print(f"📊 Enclave Status: {status.get('status')}")
                    print(f"   Port: {status.get('port')}")
                    print(f"   Uptime: {status.get('uptime')}")
                else:
                    print(f"❌ Status request failed: {status.get('error')}")
                    
        elif args.attest or args.verify:
            if args.verify:
                response = client.request_and_verify(
                    user_data=args.user_data,
                    nonce=args.nonce,
                    generate_key=args.generate_key,
                    save_to_file=args.save
                )
            else:
                response = client.request_attestation(
                    user_data=args.user_data,
                    nonce=args.nonce,
                    generate_key=args.generate_key
                )
                
                if args.save:
                    with open(args.save, 'w') as f:
                        f.write(response.get("attestation_document", ""))
                    print(f"💾 Saved to {args.save}")
                    
            if args.json:
                print(json.dumps(response, indent=2))
            else:
                if response.get("success"):
                    print("✅ Attestation successful!")
                    print(f"   Document size: {response.get('document_size')} bytes")
                    print(f"   Has public key: {response.get('has_public_key')}")
                    print(f"   Verified: {response.get('verified', 'N/A')}")
                    
                    if not args.json and not args.save:
                        # Print the attestation document
                        print("\n📄 Attestation Document (base64):")
                        print(response.get("attestation_document", ""))
                else:
                    print(f"❌ Attestation failed: {response.get('error')}")
                    sys.exit(1)
        else:
            print("No command specified. Use --ping, --status, --attest, or --verify")
            print("Use --help for full usage information")
            
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()