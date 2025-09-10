#!/usr/bin/env python3
"""
Vsock server for AWS Nitro Enclave - runs inside the enclave.
Listens for attestation requests and responds with attestation documents.
"""

import socket
import json
import base64
import sys
import threading
import time
from typing import Dict, Any, Optional

# Import the enclave functionality
from enclave_app import get_attestation_document, generate_ephemeral_keypair


class VsockAttestationServer:
    """Vsock server for handling attestation requests inside the enclave."""
    
    def __init__(self, port: int = 9000):
        self.port = port
        self.running = False
        self.sock = None
        
    def start(self):
        """Start the vsock server."""
        try:
            # Create vsock socket
            self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to any CID on the specified port
            # socket.VMADDR_CID_ANY allows connections from parent
            self.sock.bind((socket.VMADDR_CID_ANY, self.port))
            self.sock.listen(5)
            
            self.running = True
            print(f"🔥 Vsock attestation server started on port {self.port}", file=sys.stderr)
            print("Waiting for connections from parent instance...", file=sys.stderr)
            
            while self.running:
                try:
                    # Accept connection from parent
                    client_sock, addr = self.sock.accept()
                    print(f"📞 Connection from CID {addr[0]}", file=sys.stderr)
                    
                    # Handle client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_sock,),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"❌ Error accepting connection: {e}", file=sys.stderr)
                        time.sleep(1)
                        
        except Exception as e:
            print(f"❌ Failed to start vsock server: {e}", file=sys.stderr)
            raise
            
    def handle_client(self, client_sock: socket.socket):
        """Handle a client connection."""
        try:
            # Receive request data
            data = b""
            while True:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                # Simple protocol: end with newline
                if data.endswith(b'\n'):
                    break
                    
            if not data:
                print("📝 Empty request received", file=sys.stderr)
                return
                
            # Parse JSON request
            try:
                request = json.loads(data.decode('utf-8').strip())
                print(f"📝 Request: {request.get('command', 'unknown')}", file=sys.stderr)
            except json.JSONDecodeError as e:
                error_response = {
                    "success": False,
                    "error": f"Invalid JSON request: {e}"
                }
                self.send_response(client_sock, error_response)
                return
                
            # Process the request
            response = self.process_request(request)
            
            # Send response
            self.send_response(client_sock, response)
            
        except Exception as e:
            error_response = {
                "success": False,
                "error": f"Server error: {e}"
            }
            self.send_response(client_sock, error_response)
            print(f"❌ Error handling client: {e}", file=sys.stderr)
            
        finally:
            client_sock.close()
            
    def process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process an attestation request and return response."""
        try:
            command = request.get('command', '')
            
            if command == 'ping':
                return {"success": True, "message": "pong", "timestamp": int(time.time())}
                
            elif command == 'attest':
                # Extract request parameters
                user_data = request.get('user_data', 'hello-from-enclave')
                nonce = request.get('nonce', None)
                generate_key = request.get('generate_key', False)
                
                # Convert strings to bytes
                if isinstance(user_data, str):
                    user_data = user_data.encode('utf-8')
                if isinstance(nonce, str):
                    nonce = nonce.encode('utf-8')
                    
                # Generate ephemeral key if requested
                public_key_der = None
                if generate_key:
                    private_key, public_key_der = generate_ephemeral_keypair()
                
                # Get attestation document
                doc = get_attestation_document(
                    user_data=user_data,
                    nonce=nonce,
                    public_key=public_key_der
                )
                
                # Encode to base64
                b64_doc = base64.b64encode(doc).decode('ascii')
                
                response = {
                    "success": True,
                    "attestation_document": b64_doc,
                    "user_data": user_data.decode('utf-8') if user_data else None,
                    "nonce": nonce.decode('utf-8') if nonce else None,
                    "has_public_key": public_key_der is not None,
                    "document_size": len(doc),
                    "timestamp": int(time.time() * 1000)
                }
                
                return response
                
            elif command == 'status':
                return {
                    "success": True,
                    "status": "running",
                    "port": self.port,
                    "uptime": time.time()
                }
                
            else:
                return {
                    "success": False,
                    "error": f"Unknown command: {command}",
                    "available_commands": ["ping", "attest", "status"]
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to process request: {e}"
            }
            
    def send_response(self, client_sock: socket.socket, response: Dict[str, Any]):
        """Send JSON response to client."""
        try:
            response_json = json.dumps(response)
            response_data = response_json.encode('utf-8') + b'\n'
            client_sock.sendall(response_data)
        except Exception as e:
            print(f"❌ Error sending response: {e}", file=sys.stderr)
            
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.sock:
            self.sock.close()
            

def main():
    """Main entry point for the vsock server."""
    port = 9000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}", file=sys.stderr)
            sys.exit(1)
            
    server = VsockAttestationServer(port)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n🛑 Server shutdown requested", file=sys.stderr)
        server.stop()
    except Exception as e:
        print(f"❌ Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()