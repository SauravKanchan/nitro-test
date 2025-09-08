#!/usr/bin/env python3
import sys, socket

# Usage: ./parent_client.py <ENCLAVE_CID> "your message"
# Get ENCLAVE_CID from `nitro-cli describe-enclaves` -> "EnclaveCID"

def main():
    if len(sys.argv) < 3:
        print("Usage: ./parent_client.py <ENCLAVE_CID> \"message\"")
        sys.exit(1)
    cid = int(sys.argv[1])
    msg = sys.argv[2].encode() + b"\n"
    port = 5005

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((cid, port))
    s.sendall(msg)

    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\n" in chunk:
            break
    print("Digest:", data.decode().strip())

if __name__ == "__main__":
    main()
