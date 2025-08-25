#!/usr/bin/env python3
import os, socket, hashlib, secrets

# Generate a per-boot secret that never leaves the enclave
SECRET = secrets.token_bytes(32)
PORT = 5005

def sha256_hex(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(SECRET)
    h.update(data)
    return h.hexdigest()

def main():
    # AF_VSOCK works in standard Python on Linux (>=3.7)
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    # CID 3 is the enclave itself; it listens on its own CID
    s.bind( (socket.VMADDR_CID_ANY, PORT) )  # listen on all CIDs inside enclave
    s.listen(1)
    print(f"[enclave] listening on vsock:{PORT}", flush=True)

    while True:
        conn, addr = s.accept()
        try:
            data = b""
            # simple length-delimited: read until newline
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in chunk:
                    data = data.split(b"\n", 1)[0]
                    break
            digest = sha256_hex(data)
            conn.sendall((digest + "\n").encode())
        finally:
            conn.close()

if __name__ == "__main__":
    main()
