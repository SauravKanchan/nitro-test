# Simple, tiny base
FROM public.ecr.aws/amazonlinux/amazonlinux:2023

# Install Python
RUN dnf install -y python3 && dnf clean all

# Copy server
WORKDIR /app
COPY enclave_server.py /app/enclave_server.py
RUN chmod +x /app/enclave_server.py

# No networking in the enclave; only vsock. Expose is irrelevant but kept for clarity.
EXPOSE 5005

# Run the server
ENTRYPOINT ["/usr/bin/python3", "/app/enclave_server.py"]
