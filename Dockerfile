# Dockerfile for AWS Nitro Enclave Attestation Application
FROM amazonlinux:2

# Install system dependencies
RUN yum update -y && \
    yum install -y \
    python3 \
    python3-pip \
    python3-devel \
    gcc \
    git \
    openssl-devel \
    libffi-devel \
    && yum clean all \
    && rm -rf /var/cache/yum

# Upgrade pip and install Python dependencies
RUN python3 -m pip install --upgrade pip setuptools wheel

# Install Python packages required for enclave
RUN pip3 install --no-cache-dir \
    git+https://github.com/donkersgoed/aws-nsm-interface.git \
    cryptography>=41.0.0 \
    cbor2>=5.4.0

# Create application directory
WORKDIR /app

# Copy the enclave applications
COPY enclave_app.py /app/
COPY vsock_server.py /app/
COPY startup.sh /app/

# Make scripts executable
RUN chmod +x /app/enclave_app.py /app/startup.sh

# Create a non-root user for security (optional, enclave may need root for /dev/nsm)
# RUN useradd -r -s /bin/false enclaveuser
# USER enclaveuser

# Automatically start vsock server via startup script
CMD ["/app/startup.sh"]

# Labels for documentation
LABEL maintainer="AWS Nitro Enclaves Attestation"
LABEL description="Enclave application for generating attestation documents"
LABEL version="1.0"