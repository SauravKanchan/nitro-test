# Dockerfile for AWS Nitro Enclave Attestation Application
FROM amazonlinux:2

# Install system dependencies
RUN yum update -y && \
    yum install -y \
    python3 \
    python3-pip \
    python3-devel \
    gcc \
    openssl-devel \
    libffi-devel \
    && yum clean all \
    && rm -rf /var/cache/yum

# Upgrade pip and install Python dependencies
RUN python3 -m pip install --upgrade pip setuptools wheel

# Install Python packages required for enclave
RUN pip3 install --no-cache-dir \
    aws-nsm-interface>=0.1.0 \
    cryptography>=41.0.0 \
    cbor2>=5.4.0

# Create application directory
WORKDIR /app

# Copy the enclave application
COPY enclave_app.py /app/

# Make the script executable
RUN chmod +x /app/enclave_app.py

# Create a non-root user for security (optional, enclave may need root for /dev/nsm)
# RUN useradd -r -s /bin/false enclaveuser
# USER enclaveuser

# Keep container running - allows manual execution via nitro-cli console
CMD ["sh", "-c", "echo 'Enclave ready. Use: python3 /app/enclave_app.py [options]' && while true; do sleep 3600; done"]

# Health check (optional - verify Python and dependencies work)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import aws_nsm_interface, cryptography, cbor2; print('Dependencies OK')" || exit 1

# Labels for documentation
LABEL maintainer="AWS Nitro Enclaves Attestation"
LABEL description="Enclave application for generating attestation documents"
LABEL version="1.0"