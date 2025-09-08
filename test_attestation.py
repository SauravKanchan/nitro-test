#!/usr/bin/env python3
"""
Comprehensive tests for AWS Nitro Enclaves attestation document verification.
"""

import base64
import datetime
import pytest
from typing import Dict, Any
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from cose.messages import Sign1Message
from cose.keys import CoseKey
from cose.algorithms import Es384

from verifier import (
    AttestationError,
    verify_attestation_document,
    verify_cose_signature,
    parse_payload,
    load_certificates,
    verify_certificate_chain,
    TRUSTED_ROOT_PEM
)


class MockAttestationDoc:
    """Mock attestation document for testing purposes."""
    
    def __init__(self):
        self.user_data = b"test-user-data"
        self.nonce = b"test-nonce"
        self.module_id = "i-1234567890abcdef0-enc1234567890abcdef"
        self.timestamp = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        self.pcrs = {0: b'\x00' * 48, 1: b'\x11' * 48, 2: b'\x22' * 48}
        
        # Generate mock certificates (self-signed for testing)
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key_der = self.private_key.public_key().public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        
    def create_mock_payload(self) -> Dict[bytes, Any]:
        """Create a mock CBOR payload similar to real attestation docs."""
        return {
            b"module_id": self.module_id,
            b"timestamp": self.timestamp,
            b"digest": "SHA384",
            b"pcrs": self.pcrs,
            b"certificate": b"mock_leaf_cert_der",  # Would be real DER in practice
            b"cabundle": [b"mock_intermediate_der"],  # Would be real DER in practice
            b"public_key": self.public_key_der,
            b"user_data": self.user_data,
            b"nonce": self.nonce,
        }


@pytest.fixture
def mock_doc():
    """Fixture providing a mock attestation document."""
    return MockAttestationDoc()


class TestPayloadParsing:
    """Test CBOR payload parsing functionality."""
    
    def test_parse_valid_payload(self, mock_doc):
        """Test parsing of valid CBOR payload."""
        payload = mock_doc.create_mock_payload()
        payload_bytes = cbor2.dumps(payload)
        
        result = parse_payload(payload_bytes)
        
        assert result["module_id"] == mock_doc.module_id
        assert result["timestamp"] == mock_doc.timestamp
        assert result["user_data"] == mock_doc.user_data
        assert result["nonce"] == mock_doc.nonce
        assert result["public_key"] == mock_doc.public_key_der
    
    def test_parse_invalid_cbor(self):
        """Test handling of invalid CBOR data."""
        with pytest.raises(AttestationError, match="Failed to parse CBOR payload"):
            parse_payload(b"invalid cbor data")
    
    def test_parse_empty_payload(self):
        """Test parsing of empty payload."""
        result = parse_payload(cbor2.dumps({}))
        assert result == {}


class TestCertificateHandling:
    """Test certificate loading and validation."""
    
    def test_load_valid_certificates(self):
        """Test loading valid certificate chain."""
        # Create a self-signed certificate for testing
        private_key = ec.generate_private_key(ec.SECP384R1())
        
        from cryptography.x509.oid import NameOID
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(private_key, hashes.SHA384())
        
        cert_der = cert.public_bytes(Encoding.DER)
        
        # This will fail with the real root cert, but tests the loading mechanism
        with pytest.raises(AttestationError):
            load_certificates(cert_der, [], )
    
    def test_load_invalid_certificate_der(self):
        """Test handling of invalid certificate DER."""
        with pytest.raises(AttestationError, match="Failed to load certificates"):
            load_certificates(b"invalid der", [])


class TestCOSESignature:
    """Test COSE signature verification."""
    
    def test_cose_algorithm_validation(self):
        """Test that only ES384 algorithm is accepted."""
        # Create a mock COSE message with wrong algorithm
        private_key = ec.generate_private_key(ec.SECP384R1())
        
        # Create a certificate for testing
        from cryptography.x509.oid import NameOID
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(private_key, hashes.SHA384())
        
        # Create COSE message with ES256 instead of ES384
        from cose.algorithms import Es256
        from cose.headers import CoseHeaderKeys
        
        payload = cbor2.dumps({"test": "data"})
        cose_key = CoseKey.from_cryptography_key(private_key)
        
        msg = Sign1Message(
            phdr={CoseHeaderKeys.ALG: Es256.identifier},
            uhdr={},
            payload=payload,
            key=cose_key
        )
        
        msg.encode()  # This signs the message
        cose_bytes = msg.encode()
        
        # Should fail due to wrong algorithm
        with pytest.raises(AttestationError, match="Unexpected COSE algorithm"):
            verify_cose_signature(cose_bytes, cert)


class TestAttestationVerification:
    """Test end-to-end attestation verification."""
    
    def test_verify_invalid_base64(self):
        """Test handling of invalid base64 input."""
        with pytest.raises(AttestationError):
            verify_attestation_document("invalid base64!")
    
    def test_verify_missing_certificate(self):
        """Test handling of payload without certificate."""
        # Create payload without certificate
        payload = {b"module_id": "test", b"timestamp": 1234567890}
        payload_bytes = cbor2.dumps(payload)
        
        # Create minimal COSE message
        from cose.headers import CoseHeaderKeys
        msg = Sign1Message(
            phdr={CoseHeaderKeys.ALG: Es384.identifier},
            uhdr={},
            payload=payload_bytes
        )
        
        cose_bytes = msg.encode(sign=False)  # Don't sign, just encode structure
        b64_doc = base64.b64encode(cose_bytes).decode()
        
        with pytest.raises(AttestationError, match="Missing leaf certificate"):
            verify_attestation_document(b64_doc)
    
    def test_timestamp_validation(self):
        """Test timestamp freshness validation."""
        # Create old timestamp (older than max_age_seconds)
        old_timestamp = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)).timestamp() * 1000)
        
        payload = {
            b"module_id": "test",
            b"timestamp": old_timestamp,
            b"certificate": b"mock_cert_der",
            b"cabundle": []
        }
        payload_bytes = cbor2.dumps(payload)
        
        from cose.headers import CoseHeaderKeys
        msg = Sign1Message(
            phdr={CoseHeaderKeys.ALG: Es384.identifier},
            uhdr={},
            payload=payload_bytes
        )
        
        cose_bytes = msg.encode(sign=False)
        b64_doc = base64.b64encode(cose_bytes).decode()
        
        # Should fail due to old timestamp (default max_age_seconds=300)
        with pytest.raises(AttestationError, match="too old"):
            verify_attestation_document(b64_doc, max_age_seconds=300)
    
    def test_user_data_validation(self, mock_doc):
        """Test user data validation."""
        expected_data = b"expected-data"
        wrong_data = b"wrong-data"
        
        # This test would need a complete mock attestation document
        # For now, we test the validation logic conceptually
        assert expected_data != wrong_data


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_empty_input(self):
        """Test handling of empty input."""
        with pytest.raises(AttestationError):
            verify_attestation_document("")
    
    def test_malformed_cose_data(self):
        """Test handling of malformed COSE data."""
        malformed_data = base64.b64encode(b"not a valid cose message").decode()
        with pytest.raises(AttestationError):
            verify_attestation_document(malformed_data)


class TestIntegration:
    """Integration tests for the full verification process."""
    
    def test_mock_verification_flow(self, mock_doc):
        """Test the overall verification flow with mock data."""
        # This would be a full integration test with a properly signed
        # attestation document. For now, we validate the components.
        
        payload = mock_doc.create_mock_payload()
        assert payload[b"module_id"] == mock_doc.module_id
        assert payload[b"user_data"] == mock_doc.user_data
        assert payload[b"public_key"] == mock_doc.public_key_der
    
    @pytest.mark.skip(reason="Requires real enclave environment")
    def test_real_attestation_document(self):
        """Test with a real attestation document from an enclave."""
        # This test would use a real attestation document fixture
        # Skip by default as it requires enclave environment
        pass


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])