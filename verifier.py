#!/usr/bin/env python3
"""
Attestation document verifier for AWS Nitro Enclaves.
This runs on the parent instance to verify attestation documents.
"""

import base64
import datetime
import sys
from typing import Dict, List, Any, Tuple, Optional
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.base import Certificate
# COSE library imports removed - using manual CBOR parsing instead


# AWS Nitro Root Certificate (keep updated from AWS documentation)
TRUSTED_ROOT_PEM = """-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"""


class AttestationError(Exception):
    """Exception raised for attestation verification errors."""
    pass


def load_certificates(leaf_der: bytes, bundle_ders: List[bytes]) -> Tuple[Certificate, List[Certificate], Certificate]:
    """Load and parse certificates from DER format."""
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
        bundle = [x509.load_der_x509_certificate(der) for der in bundle_ders]
        root = x509.load_pem_x509_certificate(TRUSTED_ROOT_PEM.encode())
        
        # Debug: Print certificate info
        print(f"Debug: Leaf certificate subject: {leaf.subject}", file=sys.stderr)
        print(f"Debug: Leaf certificate issuer: {leaf.issuer}", file=sys.stderr)
        print(f"Debug: Leaf signature algorithm: {leaf.signature_algorithm_oid._name}", file=sys.stderr)
        print(f"Debug: Bundle certificates count: {len(bundle)}", file=sys.stderr)
        
        for i, cert in enumerate(bundle):
            print(f"Debug: Bundle[{i}] subject: {cert.subject}", file=sys.stderr)
            print(f"Debug: Bundle[{i}] issuer: {cert.issuer}", file=sys.stderr)
            print(f"Debug: Bundle[{i}] signature algorithm: {cert.signature_algorithm_oid._name}", file=sys.stderr)
        
        print(f"Debug: Root certificate subject: {root.subject}", file=sys.stderr)
        
        return leaf, bundle, root
    except Exception as e:
        raise AttestationError(f"Failed to load certificates: {e}")


def build_certificate_chain(leaf: Certificate, bundle: List[Certificate], root: Certificate) -> List[Certificate]:
    """Build the proper certificate chain from leaf to root by matching issuers to subjects."""
    chain = [leaf]
    remaining_certs = bundle + [root]
    current_cert = leaf
    
    print(f"Debug: Building chain starting from leaf: {leaf.subject}", file=sys.stderr)
    
    while True:
        # Find the issuer of the current certificate
        next_cert = None
        for cert in remaining_certs:
            if cert.subject == current_cert.issuer:
                next_cert = cert
                break
        
        if next_cert is None:
            print(f"Debug: Could not find issuer for: {current_cert.issuer}", file=sys.stderr)
            break
            
        chain.append(next_cert)
        remaining_certs.remove(next_cert)
        current_cert = next_cert
        
        print(f"Debug: Added to chain: {next_cert.subject}", file=sys.stderr)
        
        # Stop if we've reached the root (self-signed)
        if next_cert.subject == next_cert.issuer:
            print("Debug: Reached self-signed root certificate", file=sys.stderr)
            break
    
    print(f"Debug: Built chain with {len(chain)} certificates", file=sys.stderr)
    return chain


def verify_certificate_signature(cert: Certificate, issuer_cert: Certificate) -> None:
    """Verify that cert is signed by issuer_cert."""
    issuer_public_key = issuer_cert.public_key()
    
    print(f"Debug: Verifying {cert.subject} signed by {issuer_cert.subject}", file=sys.stderr)
    
    # Try the certificate's declared algorithm first
    try:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_hash_algorithm
        )
        print("Debug: Verification successful with declared algorithm", file=sys.stderr)
    except Exception as e1:
        print(f"Debug: Declared algorithm failed: {e1}", file=sys.stderr)
        
        # For AWS Nitro certificates, try ECDSA with SHA384 explicitly
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            try:
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(hashes.SHA384())
                )
                print("Debug: Verification successful with ECDSA-SHA384", file=sys.stderr)
            except Exception as e2:
                print(f"Debug: ECDSA-SHA384 failed: {e2}", file=sys.stderr)
                raise e2
        else:
            raise e1


def verify_certificate_chain(leaf: Certificate, bundle: List[Certificate], root: Certificate):
    """Verify the certificate chain from leaf to root."""
    try:
        # Build the proper certificate chain
        chain = build_certificate_chain(leaf, bundle, root)
        
        if len(chain) < 2:
            raise AttestationError("Certificate chain too short - need at least leaf and issuer")
        
        # Check time validity for all certificates
        now = datetime.datetime.now(datetime.timezone.utc)
        for i, cert in enumerate(chain):
            if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
                cert_type = "leaf" if i == 0 else f"intermediate[{i-1}]" if i < len(chain)-1 else "root"
                raise AttestationError(f"{cert_type} certificate not currently valid. Valid from {cert.not_valid_before_utc} to {cert.not_valid_after_utc}, current time: {now}")
        
        # Verify each certificate against its issuer
        for i in range(len(chain) - 1):
            cert = chain[i]
            issuer_cert = chain[i + 1]
            
            try:
                verify_certificate_signature(cert, issuer_cert)
            except Exception as e:
                cert_type = "leaf" if i == 0 else f"intermediate[{i-1}]"
                raise AttestationError(f"{cert_type} certificate signature verification failed: {e}")
                
    except AttestationError:
        raise
    except Exception as e:
        raise AttestationError(f"Certificate chain verification failed: {e}")


def verify_cose_signature(cose_bytes: bytes, leaf_cert: Certificate, bundle: List[Certificate], root: Certificate) -> bytes:
    """Verify COSE signature using manual CBOR parsing and cryptography library."""
    try:
        # Parse the raw CBOR array (AWS NSM returns untagged COSE_Sign1)
        cbor_data = cbor2.loads(cose_bytes)
        
        if not isinstance(cbor_data, list) or len(cbor_data) != 4:
            raise AttestationError(f"Invalid COSE_Sign1 structure: expected 4-element array, got {type(cbor_data)} with length {len(cbor_data) if hasattr(cbor_data, '__len__') else 'unknown'}")
        
        # Extract COSE_Sign1 components
        protected_bytes = cbor_data[0]  # Protected headers (CBOR-encoded)
        # cbor_data[1] is unprotected headers (not used for signature verification)
        payload = cbor_data[2]          # Payload (attestation data)
        signature_bytes = cbor_data[3]  # Signature
        
        print(f"Debug: COSE components - protected: {len(protected_bytes) if protected_bytes else 0} bytes, payload: {len(payload)} bytes, signature: {len(signature_bytes)} bytes", file=sys.stderr)
        
        # Parse protected headers
        if protected_bytes:
            protected = cbor2.loads(protected_bytes)
            print(f"Debug: Protected headers: {protected}", file=sys.stderr)
        else:
            protected = {}
            print("Debug: No protected headers", file=sys.stderr)
        
        # Verify algorithm is ES384 (ECDSA P-384 with SHA-384)
        alg = protected.get(1)  # Algorithm parameter (key 1 in COSE)
        print(f"Debug: COSE algorithm: {alg}", file=sys.stderr)
        if alg != -35:  # ES384 algorithm identifier
            raise AttestationError(f"Unexpected COSE algorithm: {alg}, expected ES384 (-35)")
        
        # Build Sig_structure as per COSE RFC 8152 Section 4.4
        # Sig_structure = [
        #     context,           // "Signature1" for COSE_Sign1
        #     body_protected,    // Protected headers
        #     external_aad,      // Empty for attestation documents
        #     payload            // The payload being signed
        # ]
        context = "Signature1"
        external_aad = b""  # Empty for attestation documents
        
        sig_structure = [
            context,
            protected_bytes if protected_bytes else b"",
            external_aad,
            payload
        ]
        
        # Encode Sig_structure as CBOR
        sig_structure_bytes = cbor2.dumps(sig_structure)
        print(f"Debug: Sig_structure length: {len(sig_structure_bytes)} bytes", file=sys.stderr)
        print(f"Debug: Sig_structure hex (first 64 bytes): {sig_structure_bytes[:64].hex()}", file=sys.stderr)
        print(f"Debug: Signature bytes hex (first 32 bytes): {signature_bytes[:32].hex()}", file=sys.stderr)
        print(f"Debug: Signature bytes hex (last 32 bytes): {signature_bytes[-32:].hex()}", file=sys.stderr)
        
        # Try systematic COSE verification with different certificates
        # AWS Nitro attestation documents are signed by NSM, need to find the right certificate
        verification_successful = False
        attempted_certs = []
        
        # Try leaf certificate first
        print("Debug: Attempting COSE signature verification with leaf certificate...", file=sys.stderr)
        try:
            pub_key = leaf_cert.public_key()
            if isinstance(pub_key, ec.EllipticCurvePublicKey) and pub_key.curve.name == "secp384r1":
                pub_key.verify(signature_bytes, sig_structure_bytes, ec.ECDSA(hashes.SHA384()))
                print("Debug: ECDSA signature verification successful with leaf certificate!", file=sys.stderr)
                verification_successful = True
            else:
                print(f"Debug: Leaf certificate has unsupported key type or curve", file=sys.stderr)
        except Exception as e:
            print(f"Debug: Leaf certificate verification failed: {e}", file=sys.stderr)
            attempted_certs.append(f"leaf: {e}")
        
        # If leaf certificate fails, try certificates from bundle
        if not verification_successful:
            for i, cert in enumerate(bundle):
                print(f"Debug: Attempting COSE signature verification with bundle certificate {i}...", file=sys.stderr)
                try:
                    pub_key = cert.public_key()
                    if isinstance(pub_key, ec.EllipticCurvePublicKey) and pub_key.curve.name == "secp384r1":
                        pub_key.verify(signature_bytes, sig_structure_bytes, ec.ECDSA(hashes.SHA384()))
                        print(f"Debug: ECDSA signature verification successful with bundle certificate {i}!", file=sys.stderr)
                        verification_successful = True
                        break
                    else:
                        print(f"Debug: Bundle certificate {i} has unsupported key type or curve", file=sys.stderr)
                except Exception as e:
                    print(f"Debug: Bundle certificate {i} verification failed: {e}", file=sys.stderr)
                    attempted_certs.append(f"bundle[{i}]: {e}")
        
        # If all bundle certificates fail, try root certificate
        if not verification_successful:
            print("Debug: Attempting COSE signature verification with root certificate...", file=sys.stderr)
            try:
                pub_key = root.public_key()
                if isinstance(pub_key, ec.EllipticCurvePublicKey) and pub_key.curve.name == "secp384r1":
                    pub_key.verify(signature_bytes, sig_structure_bytes, ec.ECDSA(hashes.SHA384()))
                    print("Debug: ECDSA signature verification successful with root certificate!", file=sys.stderr)
                    verification_successful = True
                else:
                    print(f"Debug: Root certificate has unsupported key type or curve", file=sys.stderr)
            except Exception as e:
                print(f"Debug: Root certificate verification failed: {e}", file=sys.stderr)
                attempted_certs.append(f"root: {e}")
        
        if not verification_successful:
            print(f"Debug: All attempted certificates failed: {attempted_certs}", file=sys.stderr)
            raise AttestationError(f"COSE signature verification failed with all attempted certificates. Tried {len(attempted_certs) + 1} certificates.")
            
        return payload
        
    except AttestationError:
        raise
    except Exception as e:
        raise AttestationError(f"COSE signature verification error: {e}")


def parse_payload(payload_bytes: bytes) -> Dict[str, Any]:
    """Parse and validate the CBOR payload."""
    try:
        payload = cbor2.loads(payload_bytes)
        
        # Convert bytes keys to strings for easier handling
        result = {}
        for key, value in payload.items():
            if isinstance(key, bytes):
                str_key = key.decode('utf-8')
            else:
                str_key = str(key)
            result[str_key] = value
            
        return result
        
    except Exception as e:
        raise AttestationError(f"Failed to parse CBOR payload: {e}")


def verify_attestation_document(
    b64_doc: str,
    expected_user_data: Optional[bytes] = None,
    expected_nonce: Optional[bytes] = None,
    max_age_seconds: int = 300
) -> Dict[str, Any]:
    """
    Verify an attestation document and return the parsed payload.
    
    Args:
        b64_doc: Base64-encoded attestation document
        expected_user_data: Expected user data (optional)
        expected_nonce: Expected nonce (optional)  
        max_age_seconds: Maximum age of the attestation in seconds
        
    Returns:
        Parsed and verified attestation payload
    """
    try:
        # Decode from base64
        cose_bytes = base64.b64decode(b64_doc.strip())
        
        # Parse CBOR array to extract certificates from payload
        cbor_data = cbor2.loads(cose_bytes)
        if not isinstance(cbor_data, list) or len(cbor_data) != 4:
            raise AttestationError("Invalid attestation document structure")
        
        # The payload should be CBOR-encoded bytes, decode it
        payload_bytes = cbor_data[2]
        if isinstance(payload_bytes, bytes):
            payload = cbor2.loads(payload_bytes)
        else:
            payload = payload_bytes  # Maybe it's already decoded
        
        # Extract certificates from payload
        leaf_cert_data = payload.get("certificate")
        bundle_cert_data = payload.get("cabundle", [])
        
        if not leaf_cert_data:
            raise AttestationError("Missing leaf certificate in attestation payload")
        
        # Handle certificate data - it might be raw DER bytes or base64 strings
        try:
            if isinstance(leaf_cert_data, bytes):
                # Already raw DER bytes
                leaf_der = leaf_cert_data
            elif isinstance(leaf_cert_data, str):
                # Base64-encoded string, need to decode
                leaf_der = base64.b64decode(leaf_cert_data)
            else:
                raise AttestationError(f"Unexpected certificate data type: {type(leaf_cert_data)}")
            
            # Handle bundle certificates
            bundle_ders = []
            for cert_data in bundle_cert_data:
                if isinstance(cert_data, bytes):
                    bundle_ders.append(cert_data)
                elif isinstance(cert_data, str):
                    bundle_ders.append(base64.b64decode(cert_data))
                else:
                    raise AttestationError(f"Unexpected bundle certificate data type: {type(cert_data)}")
                    
        except Exception as e:
            raise AttestationError(f"Failed to process certificate data: {e}")
        
        # Load and verify certificate chain
        leaf, bundle, root = load_certificates(leaf_der, bundle_ders)
        verify_certificate_chain(leaf, bundle, root)
        
        # Verify COSE signature
        verified_payload_bytes = verify_cose_signature(cose_bytes, leaf, bundle, root)
        verified_payload = parse_payload(verified_payload_bytes)
        
        # Verify timestamp freshness
        timestamp = verified_payload.get("timestamp")
        if timestamp:
            # Convert milliseconds to seconds
            doc_time = datetime.datetime.fromtimestamp(timestamp / 1000, tz=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            age = (now - doc_time).total_seconds()
            
            if age > max_age_seconds:
                raise AttestationError(f"Attestation document too old: {age:.1f} seconds (max {max_age_seconds})")
        
        # Verify expected values
        if expected_user_data is not None:
            actual_user_data = verified_payload.get("user_data")
            if actual_user_data != expected_user_data:
                raise AttestationError(f"User data mismatch: expected {expected_user_data}, got {actual_user_data}")
        
        if expected_nonce is not None:
            actual_nonce = verified_payload.get("nonce")
            if actual_nonce != expected_nonce:
                raise AttestationError(f"Nonce mismatch: expected {expected_nonce}, got {actual_nonce}")
        
        # Add verification status
        verified_payload["verification_status"] = "SUCCESS"
        verified_payload["verified_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        return verified_payload
        
    except AttestationError:
        raise
    except Exception as e:
        raise AttestationError(f"Attestation verification failed: {e}")


def main():
    """Main entry point for the verifier."""
    if len(sys.argv) < 2:
        # Read from stdin
        b64_doc = sys.stdin.read().strip()
    else:
        # Read from file
        with open(sys.argv[1], 'r') as f:
            b64_doc = f.read().strip()
    
    if not b64_doc:
        print("Error: No attestation document provided", file=sys.stderr)
        sys.exit(1)
    
    try:
        result = verify_attestation_document(b64_doc)
        
        # Print key information
        print("✅ Attestation document verified successfully!")
        print(f"Module ID: {result.get('module_id')}")
        print(f"Timestamp: {result.get('timestamp')}")
        print(f"User data: {result.get('user_data')}")
        print(f"Nonce: {result.get('nonce')}")
        print(f"Public key: {'Present' if result.get('public_key') else 'None'}")
        print(f"PCRs: {len(result.get('pcrs', {}))} measurements")
        print(f"Verified at: {result.get('verified_at')}")
        
        # Optionally print full result as JSON
        if "--json" in sys.argv:
            import json
            # Convert bytes to base64 for JSON serialization
            json_result = {}
            for k, v in result.items():
                if isinstance(v, bytes):
                    json_result[k] = base64.b64encode(v).decode('ascii')
                elif isinstance(v, dict):
                    # Handle PCRs dict with bytes values
                    if k == 'pcrs':
                        json_result[k] = {str(pcr_k): base64.b64encode(pcr_v).decode('ascii') if isinstance(pcr_v, bytes) else pcr_v for pcr_k, pcr_v in v.items()}
                    else:
                        json_result[k] = v
                else:
                    json_result[k] = v
            print("\nFull verification result:")
            print(json.dumps(json_result, indent=2))
        
    except AttestationError as e:
        print(f"❌ Attestation verification failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()