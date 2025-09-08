# Claude task: generate & verify an AWS Nitro Enclaves attestation document (Python)

**Goal**

* Write Python code to (1) run **inside** an AWS Nitro Enclave to request an **attestation document** from the Nitro Secure Module (NSM), and (2) run **outside** the enclave (the parent instance) to **verify** that attestation document.
* Provide runnable tests and a simple demo flow (enclave ↔ parent over vsock or stdio) to prove end‑to‑end.

---

## Repositories & docs to reference

* **NSM API repo (Rust/C, official):** [https://github.com/aws/aws-nitro-enclaves-nsm-api](https://github.com/aws/aws-nitro-enclaves-nsm-api)
* **Native Python NSM binding:** [https://github.com/donkersgoed/aws-nsm-interface](https://github.com/donkersgoed/aws-nsm-interface) (PyPI: `aws-nsm-interface`)
* **AWS docs: Cryptographic attestation:** [https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)
* **AWS docs: Verifying root of trust & doc structure:** [https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
* **Deep dive blog (doc anatomy & validation):** [https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/](https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/)

> Use **`aws-nsm-interface`** to talk to `/dev/nsm` in Python from inside the enclave. Use **`python-cose`**, **`cbor2`**, and **`cryptography`** for verification on the parent.

---

## Environment assumptions

* The enclave image (EIF) is built and launched via `nitro-cli`.
* The enclave app runs as root (or a user with access) so it can open `/dev/nsm`.
* For a quick demo, you can print the attestation doc bytes (base64) from the enclave and paste to the verifier, or write a simple vsock echo.

---

## Deliverables

1. **`enclave_app.py`** — requests an attestation doc using `aws_nsm_interface`.
2. **`verifier.py`** — verifies the attestation document on the parent.
3. **`test_attestation.py`** — pytest covering encode/decode & verification paths.
4. **`README.md`** — run instructions (nitro-cli build/run, pip installs, expected output).
5. (Optional) **vsock pair**: tiny server/client to move the COSE bytes automatically.

---

## Python dependencies

Inside enclave (build these into your image):

```bash
pip install aws-nsm-interface cbor2
```

On parent instance:

```bash
pip install python-cose==1.* cbor2 cryptography pytest
```

> Note: Attestation docs are **COSE\_Sign1** over a CBOR payload. AWS uses **ECDSA P‑384 with SHA‑384**; verify via COSE headers and the leaf certificate.

---

## 1) Enclave-side code (generate the doc)

Create `enclave_app.py` that:

* Optionally generates an **ephemeral keypair** inside the enclave (ECDH/ECDSA P‑384) and includes the **DER‑encoded public key** in the request.
* Optionally accepts a **nonce** and **user\_data**.
* Calls `aws_nsm_interface.get_attestation_doc(...)` and prints **base64** of the COSE bytes.

Skeleton:

```python
# enclave_app.py
import base64
from aws_nsm_interface.client import Nsm

# Optional: supply DER-encoded public key bytes if you generate one inside the enclave.
# For MVP, set to None and focus on doc creation.
PUBLIC_KEY_DER = None
USER_DATA = b"hello-from-enclave"
NONCE = None

if __name__ == "__main__":
    with Nsm() as nsm:
        doc = nsm.get_attestation_doc(
            user_data=USER_DATA,
            nonce=NONCE,
            public_key=PUBLIC_KEY_DER,
        )
        # doc is bytes containing a COSE_Sign1
        print(base64.b64encode(doc).decode())
```

Notes:

* If you do generate a key: use `cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(ec.SECP384R1())` and export **SubjectPublicKeyInfo DER** via `public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)`.
* For real provisioning, the verifier will encrypt to this public key.

---

## 2) Parent-side verification code

Create `verifier.py` that:

1. Accepts a base64 COSE doc, decodes to bytes.
2. Parses **COSE\_Sign1** (with `python-cose`).
3. Extracts the **CBOR payload** and decodes fields: `module_id`, `timestamp`, `pcrs`, `certificate` (leaf), `cabundle` (intermediates), and optional `public_key`, `user_data`, `nonce`.
4. Builds an **X.509 chain**: `leaf` → `intermediates...` → **AWS Nitro Root** (trust anchor). Either:

   * Use the **Nitro Root** published by AWS (hardcode the PEM in the verifier as a trust anchor), or
   * Pin to an allowlisted root thumbprint documented by AWS.
5. Performs checks:

   * **Chain validation** (signatures, validity window; certs are short‑lived \~3 hours).
   * **COSE signature verification** using the **leaf cert pubkey** and the COSE headers (alg should indicate ES384).
   * **Semantic checks**: timestamp freshness; expected PCR values / measurements (you can accept any for sample test, but leave hooks to pin them later); optional `nonce`/`user_data` matches expectations.

Skeleton (omitting full error handling for brevity):

```python
# verifier.py
import base64, datetime, sys
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.base import Certificate
from cose.messages import Sign1Message

# Paste AWS Nitro Root PEM here as TRUSTED_ROOT_PEM (string). Use AWS docs to keep it current.
TRUSTED_ROOT_PEM = """-----BEGIN CERTIFICATE-----\n...AWS Nitro Root...\n-----END CERTIFICATE-----\n"""

class AttestationError(Exception):
    pass

def load_chain(leaf_pem: bytes, bundle_pems: list[bytes]) -> tuple[Certificate, list[Certificate], Certificate]:
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    bundle = [x509.load_pem_x509_certificate(p) for p in bundle_pems]
    root = x509.load_pem_x509_certificate(TRUSTED_ROOT_PEM.encode())
    return leaf, bundle, root

# Minimal chain validation (you may use certvalidator lib for full PKI path build)

def verify_cose_with_leaf(cose_bytes: bytes, leaf_cert: Certificate):
    msg = Sign1Message.decode(cose_bytes)
    # COSE verification with leaf pubkey
    pub = leaf_cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise AttestationError("Unexpected public key type")
    # python-cose uses msg.verify_signature with a cose key object; use from_cryptography_key
    from cose.keys import CoseKey
    from cose.keys.cosekey import KpKty
    from cose.keys.keyparam import KpAlg
    from cose.algorithms import Es256, Es384

    ck = CoseKey.from_cryptography_key(pub)
    msg.key = ck
    if not msg.verify_signature():
        raise AttestationError("COSE signature invalid")
    return msg.payload

def parse_payload(payload_bytes: bytes) -> dict:
    return cbor2.loads(payload_bytes)

if __name__ == "__main__":
    b64 = sys.stdin.read().strip()
    cose_bytes = base64.b64decode(b64)

    # Extract and decode payload to fetch PEMs
    msg = Sign1Message.decode(cose_bytes)
    payload = cbor2.loads(msg.payload)

    # Expect DER-encoded certs inside payload; convert to PEM for cryptography
    leaf_der = payload.get(b"certificate")
    bundle_ders = payload.get(b"cabundle", [])

    if not leaf_der:
        raise AttestationError("Missing leaf certificate in attestation payload")

    leaf = x509.load_der_x509_certificate(leaf_der)
    bundle = [x509.load_der_x509_certificate(d) for d in bundle_ders]
    root = x509.load_pem_x509_certificate(TRUSTED_ROOT_PEM.encode())

    # Basic chain checks: leaf signed by bundle[0] or root, and bundle leads to root
    # (For production, use a proper path builder / AIA fetching as needed.)
    issuer = bundle[0] if bundle else root
    issuer_pub = issuer.public_key()
    issuer_pub.verify(leaf.signature, leaf.tbs_certificate_bytes, leaf.signature_hash_algorithm)
    # If bundle exists, verify each hop and finally that last bundle cert is issued by root.

    # Time checks (short-lived certs):
    now = datetime.datetime.utcnow()
    if not (leaf.not_valid_before <= now <= leaf.not_valid_after):
        raise AttestationError("Leaf certificate not currently valid")

    # Finally verify the COSE signature with the leaf public key
    from cose.keys import CoseKey
    ck = CoseKey.from_cryptography_key(leaf.public_key())
    msg.key = ck
    if not msg.verify_signature():
        raise AttestationError("COSE signature invalid")

    # Optional semantic checks
    # e.g., ensure expected module_id/pcrs/user_data
    module_id = payload.get(b"module_id")
    user_data = payload.get(b"user_data")
    print({"module_id": module_id, "user_data": user_data, "verified": True})
```

> **Production note:** swap the ad‑hoc chain checks for a robust path validation library (e.g., `certvalidator`) and enforce
> constraints (key usage, EKU if present), algorithm checks (`ES384`), cert policies, and a **freshness window** (e.g., timestamp within 5 minutes and cert TTL).

---

## 3) Tests (`test_attestation.py`)

Write tests that:

* Round‑trip CBOR payload encode/decode.
* Fail when COSE signature is altered.
* Fail when chain is broken (remove last bundle cert), or when time is outside validity.
* Pass for a recorded, known‑good attestation doc (store a small sample fixture from a real enclave run; redact sensitive fields if needed).

Example outline:

```python
# test_attestation.py
import base64, pytest
from verifier import AttestationError, verify_cose_with_leaf

@pytest.mark.parametrize("fixture_name", ["sample_good" ])
def test_good_doc(sample_good):
    # sample_good provides (cose_bytes, leaf_cert)
    payload = verify_cose_with_leaf(sample_good.cose, sample_good.leaf)
    assert payload

def test_signature_tamper(sample_good):
    tampered = bytearray(sample_good.cose)
    tampered[-1] ^= 0x01
    with pytest.raises(AttestationError):
        verify_cose_with_leaf(bytes(tampered), sample_good.leaf)
```

---

## 4) Minimal run instructions for README

1. **Build enclave image** that contains `enclave_app.py` and its deps:

   ```bash
   nitro-cli build-enclave --docker-uri <your-image> --output-file app.eif
   ```
2. **Run enclave**:

   ```bash
   nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path app.eif
   ```
3. **Inside enclave:**

   ```bash
   python enclave_app.py > /tmp/doc.b64
   ```
4. **On parent:**

   ```bash
   python verifier.py < /tmp/doc.b64
   ```

---

## 5) Implementation tips & pitfalls

* **Debug mode:** Avoid `--debug-mode` for real attestation; PCRs are all zeros and not trustworthy.
* **TRUSTED ROOT:** Keep the AWS Nitro Root cert up‑to‑date. Treat it as the sole trust anchor.
* **Algorithms:** Expect **ES384**; validate COSE `alg` header matches and reject anything else.
* **Freshness:** Certificates are short‑lived (\~hours). Enforce a skew window and check the payload `timestamp`.
* **Binding a key:** If you include `public_key` in the attestation request, verify that the same key is present in payload and then use it to encrypt secrets to the enclave.

---

## Stretch goals (nice‑to‑have)

* Implement a tiny **vsock** channel: parent requests nonce → enclave returns attestation + ephemeral pubkey → parent verifies and returns an encrypted secret.
* Add **PCR policy** checking (hash of EIF or file manifest) and a config file to pin expected measurements.
* CI job that runs the verifier tests with a stored fixture.

---

## Definition of done

* You can paste the base64 output from the enclave into `verifier.py` and get `{ verified: True }` with chain & COSE checks.
* `pytest` green on all tests, including tamper/broken‑chain cases.
* README explains how to reproduce on a fresh instance with Nitro Enclaves enabled.
