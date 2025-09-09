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

