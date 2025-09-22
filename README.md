# SDEV245 Midterm Crypto App
### CIA + Randomness + Caesar + SHA-256 + AES-GCM + Ed25519

---

## === Features ===
- Input: either a message string or a file path
- Hash: SHA-256 (integrity)
- Encrypt/Decrypt: AES-256-GCM (confidentiality + integrity)
- Verify integrity after decrypt by comparing hashes
- Digital signatures: Ed25519 sign/verify the SHA-256 of plaintext
- Simple substitution cipher: Caesar shift demo (educational only)

## Usage examples:
<pre>```
  python crypto.py --message "hello world"
  python crypto.py --file ./example.txt
  python crypto.py --message "abc" --caesar-shift 3
```</pre>
## Requirements:
` pip install -r requirements.txt `
## === CIA TRIAD (How this demo upholds it) ===
- Confidentiality: AES-256-GCM encrypts the data so only key holders can read it.
- Integrity: SHA-256 hashes are compared; AES-GCM also authenticates data with its tag.
- Availability: Script is simple, dependency-light, and can run locally/offline.

## === RANDOMNESS / ENTROPY ===
- AES key and nonce come from os.urandom (CSPRNG).
- Strong, unpredictable keys/nonces prevent brute-force and replay/nonce-reuse attacks.
- Ed25519 keys are generated with a CSPRNG for unforgeable signatures.
