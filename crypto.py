#!/usr/bin/env python3
"""
Crypto Demo: CIA + Randomness + Caesar + SHA-256 + AES-GCM + Ed25519

Features
- Input: either a message string or a file path
- Hash: SHA-256 (integrity)
- Encrypt/Decrypt: AES-256-GCM (confidentiality + integrity)
- Verify integrity after decrypt by comparing hashes
- Digital signatures: Ed25519 sign/verify the SHA-256 of plaintext
- Simple substitution cipher: Caesar shift demo (educational only)

Usage examples:
  python crypto.py --message "hello world"
  python crypto.py --file ./example.txt
  python crypto.py --message "abc" --caesar-shift 3

Requirements:
  pip install cryptography
"""

import argparse
import base64
import hashlib
import os
from dataclasses import dataclass

# AES-GCM + Ed25519 from cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization


# ----------------------------
# 1) Simple Substitution (Caesar)
# ----------------------------
ALPHABET = "abcdefghijklmnopqrstuvwxyz"

def caesar_shift(text: str, shift: int) -> str:
    out = []
    s = shift % 26
    for ch in text:
        low = ch.lower()
        if low in ALPHABET:
            i = ALPHABET.index(low)
            new = ALPHABET[(i + s) % 26]
            out.append(new if ch.islower() else new.upper())
        else:
            out.append(ch)
    return "".join(out)


# ----------------------------
# 2) SHA-256 Hash (Integrity)
# ----------------------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----------------------------
# 3) AES-256-GCM (Symmetric)
# ----------------------------
@dataclass
class AESPackage:
    key_b64: str
    nonce_b64: str
    ciphertext_b64: str  # includes GCM tag at the end


def aes_gcm_encrypt(plaintext: bytes, aad: bytes | None = None) -> AESPackage:
    key = AESGCM.generate_key(bit_length=256)              # random 256-bit key
    aes = AESGCM(key)
    nonce = os.urandom(12)                                 # 96-bit nonce
    ct = aes.encrypt(nonce, plaintext, aad)               # returns ciphertext||tag
    return AESPackage(
        key_b64=base64.b64encode(key).decode(),
        nonce_b64=base64.b64encode(nonce).decode(),
        ciphertext_b64=base64.b64encode(ct).decode(),
    )


def aes_gcm_decrypt(pkg: AESPackage, aad: bytes | None = None) -> bytes:
    key = base64.b64decode(pkg.key_b64.encode())
    nonce = base64.b64decode(pkg.nonce_b64.encode())
    ct = base64.b64decode(pkg.ciphertext_b64.encode())
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, aad)


# ----------------------------
# 4) Digital Signatures (Ed25519)
# ----------------------------
@dataclass
class SigBundle:
    public_key_pem: str
    signature_b64: str

def sign_digest_ed25519(digest_hex: str) -> SigBundle:
    # Sign the SHA-256 digest bytes (32 bytes)
    digest = bytes.fromhex(digest_hex)
    prv = Ed25519PrivateKey.generate()
    pub = prv.public_key()
    sig = prv.sign(digest)

    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return SigBundle(
        public_key_pem=pub_pem,
        signature_b64=base64.b64encode(sig).decode(),
    )

def verify_digest_ed25519(digest_hex: str, public_key_pem: str, signature_b64: str) -> bool:
    digest = bytes.fromhex(digest_hex)
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        assert isinstance(pub, Ed25519PublicKey)
        pub.verify(base64.b64decode(signature_b64.encode()), digest)
        return True
    except Exception:
        return False


# ----------------------------
# I/O Helpers
# ----------------------------
def read_input_bytes(args: argparse.Namespace) -> bytes:
    if args.message is not None:
        return args.message.encode("utf-8")
    if args.file is not None:
        with open(args.file, "rb") as f:
            return f.read()
    raise ValueError("Provide --message or --file")


# ----------------------------
# Main
# ----------------------------
def main():
    p = argparse.ArgumentParser(description="Crypto Demo")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--message", type=str, help="Plaintext message input")
    src.add_argument("--file", type=str, help="Path to input file")
    p.add_argument("--caesar-shift", type=int, default=None, help="Optional Caesar shift demo")
    args = p.parse_args()

    # 0) Input
    original = read_input_bytes(args)
    print("=== INPUT ===")
    if args.message:
        print("Source: --message")
        print(f"Message: {args.message}")
    else:
        print(f"Source: --file  ({args.file})")
        print(f"Bytes: {len(original)}")

    # 1) Optional: Simple substitution (Caesar)
    if args.caesar_shift is not None:
        as_text = original.decode("utf-8", errors="ignore")
        enc = caesar_shift(as_text, args.caesar_shift)
        dec = caesar_shift(enc, -args.caesar_shift)
        print("\n=== SIMPLE SUBSTITUTION (Caesar) ===")
        print(f"Shift: {args.caesar_shift}")
        print(f"Encrypted: {enc}")
        print(f"Decrypted: {dec}")

    # 2) Hash (SHA-256)
    h_plain = sha256_bytes(original)
    print("\n=== SHA-256 (Integrity) ===")
    print(f"Plaintext SHA-256: {h_plain}")

    # 3) Encrypt (AES-256-GCM)
    pkg = aes_gcm_encrypt(original, aad=None)
    print("\n=== AES-256-GCM (Confidentiality + Integrity) ===")
    print(f"Key (base64):  {pkg.key_b64}")
    print(f"Nonce (base64): {pkg.nonce_b64}")
    print(f"Ciphertext+Tag (base64): {pkg.ciphertext_b64[:60]}...")

    # 4) Decrypt & Verify
    recovered = aes_gcm_decrypt(pkg, aad=None)
    h_recovered = sha256_bytes(recovered)
    print("\n=== DECRYPT & VERIFY ===")
    print(f"Recovered SHA-256: {h_recovered}")
    print("Integrity match:", "YES" if h_recovered == h_plain else "NO")

    # 5) Digital Signature (sign the SHA-256 digest of plaintext)
    sig = sign_digest_ed25519(h_plain)
    ok = verify_digest_ed25519(h_plain, sig.public_key_pem, sig.signature_b64)
    print("\n=== DIGITAL SIGNATURE (Ed25519) ===")
    print("Public Key (PEM):")
    print(sig.public_key_pem.strip())
    print(f"Signature (base64): {sig.signature_b64}")
    print("Signature verifies:", "YES" if ok else "NO")

    # 6) CIA quick mapping
    print("\n=== CIA TRIAD (How this demo upholds it) ===")
    print("- Confidentiality: AES-256-GCM encrypts the data so only key holders can read it.")
    print("- Integrity: SHA-256 hashes are compared; AES-GCM also authenticates data with its tag.")
    print("- Availability: Script is simple, dependency-light, and can run locally/offline.")

    # 7) Randomness & entropy
    print("\n=== RANDOMNESS / ENTROPY ===")
    print("- AES key and nonce come from os.urandom (CSPRNG).")
    print("- Strong, unpredictable keys/nonces prevent brute-force and replay/nonce-reuse attacks.")
    print("- Ed25519 keys are generated with a CSPRNG for unforgeable signatures.")


if __name__ == "__main__":
    main()

