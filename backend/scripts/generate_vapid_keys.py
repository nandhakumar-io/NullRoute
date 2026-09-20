#!/usr/bin/env python3
"""Generate a Web Push (VAPID) keypair.

  python scripts/generate_vapid_keys.py

Put the two printed lines in backend/.env. VAPID_PRIVATE_KEY is a raw
base64url value (NOT a file path) so it works unchanged inside Docker.
The public key is derived from the private key at runtime, so they cannot
drift apart. Changing the key invalidates existing browser subscriptions;
users simply click "Subscribe this browser" again.
"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


key = ec.generate_private_key(ec.SECP256R1())
priv = key.private_numbers().private_value.to_bytes(32, "big")
pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
print(f"VAPID_PRIVATE_KEY={b64u(priv)}")
print(f"VAPID_PUBLIC_KEY={b64u(pub)}")
