"""
Fast Pair Cryptography Module

Implements AES-128 encryption, ECDH key exchange, and key derivation
as specified in the Google Fast Pair protocol.

Reference: https://developers.google.com/nearby/fast-pair/specifications/appendix/testcases
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


ACCOUNT_KEY_SIZE = 16
AES_BLOCK_SIZE = 16


def aes_128_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-128 ECB encryption (single block)"""
    if len(key) != 16:
        raise ValueError("AES key must be 16 bytes")
    if len(plaintext) != 16:
        raise ValueError("Plaintext must be 16 bytes for single-block AES")

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_128_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-128 ECB decryption (single block)"""
    if len(key) != 16:
        raise ValueError("AES key must be 16 bytes")
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext must be 16 bytes for single-block AES")

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@dataclass
class ECDHKeyPair:
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey
    public_key_bytes: bytes


def generate_secp256r1_keypair() -> ECDHKeyPair:
    """Generate a new secp256r1 (P-256) key pair for ECDH"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    public_numbers = public_key.public_numbers()
    x_bytes = public_numbers.x.to_bytes(32, byteorder="big")
    y_bytes = public_numbers.y.to_bytes(32, byteorder="big")
    public_key_bytes = x_bytes + y_bytes

    return ECDHKeyPair(
        private_key=private_key,
        public_key=public_key,
        public_key_bytes=public_key_bytes,
    )


def derive_shared_secret_from_provider_public_key(
    seeker_private_key: ec.EllipticCurvePrivateKey,
    provider_public_key_bytes: bytes,
) -> bytes:
    """
    Derive shared secret using ECDH with Provider's public key.
    Provider public key is 64 bytes: X (32 bytes) || Y (32 bytes)
    
    Returns: First 16 bytes of SHA-256(shared_secret_point.x)
    """
    if len(provider_public_key_bytes) != 64:
        raise ValueError("Provider public key must be 64 bytes (X || Y)")

    x = int.from_bytes(provider_public_key_bytes[:32], byteorder="big")
    y = int.from_bytes(provider_public_key_bytes[32:], byteorder="big")

    provider_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        b"\x04" + provider_public_key_bytes,
    )

    shared_secret_point = seeker_private_key.exchange(ec.ECDH(), provider_public_key)

    shared_secret_hash = sha256(shared_secret_point)
    aes_key = shared_secret_hash[:16]

    return aes_key


def derive_aes_key_from_anti_spoofing_key(
    seeker_private_key: ec.EllipticCurvePrivateKey,
    provider_anti_spoofing_public_key: bytes,
) -> bytes:
    """
    Derive AES key for key-based pairing using the Anti-Spoofing public key.
    
    The Anti-Spoofing key is a per-model public key registered with Google.
    This key is used when the device is in "discoverable" mode.
    """
    return derive_shared_secret_from_provider_public_key(
        seeker_private_key, provider_anti_spoofing_public_key
    )


def derive_aes_key_from_account_key(account_key: bytes) -> bytes:
    """
    When device is not in discoverable mode, use existing Account Key as AES key.
    Account keys are 16 bytes and used directly as AES keys.
    """
    if len(account_key) != ACCOUNT_KEY_SIZE:
        raise ValueError(f"Account key must be {ACCOUNT_KEY_SIZE} bytes")
    return account_key


def generate_random_salt(length: int = 8) -> bytes:
    return os.urandom(length)


def generate_account_key() -> bytes:
    """Generate a new random 16-byte Account Key"""
    return os.urandom(ACCOUNT_KEY_SIZE)


def create_bloom_filter_for_account_key(
    account_key: bytes,
    salt: bytes,
    filter_size: int = 8,
) -> bytes:
    """
    Create a bloom filter entry for account key detection.
    
    Fast Pair uses bloom filters in advertisements to indicate
    which account keys a device has, without revealing them.
    
    Format: HMAC-SHA256(account_key, salt) -> bit positions in bloom filter
    """
    import hmac

    h = hmac.new(account_key, salt, hashlib.sha256).digest()

    bloom_filter = bytearray(filter_size)
    for i in range(0, 32, 4):
        position = struct.unpack(">I", h[i:i+4])[0] % (filter_size * 8)
        byte_index = position // 8
        bit_index = position % 8
        bloom_filter[byte_index] |= (1 << bit_index)

    return bytes(bloom_filter)


def encrypt_account_key_for_write(
    account_key: bytes,
    shared_secret: bytes,
) -> bytes:
    """
    Encrypt account key before writing to Account Key characteristic.
    Uses AES-128 ECB with the shared secret derived during pairing.
    """
    return aes_128_encrypt(shared_secret, account_key)


class FastPairCrypto:
    def __init__(self, anti_spoofing_public_key: bytes | None = None):
        self.seeker_keypair = generate_secp256r1_keypair()
        self.anti_spoofing_public_key = anti_spoofing_public_key
        self.shared_secret: bytes | None = None
        self.account_key: bytes | None = None

    @property
    def seeker_public_key(self) -> bytes:
        return self.seeker_keypair.public_key_bytes

    def derive_key_with_anti_spoofing(self) -> bytes:
        """Derive AES key using Anti-Spoofing public key (discoverable mode)"""
        if not self.anti_spoofing_public_key:
            raise ValueError("Anti-Spoofing public key not set")

        self.shared_secret = derive_aes_key_from_anti_spoofing_key(
            self.seeker_keypair.private_key,
            self.anti_spoofing_public_key,
        )
        return self.shared_secret

    def derive_key_with_account_key(self, account_key: bytes) -> bytes:
        """Use existing account key as AES key (non-discoverable mode)"""
        self.account_key = account_key
        self.shared_secret = derive_aes_key_from_account_key(account_key)
        return self.shared_secret

    def encrypt_request(self, plaintext: bytes) -> bytes:
        if not self.shared_secret:
            raise ValueError("Shared secret not derived. Call derive_key_* first.")
        return aes_128_encrypt(self.shared_secret, plaintext)

    def decrypt_response(self, ciphertext: bytes) -> bytes:
        if not self.shared_secret:
            raise ValueError("Shared secret not derived. Call derive_key_* first.")
        return aes_128_decrypt(self.shared_secret, ciphertext)

    def generate_new_account_key(self) -> bytes:
        self.account_key = generate_account_key()
        return self.account_key

    def encrypt_account_key(self) -> bytes:
        if not self.account_key:
            raise ValueError("Account key not set")
        if not self.shared_secret:
            raise ValueError("Shared secret not derived")
        return encrypt_account_key_for_write(self.account_key, self.shared_secret)
