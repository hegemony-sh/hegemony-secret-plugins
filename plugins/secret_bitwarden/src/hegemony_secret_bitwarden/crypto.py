# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Client-side encryption for the Bitwarden vault protocol.

A Vaultwarden (or Bitwarden) server stores only ciphertext; the client derives the
keys and decrypts. The chain is:

1. master password + salt (the account email) --KDF--> 32-byte *master key*
2. master key --HKDF-Expand--> *stretched master key* (encryption half + MAC half)
3. stretched master key decrypts the account's *user key* (64 bytes)
4. the user key decrypts the account's RSA private key
5. the RSA private key decrypts each *organization key* (64 bytes)
6. an organization key decrypts that organization's collections and items; an item may
   carry its own *item key*, itself encrypted with the organization key

Every symmetric value is an "EncString" of type 2: AES-256-CBC with PKCS#7 padding,
authenticated by HMAC-SHA256 over ``iv || ciphertext`` (encrypt-then-MAC), written as
``2.<iv>|<ciphertext>|<mac>`` in base64. The MAC is checked, in constant time, before
anything is decrypted. Only standard primitives from ``cryptography`` are composed
here; nothing is implemented from scratch.

Other EncString types are refused with :class:`UnsupportedEncryptionError` rather than
guessed at: the unauthenticated AES types (0 and 1) of very old accounts, and newer
types this module does not know.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

KDF_PBKDF2_SHA256 = 0
KDF_ARGON2ID = 1

# The server names the KDF parameters, so a hostile or broken one could ask for a
# derivation that never finishes or exhausts memory. These bounds are far above what
# any client lets a user configure.
MAX_PBKDF2_ITERATIONS = 10_000_000
MAX_ARGON2_ITERATIONS = 100
MAX_ARGON2_MEMORY_MIB = 1024
MAX_ARGON2_PARALLELISM = 16

_ENC_AES_CBC256_HMAC_SHA256 = 2
_ENC_RSA_OAEP_SHA256 = 3
_ENC_RSA_OAEP_SHA1 = 4
# Types 5 and 6 are 3 and 4 with a trailing MAC part that clients never verified.
_ENC_RSA_OAEP_SHA256_HMAC = 5
_ENC_RSA_OAEP_SHA1_HMAC = 6

_AES_BLOCK_BYTES = 16
_KEY_HALF_BYTES = 32
_MAC_BYTES = 32


class BitwardenCryptoError(ValueError):
    """A value could not be decrypted: malformed, wrong key, or tampered with.

    Messages never contain key material, plaintext or ciphertext.
    """


class UnsupportedEncryptionError(BitwardenCryptoError):
    """The value uses an encryption type or KDF this plugin does not implement."""


@dataclass(frozen=True, repr=False)
class SymmetricKey:
    """A 64-byte Bitwarden key: an AES-256 key and an HMAC-SHA256 key."""

    enc: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if len(self.enc) != _KEY_HALF_BYTES or len(self.mac) != _KEY_HALF_BYTES:
            raise BitwardenCryptoError("a Bitwarden symmetric key must be 64 bytes")

    def __repr__(self) -> str:
        # Never let a key reach a log line or a traceback through repr().
        return "SymmetricKey(<redacted>)"

    @classmethod
    def from_bytes(cls, raw: bytes) -> SymmetricKey:
        if len(raw) != 2 * _KEY_HALF_BYTES:
            raise UnsupportedEncryptionError(
                f"expected a 64-byte key, got {len(raw)} bytes; keys without a MAC half "
                "(very old accounts) are not supported"
            )
        return cls(enc=raw[:_KEY_HALF_BYTES], mac=raw[_KEY_HALF_BYTES:])

    @classmethod
    def generate(cls) -> SymmetricKey:
        return cls.from_bytes(os.urandom(2 * _KEY_HALF_BYTES))

    def to_bytes(self) -> bytes:
        return self.enc + self.mac


def _in_range(name: str, value: object, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise BitwardenCryptoError(f"KDF parameter {name} is missing or out of range")
    return value


def derive_master_key(
    password: str,
    salt: str,
    *,
    kdf_type: int,
    iterations: int,
    memory_mib: int | None = None,
    parallelism: int | None = None,
) -> bytes:
    """Derive the 32-byte master key from the master password.

    Args:
        password: The account's master password.
        salt: The account email; it is trimmed and lower-cased as the clients do.
        kdf_type: ``0`` for PBKDF2-SHA256, ``1`` for Argon2id.
        iterations: PBKDF2 rounds, or Argon2id passes.
        memory_mib: Argon2id memory in MiB (Argon2id only).
        parallelism: Argon2id lanes (Argon2id only).
    """
    secret = password.encode("utf-8")
    normalized_salt = salt.strip().lower().encode("utf-8")
    if kdf_type == KDF_PBKDF2_SHA256:
        rounds = _in_range("iterations", iterations, MAX_PBKDF2_ITERATIONS)
        return hashlib.pbkdf2_hmac("sha256", secret, normalized_salt, rounds, _KEY_HALF_BYTES)
    if kdf_type == KDF_ARGON2ID:
        return Argon2id(
            # Argon2 needs a salt of at least 8 bytes, so the clients hash the email.
            salt=hashlib.sha256(normalized_salt).digest(),
            length=_KEY_HALF_BYTES,
            iterations=_in_range("iterations", iterations, MAX_ARGON2_ITERATIONS),
            lanes=_in_range("parallelism", parallelism, MAX_ARGON2_PARALLELISM),
            memory_cost=_in_range("memory", memory_mib, MAX_ARGON2_MEMORY_MIB) * 1024,
        ).derive(secret)
    raise UnsupportedEncryptionError(f"unsupported KDF type {kdf_type!r}")


def stretch_master_key(master_key: bytes) -> SymmetricKey:
    """Expand the 32-byte master key into the key that decrypts the user key."""
    if len(master_key) != _KEY_HALF_BYTES:
        raise BitwardenCryptoError("the master key must be 32 bytes")
    return SymmetricKey(
        enc=HKDFExpand(hashes.SHA256(), _KEY_HALF_BYTES, b"enc").derive(master_key),
        mac=HKDFExpand(hashes.SHA256(), _KEY_HALF_BYTES, b"mac").derive(master_key),
    )


def _split(enc_string: object) -> tuple[int, list[bytes]]:
    """Parse ``<type>.<part>|<part>...`` into the type and its base64-decoded parts."""
    if not isinstance(enc_string, str):
        raise BitwardenCryptoError("encrypted value is not a string")
    head, separator, body = enc_string.partition(".")
    # isascii() too: str.isdigit() accepts digits int() cannot parse (such as "²").
    if not separator or not head.isascii() or not head.isdigit() or len(head) > 3:
        raise BitwardenCryptoError("encrypted value has no encryption type prefix")
    try:
        parts = [base64.b64decode(part, validate=True) for part in body.split("|")]
    except (binascii.Error, ValueError):
        raise BitwardenCryptoError("encrypted value is not valid base64") from None
    return int(head), parts


def decrypt(enc_string: object, key: SymmetricKey) -> bytes:
    """Authenticate and decrypt a type 2 EncString; return the plaintext bytes."""
    enc_type, parts = _split(enc_string)
    if enc_type != _ENC_AES_CBC256_HMAC_SHA256:
        raise UnsupportedEncryptionError(f"unsupported symmetric encryption type {enc_type}")
    if len(parts) != 3:
        raise BitwardenCryptoError("encrypted value must have an IV, a ciphertext and a MAC")
    iv, ciphertext, mac = parts
    if (
        len(iv) != _AES_BLOCK_BYTES
        or len(mac) != _MAC_BYTES
        or not ciphertext
        or len(ciphertext) % _AES_BLOCK_BYTES
    ):
        raise BitwardenCryptoError("encrypted value has a malformed IV, ciphertext or MAC")
    expected = hmac.new(key.mac, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise BitwardenCryptoError(
            "MAC check failed: wrong key (for the user key, a wrong master password) "
            "or modified data"
        )
    decryptor = Cipher(algorithms.AES(key.enc), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise BitwardenCryptoError("decrypted value has invalid padding") from None


def decrypt_text(enc_string: object, key: SymmetricKey) -> str:
    """Decrypt a type 2 EncString holding UTF-8 text."""
    try:
        return decrypt(enc_string, key).decode("utf-8")
    except UnicodeDecodeError:
        raise BitwardenCryptoError("decrypted value is not valid UTF-8") from None


def encrypt(plaintext: bytes, key: SymmetricKey) -> str:
    """Encrypt ``plaintext`` as a type 2 EncString under a fresh random IV."""
    iv = os.urandom(_AES_BLOCK_BYTES)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key.enc), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(key.mac, iv + ciphertext, hashlib.sha256).digest()
    encoded = (base64.b64encode(part).decode("ascii") for part in (iv, ciphertext, mac))
    return f"{_ENC_AES_CBC256_HMAC_SHA256}." + "|".join(encoded)


def encrypt_text(plaintext: str, key: SymmetricKey) -> str:
    """Encrypt UTF-8 text as a type 2 EncString."""
    return encrypt(plaintext.encode("utf-8"), key)


def load_private_key(der: bytes) -> rsa.RSAPrivateKey:
    """Load the account's RSA private key (PKCS#8 DER, as decrypted with the user key)."""
    try:
        key = serialization.load_der_private_key(der, password=None)
    except (ValueError, TypeError):
        raise BitwardenCryptoError("the account's private key could not be parsed") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise UnsupportedEncryptionError("the account's private key is not an RSA key")
    return key


def rsa_decrypt(enc_string: object, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt an RSA-OAEP EncString (an organization key shared with the account)."""
    enc_type, parts = _split(enc_string)
    if enc_type in (_ENC_RSA_OAEP_SHA1, _ENC_RSA_OAEP_SHA1_HMAC):
        algorithm: hashes.HashAlgorithm = hashes.SHA1()
    elif enc_type in (_ENC_RSA_OAEP_SHA256, _ENC_RSA_OAEP_SHA256_HMAC):
        algorithm = hashes.SHA256()
    else:
        raise UnsupportedEncryptionError(f"unsupported asymmetric encryption type {enc_type}")
    if not parts or not parts[0]:
        raise BitwardenCryptoError("encrypted key is empty")
    oaep = rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=algorithm), algorithm=algorithm, label=None
    )
    try:
        return private_key.decrypt(parts[0], oaep)
    except ValueError:
        raise BitwardenCryptoError(
            "the organization key could not be decrypted with the account's private key"
        ) from None
