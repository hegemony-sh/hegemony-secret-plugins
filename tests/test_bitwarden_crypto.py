# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the Bitwarden vault crypto: key derivation, EncStrings and RSA key unwrap.

Expected values are computed here from ``hashlib``/``hmac`` directly, independently of
the module under test. Interoperability with a real server is covered by
``scripts/live_check_vaultwarden.py``.
"""

import base64
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from hegemony_secret_bitwarden.crypto import (
    KDF_ARGON2ID,
    KDF_PBKDF2_SHA256,
    BitwardenCryptoError,
    SymmetricKey,
    UnsupportedEncryptionError,
    decrypt,
    decrypt_text,
    derive_master_key,
    encrypt,
    encrypt_text,
    load_private_key,
    rsa_decrypt,
    stretch_master_key,
)

KEY = SymmetricKey(enc=bytes(range(32)), mac=bytes(range(32, 64)))
OTHER_KEY = SymmetricKey(enc=bytes(32), mac=bytes(32))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _parts(enc_string: str) -> list[bytes]:
    return [base64.b64decode(part) for part in enc_string.split(".", 1)[1].split("|")]


def _join(enc_type: int, *parts: bytes) -> str:
    return f"{enc_type}." + "|".join(_b64(part) for part in parts)


# --- key derivation ---------------------------------------------------------------


def test_pbkdf2_master_key_matches_hashlib_and_normalizes_the_email():
    expected = hashlib.pbkdf2_hmac("sha256", b"hunter2", b"alice@example.com", 1000, 32)
    for salt in ("alice@example.com", "  Alice@Example.COM "):
        key = derive_master_key("hunter2", salt, kdf_type=KDF_PBKDF2_SHA256, iterations=1000)
        assert key == expected


def test_argon2id_master_key_is_deterministic_and_depends_on_every_input():
    def derive(password="hunter2", salt="alice@example.com", iterations=2, memory=8, lanes=1):
        return derive_master_key(
            password,
            salt,
            kdf_type=KDF_ARGON2ID,
            iterations=iterations,
            memory_mib=memory,
            parallelism=lanes,
        )

    base = derive()
    assert len(base) == 32
    assert derive() == base
    assert derive(salt="ALICE@example.com") == base
    assert derive(password="hunter3") != base
    assert derive(salt="bob@example.com") != base
    assert derive(iterations=3) != base
    assert derive(memory=16) != base
    assert derive(lanes=2) != base


@pytest.mark.parametrize(
    "kwargs",
    [
        {"kdf_type": KDF_PBKDF2_SHA256, "iterations": 0},
        {"kdf_type": KDF_PBKDF2_SHA256, "iterations": 10_000_001},
        {"kdf_type": KDF_PBKDF2_SHA256, "iterations": None},
        {"kdf_type": KDF_PBKDF2_SHA256, "iterations": "1000"},
        {"kdf_type": KDF_PBKDF2_SHA256, "iterations": True},
        {"kdf_type": KDF_ARGON2ID, "iterations": 3, "memory_mib": None, "parallelism": 4},
        {"kdf_type": KDF_ARGON2ID, "iterations": 3, "memory_mib": 64, "parallelism": None},
        {"kdf_type": KDF_ARGON2ID, "iterations": 3, "memory_mib": 4096, "parallelism": 4},
        {"kdf_type": KDF_ARGON2ID, "iterations": 1000, "memory_mib": 64, "parallelism": 4},
        {"kdf_type": KDF_ARGON2ID, "iterations": 3, "memory_mib": 64, "parallelism": 64},
    ],
)
def test_kdf_parameters_from_the_server_are_bounded(kwargs):
    with pytest.raises(BitwardenCryptoError, match="KDF parameter"):
        derive_master_key("hunter2", "alice@example.com", **kwargs)


@pytest.mark.parametrize("kdf_type", [2, -1, None, "0"])
def test_unknown_kdf_type_is_refused(kdf_type):
    with pytest.raises(UnsupportedEncryptionError, match="KDF type"):
        derive_master_key("hunter2", "alice@example.com", kdf_type=kdf_type, iterations=1000)


def test_stretch_master_key_is_hkdf_expand_with_enc_and_mac_labels():
    master_key = bytes(range(100, 132))
    stretched = stretch_master_key(master_key)
    # HKDF-Expand for one 32-byte block is HMAC(key, info || 0x01).
    assert stretched.enc == hmac.new(master_key, b"enc\x01", hashlib.sha256).digest()
    assert stretched.mac == hmac.new(master_key, b"mac\x01", hashlib.sha256).digest()
    with pytest.raises(BitwardenCryptoError):
        stretch_master_key(b"short")


# --- symmetric keys ---------------------------------------------------------------


def test_symmetric_key_splits_64_bytes_and_never_prints_itself():
    raw = bytes(range(64))
    key = SymmetricKey.from_bytes(raw)
    assert (key.enc, key.mac) == (raw[:32], raw[32:])
    assert key.to_bytes() == raw
    assert repr(key) == "SymmetricKey(<redacted>)"
    assert "SymmetricKey(<redacted>)" in f"{key}"
    assert SymmetricKey.generate() != SymmetricKey.generate()


@pytest.mark.parametrize("size", [0, 16, 32, 63, 65])
def test_symmetric_key_refuses_other_sizes(size):
    with pytest.raises(UnsupportedEncryptionError, match="64-byte key"):
        SymmetricKey.from_bytes(bytes(size))


# --- EncStrings -------------------------------------------------------------------


@pytest.mark.parametrize(
    "plaintext", [b"", b"a", b"x" * 15, b"x" * 16, b"x" * 17, bytes(range(256))]
)
def test_encrypt_round_trips_and_has_the_type_2_shape(plaintext):
    enc_string = encrypt(plaintext, KEY)
    assert enc_string.startswith("2.")
    iv, ciphertext, mac = _parts(enc_string)
    assert len(iv) == 16 and len(mac) == 32
    assert len(ciphertext) == (len(plaintext) // 16 + 1) * 16
    assert mac == hmac.new(KEY.mac, iv + ciphertext, hashlib.sha256).digest()
    assert decrypt(enc_string, KEY) == plaintext


def test_encrypt_uses_a_fresh_iv_every_time():
    assert encrypt(b"same", KEY) != encrypt(b"same", KEY)


def test_text_round_trip_is_utf8():
    assert decrypt_text(encrypt_text("žluťoučký kůň 🔑", KEY), KEY) == "žluťoučký kůň 🔑"
    with pytest.raises(BitwardenCryptoError, match="UTF-8"):
        decrypt_text(encrypt(b"\xff\xfe", KEY), KEY)


def test_wrong_key_fails_the_mac_check():
    with pytest.raises(BitwardenCryptoError, match="MAC check failed"):
        decrypt(encrypt(b"secret", KEY), OTHER_KEY)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_any_modified_part_fails_the_mac_check(index):
    parts = _parts(encrypt(b"secret value", KEY))
    parts[index] = bytes([parts[index][0] ^ 1]) + parts[index][1:]
    with pytest.raises(BitwardenCryptoError, match="MAC check failed"):
        decrypt(_join(2, *parts), KEY)


def test_mac_is_checked_before_padding_so_errors_are_not_a_padding_oracle():
    iv, ciphertext, _ = _parts(encrypt(b"secret", KEY))
    forged = _join(2, iv, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), bytes(32))
    with pytest.raises(BitwardenCryptoError, match="MAC check failed"):
        decrypt(forged, KEY)


def test_invalid_padding_under_a_valid_mac_is_reported():
    iv = bytes(16)
    # One block of zero bytes decrypts to something that is not valid PKCS#7 for this key.
    ciphertext = bytes(16)
    mac = hmac.new(KEY.mac, iv + ciphertext, hashlib.sha256).digest()
    with pytest.raises(BitwardenCryptoError, match="padding"):
        decrypt(_join(2, iv, ciphertext, mac), KEY)


@pytest.mark.parametrize("enc_type", [0, 1, 3, 4, 7, 99])
def test_other_symmetric_types_are_refused_not_guessed(enc_type):
    iv, ciphertext, mac = _parts(encrypt(b"secret", KEY))
    with pytest.raises(UnsupportedEncryptionError, match=f"type {enc_type}"):
        decrypt(_join(enc_type, iv, ciphertext, mac), KEY)


@pytest.mark.parametrize(
    "value",
    [
        None,
        42,
        b"2.AAAA",
        "",
        "2",
        "nodot",
        ".AAAA|AAAA|AAAA",
        "x.AAAA|AAAA|AAAA",
        "²." + _b64(bytes(16)),
        "2222." + _b64(bytes(16)),
        "2.not base64|AAAA|AAAA",
        "2." + _b64(bytes(16)),
        _join(2, bytes(16), bytes(16)),
        _join(2, bytes(16), bytes(16), bytes(32), bytes(1)),
        _join(2, bytes(15), bytes(16), bytes(32)),
        _join(2, bytes(16), bytes(15), bytes(32)),
        _join(2, bytes(16), b"", bytes(32)),
        _join(2, bytes(16), bytes(16), bytes(31)),
    ],
)
def test_malformed_values_raise_the_crypto_error(value):
    with pytest.raises(BitwardenCryptoError):
        decrypt(value, KEY)


def test_errors_never_contain_the_ciphertext():
    enc_string = encrypt(b"secret", KEY)
    with pytest.raises(BitwardenCryptoError) as excinfo:
        decrypt(enc_string, OTHER_KEY)
    for part in enc_string.split(".", 1)[1].split("|"):
        assert part not in str(excinfo.value)


# --- RSA --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _wrap(private_key: rsa.RSAPrivateKey, data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    oaep = padding.OAEP(mgf=padding.MGF1(algorithm), algorithm=algorithm, label=None)
    return private_key.public_key().encrypt(data, oaep)


@pytest.mark.parametrize(
    ("enc_type", "algorithm"),
    [(4, hashes.SHA1()), (6, hashes.SHA1()), (3, hashes.SHA256()), (5, hashes.SHA256())],
)
def test_rsa_decrypt_unwraps_an_organization_key(private_key, enc_type, algorithm):
    organization_key = bytes(range(64))
    wrapped = _wrap(private_key, organization_key, algorithm)
    parts = (wrapped, bytes(32)) if enc_type in (5, 6) else (wrapped,)
    assert rsa_decrypt(_join(enc_type, *parts), private_key) == organization_key


def test_rsa_decrypt_refuses_symmetric_and_unknown_types(private_key):
    wrapped = _wrap(private_key, bytes(64), hashes.SHA1())
    for enc_type in (0, 2, 7):
        with pytest.raises(UnsupportedEncryptionError, match="asymmetric"):
            rsa_decrypt(_join(enc_type, wrapped), private_key)


def test_rsa_decrypt_reports_a_key_meant_for_someone_else(private_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrapped = _wrap(other, bytes(64), hashes.SHA1())
    with pytest.raises(BitwardenCryptoError, match="organization key"):
        rsa_decrypt(_join(4, wrapped), private_key)
    with pytest.raises(BitwardenCryptoError, match="empty"):
        rsa_decrypt("4.", private_key)
    with pytest.raises(BitwardenCryptoError):
        rsa_decrypt(_join(4, b"too short"), private_key)


def test_load_private_key_accepts_pkcs8_rsa_only(private_key):
    der = private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    assert load_private_key(der).private_numbers() == private_key.private_numbers()
    with pytest.raises(BitwardenCryptoError, match="could not be parsed"):
        load_private_key(b"not a key")
    ec_der = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(UnsupportedEncryptionError, match="not an RSA key"):
        load_private_key(ec_der)
