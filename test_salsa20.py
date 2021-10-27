import pure_salsa20


def test_salsa20():
    # Test this implementation against `pip install pycryptodome`.
    from Crypto.Cipher import Salsa20 as PyCryptodomeSalsa20
    import secrets

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(8)
    length = 1000
    plaintext = secrets.token_bytes(length)
    here = pure_salsa20.salsa20_xor(key, nonce, plaintext)
    there = PyCryptodomeSalsa20.new(key=key, nonce=nonce).encrypt(plaintext)
    assert here == there


def test_xsalsa20():
    # Test this implementation against `pip install pynacl`.
    from nacl.secret import SecretBox
    import secrets

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(24)
    length = 1000
    plaintext = secrets.token_bytes(length)
    # Account for the fact that secretbox uses the first 32 bytes of stream
    # output for the Poly1305 key.
    here = pure_salsa20.xsalsa20_xor(key, nonce, b"\0" * 32 + plaintext)
    there = SecretBox(key).encrypt(plaintext, nonce).ciphertext
    assert len(there) == length + 16
    assert here[32:] == there[16:]


def test_xsalsa20_vector():
    # This test vector comes from https://go.googlesource.com/crypto/+/master/salsa20/salsa20_test.go.
    key = b"this is 32-byte key for xsalsa20"
    nonce = b"24-byte nonce for xsalsa"
    plaintext = b"\0" * 64
    # fmt: off
    expected_xor = bytes([
        0x48, 0x48, 0x29, 0x7f, 0xeb, 0x1f, 0xb5, 0x2f,
        0xb6, 0x6d, 0x81, 0x60, 0x9b, 0xd5, 0x47, 0xfa,
        0xbc, 0xbe, 0x70, 0x26, 0xed, 0xc8, 0xb5, 0xe5,
        0xe4, 0x49, 0xd0, 0x88, 0xbf, 0xa6, 0x9c, 0x08,
        0x8f, 0x5d, 0x8d, 0xa1, 0xd7, 0x91, 0x26, 0x7c,
        0x2c, 0x19, 0x5a, 0x7f, 0x8c, 0xae, 0x9c, 0x4b,
        0x40, 0x50, 0xd0, 0x8c, 0xe6, 0xd3, 0xa1, 0x51,
        0xec, 0x26, 0x5f, 0x3a, 0x58, 0xe4, 0x76, 0x48,
    ])
    # fmt: on
    my_xor = pure_salsa20.xsalsa20_xor(key, nonce, plaintext)
    assert expected_xor == my_xor
