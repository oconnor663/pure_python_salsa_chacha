import pure_salsa20


def test_salsa20():
    # Test this implementation against `pip install pycryptodome`.
    from Crypto.Cipher import Salsa20 as PyCryptodomeSalsa20
    import secrets

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(8)
    length = 1000
    here = pure_salsa20.salsa20_stream(key, nonce, length)
    there = PyCryptodomeSalsa20.new(key, nonce).encrypt(b"\0" * length)
    assert here == there


def test_xsalsa20():
    # Test this implementation against `pip install pynacl`.
    from nacl.secret import SecretBox
    import secrets

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(24)
    length = 1000
    # Account for the fact that secretbox uses the first 32 bytes of stream
    # output for the Poly1305 key.
    here = pure_salsa20.xsalsa20_stream(key, nonce, length + 32)
    there = SecretBox(key).encrypt(b"\0" * length, nonce).ciphertext
    assert len(there) == length + 16
    assert here[32:] == there[16:]
