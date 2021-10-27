import pure_chacha20


def test_chacha20():
    # Test this implementation against `pip install pycryptodome`.
    from Crypto.Cipher import ChaCha20 as PyCryptodomeChaCha20
    import secrets

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    length = 1000
    here = pure_chacha20.chacha20_stream(key, nonce, length)
    there = PyCryptodomeChaCha20.new(key=key, nonce=nonce).encrypt(b"\0" * length)
    assert here == there


def test_xchacha20():
    # Test this implementation against `pip install pycryptodome`.
    from Crypto.Cipher import ChaCha20 as PyCryptodomeChaCha20
    import secrets

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(24)
    length = 1000
    here = pure_chacha20.xchacha20_stream(key, nonce, length)
    # Using the 24-byte nonce here automatically involves XChaCha20 rather than ChaCha20.
    there = PyCryptodomeChaCha20.new(key=key, nonce=nonce).encrypt(b"\0" * length)
    assert here == there
