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


def test_hchacha20():
    # This test vector comes from https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03.
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    input_bytes = bytes.fromhex("000000090000004a0000000031415927")
    expected = bytes.fromhex(
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    )
    found = pure_chacha20.hchacha20(key, input_bytes)
    assert expected == found
