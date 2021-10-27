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


def test_hchacha20_vector():
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


def test_xchacha20_vector():
    # This test vector comes from https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03.
    plaintext = bytes.fromhex(
        "5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973"
        + "20616c736f206b6e6f776e2061732074686520417369617469632077696c6420"
        + "646f672c2072656420646f672c20616e642077686973746c696e6720646f672e"
        + "2049742069732061626f7574207468652073697a65206f662061204765726d61"
        + "6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061"
        + "206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c"
        + "757369766520616e6420736b696c6c6564206a756d70657220697320636c6173"
        + "736966696564207769746820776f6c7665732c20636f796f7465732c206a6163"
        + "6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963"
        + "2066616d696c792043616e696461652e"
    )
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555658")
    expected_stream = bytes.fromhex(
        "29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4"
        + "cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25"
        + "5e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe46221"
        + "5cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf60"
        + "7cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd"
        + "241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290f"
        + "a0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00"
        + "b3df507ca8c924f7017b7e712d15a2eb5c50484451e54e1b4b995bd8fdd94597"
        + "bb94d7af0b2c04df10ba0890899ed9293a0f55b8bafa999264035f1d4fbe7fe0"
        + "aafa109a62372027e50e10cdfecca127"
    )
    expected_xor = bytes.fromhex(
        "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87"
        + "ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05"
        + "3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f"
        + "7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201"
        + "12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc"
        + "047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63"
        + "d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73"
        + "c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4"
        + "d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683"
        + "8a9c71f70b5b5907a66f7ea49aadc409"
    )
    # This test vector assumes you start at block 1 (not 0). Skip 64 bytes to simulate this.
    my_stream = pure_chacha20.xchacha20_stream(key, nonce, len(expected_stream) + 64)
    my_stream = my_stream[64:]
    assert expected_stream == my_stream
    my_xor = pure_chacha20.xchacha20_xor(key, nonce, (64 * b"\0") + plaintext)
    my_xor = my_xor[64:]
    assert expected_xor == my_xor
