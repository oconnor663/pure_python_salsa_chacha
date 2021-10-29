# Pure Python Salsa and ChaCha [![Actions Status](https://github.com/oconnor663/pure_python_salsa_chacha/workflows/tests/badge.svg)](https://github.com/oconnor663/pure_python_salsa_chacha/actions)

This project contains pure Python implementations of the Salsa20, XSalsa20,
ChaCha20 (IETF), and XChaCha20 stream ciphers. These are intended for
educational and testing use only. These implementations are too slow for
production use, and they have not been audited.

Note that these are **unauthenticated** stream ciphers, which are low-level
cryptographic building blocks, not suitable for application code. If you need
to encrypt real data in an application, use an authenticated cipher like
[`SecretBox`](https://pynacl.readthedocs.io/en/latest/secret/). If some of
these terms are new to you, [Cryptographic Right
Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html)
is an excellent starting point.

## Installation

```
pip install pure_salsa20
pip install pure_chacha20
```

Note that some environments might refer to `pip` as `pip3`, and some
environments might need you to run those commands with `sudo`.

## Examples

### Salsa20

```python
import pure_salsa20
import secrets

key = secrets.token_bytes(32)
nonce = secrets.token_bytes(8)
plaintext = b"hello world"

# encryption
ciphertext = pure_salsa20.salsa20_xor(key, nonce, plaintext)

# decryption
assert plaintext == pure_salsa20.salsa20_xor(key, nonce, ciphertext)
```

### XSalsa20

```python
import pure_salsa20
import secrets

key = secrets.token_bytes(32)
nonce = secrets.token_bytes(24)
plaintext = b"hello world"

# encryption
ciphertext = pure_salsa20.xsalsa20_xor(key, nonce, plaintext)

# decryption
assert plaintext == pure_salsa20.xsalsa20_xor(key, nonce, ciphertext)
```

### ChaCha20 (IETF [RFC 7539](https://datatracker.ietf.org/doc/html/rfc7539))

```python
import pure_chacha20
import secrets

key = secrets.token_bytes(32)
nonce = secrets.token_bytes(12) # note the 12-byte/96-bit nonce from RFC 7539
plaintext = b"hello world"

# encryption
ciphertext = pure_chacha20.chacha20_xor(key, nonce, plaintext)

# decryption
assert plaintext == pure_chacha20.chacha20_xor(key, nonce, ciphertext)
```

### XChaCha20 ([draft RFC](https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-02))

```python
import pure_chacha20
import secrets

key = secrets.token_bytes(32)
nonce = secrets.token_bytes(24)
plaintext = b"hello world"

# encryption
ciphertext = pure_chacha20.xchacha20_xor(key, nonce, plaintext)

# decryption
assert plaintext == pure_chacha20.xchacha20_xor(key, nonce, ciphertext)
```
