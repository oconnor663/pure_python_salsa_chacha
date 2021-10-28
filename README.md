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
