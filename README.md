# SimpleCrypt

Simple file encryption. Created out of boredom during summer vacation in 1 day. Cross-platform.

## Encryption
For encryption, it uses AES-GCM 256. As a KDF - Argon2 ID.

Default KDF parameters -  19 MiB of memory, an iteration count of 2, and 1 degree of parallelism (as recommended by [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)).

## Installation

`git clone https://github.com/kolbanidze/simplecrypt`

`cd simplecrypt`

`pip install -r requirements.txt`

## Usage

Universal: `python3 encrypt.py` or `python3 decrypt.py`

It has *#!/usr/bin/python3*, so you can execute it on Linux with `./encrypt.py` or `./decrypt.py`

## Encrypted file format

```
| Order | Name        | Size                   |
|-------|-------------|------------------------|
| 1     | Time cost   | 4 bytes                |
| 2     | Memory cost | 4 bytes                |
| 3     | Parallelism | 4 bytes                |
| 4     | Salt size   | 4 bytes                |
| 5     | Key size    | 4 bytes                |
| 6     | Tag         | 16 bytes               |
| 7     | Nonce       | 16 bytes               |
| 8     | Salt        | defined in salt size   |
| 9     | Ciphertext  | to the end of the file |
```

By default, the encrypted file size will be 68 bytes larger than the unencrypted file size.
