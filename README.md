# Encryptinator

Encryptinator is a command-line tool written in Go that can be used to encrypt and decrypt files and folders using AES-GCM encryption. It uses Argon2 key derivation function to derive a key from the password.

## Usage

```bash
encryptinator [(e)ncrypt|(d)ecrypt] <file|folder>
```

### Examples

Encrypt a file:

```bash
encryptinator encrypt secret.txt
```

Encrypt a folder:

```bash
encryptinator encrypt secret_folder
```

Decrypt a file:

```bash
encryptinator decrypt secret.txt
```

Decrypt a folder:

```bash
encryptinator decrypt secret_folder
```
