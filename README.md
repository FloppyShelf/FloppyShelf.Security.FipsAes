# FloppyShelf.Security.FipsAes

A FIPS-compliant AES encryption library for .NET providing secure, authenticated encryption with streaming support and robust security features.

## Overview

This library implements a secure encryption system using AES-256-CBC with HMAC-SHA256 authentication, following FIPS compliance requirements. It supports both streaming operations and direct string encryption/decryption, with built-in protection against timing attacks and secure key management.

## Features

* FIPS-compliant AES-256 encryption
* Authenticated encryption with HMAC-SHA256
* Streaming support for large files
* Secure key derivation using PBKDF2
* Protection against timing attacks
* Memory-safe operations
* Asynchronous API support
* Built-in error handling

## Installation

Add the NuGet package to your project:

```bash
Install-Package FloppyShelf.Security.FipsAes
```

Or using .NET CLI:

```bash
dotnet add package FloppyShelf.Security.FipsAes
```

## Usage Examples

### Basic String Encryption

```csharp
var encryptor = new FipsAesStreamEncryptor();

// Encrypt a string
string encrypted = await encryptor.EncryptAsync("Sensitive Data", "your_password_here");

// Decrypt the result
string decrypted = await encryptor.DecryptAsync(encrypted, "your_password_here");
```

### Stream Encryption

```csharp
var encryptor = new FipsAesStreamEncryptor();

// Encrypt a file stream
await encryptor.EncryptStreamAsync(
    inputStream: inputFileStream,
    outputStream: outputFileStream,
    password: "your_password_here"
);

// Decrypt a file stream
await encryptor.DecryptStreamAsync(
    inputStream: encryptedFileStream,
    outputStream: decryptedFileStream,
    password: "your_password_here"
);
```

## Security Features

* **Key Derivation**: Uses PBKDF2 with SHA256 and 100,000 iterations
* **AES Configuration**: AES-256-CBC with PKCS7 padding
* **Authentication**: HMAC-SHA256 for data integrity verification
* **Secure Memory Handling**: Explicit clearing of sensitive data
* **Constant Time Comparisons**: Protection against timing attacks
* **Input Validation**: Comprehensive parameter checking
* **Error Handling**: Specific exceptions for different failure scenarios

## Technical Details

* **Key Size**: 256-bit AES key
* **Block Size**: 128-bit AES blocks
* **Salt Size**: 16 bytes
* **HMAC Size**: 32 bytes (SHA256)
* **PBKDF2 Iterations**: 100,000
* **Cipher Mode**: CBC
* **Padding Mode**: PKCS7