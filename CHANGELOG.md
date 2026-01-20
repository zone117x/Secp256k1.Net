# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-01-19

### Added

- New idiomatic C# static API with thread-safe internal context
- Key generation: `CreateSecretKey()`, `CreatePublicKey()`, `CreateKeyPair()`, `CreateXOnlyPublicKey()`
- Key validation: `IsValidSecretKey()`, `IsValidPublicKey()`
- Public key operations: `CompressPublicKey()`, `DecompressPublicKey()`, `NegatePublicKey()`, `CombinePublicKeys()`
- ECDSA signing: `Sign()`, `Verify()`, `SignRecoverable()`, `RecoverPublicKey()`
- DER signatures: `SignatureToDer()`, `SignatureFromDer()`, `VerifyDer()`
- Signature normalization: `NormalizeSignature()`, `IsNormalizedSignature()`
- Schnorr signatures (BIP-340): `SignSchnorr()`, `VerifySchnorr()`
- ECDH: `ComputeSharedSecret()`
- Key tweaking (BIP-32): `TweakSecretKeyAdd()`, `TweakPublicKeyAdd()`, `TweakSecretKeyMul()`, `TweakPublicKeyMul()`, `NegateSecretKey()`
- Tagged hashing (BIP-340): `TaggedHash()`
- MuSig2 multi-signature support
- ElligatorSwift encoding (BIP-324)
- X-only public key operations for Taproot (BIP-341)
- Keypair operations for efficient Schnorr signing
- Public key sorting and comparison
- Custom ECDH hash function support
- Custom nonce function support
- New platform target: Linux musl (Alpine) x64/arm64
- Comprehensive examples project

### Changed

- Updated native secp256k1 library to latest version
- All functions in the secp256k1 C library are now exposed, including all modules (extrakeys, schnorrsig, ecdh, recovery, ellswift, musig)
- All interop functions are now auto-generated from the native C library header files
- Improved error handling with descriptive exceptions
- Modernized native interop for .NET 8+:
  - Uses unmanaged function pointers (`delegate* unmanaged[Cdecl]`) instead of delegate instances, reducing allocations and improving call performance
  - Uses `NativeLibrary.GetExport()` for direct symbol resolution instead of `Marshal.GetDelegateForFunctionPointer()`
  - Falls back to delegate-based approach on older .NET versions for compatibility

### Breaking Changes

The 2.0 release introduces a new idiomatic C# API. The old instance-based API is still available for advanced use cases, but the recommended approach is now to use the static methods.

#### Migration Guide

**Key Generation (Before)**
```csharp
using var secp256k1 = new Secp256k1();

var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH];
var rnd = RandomNumberGenerator.Create();
do { rnd.GetBytes(privateKey); }
while (!secp256k1.SecretKeyVerify(privateKey));

var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
secp256k1.PublicKeyCreate(publicKey, privateKey);

var serializedKey = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
secp256k1.PublicKeySerialize(serializedKey, publicKey, Flags.SECP256K1_EC_COMPRESSED);
```

**Key Generation (After)**
```csharp
var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);

// Or generate separately:
byte[] secretKey = Secp256k1.CreateSecretKey();
byte[] publicKey = Secp256k1.CreatePublicKey(secretKey, compressed: true);
```

---

**Signing & Verification (Before)**
```csharp
using var secp256k1 = new Secp256k1();

var msgHash = SHA256.HashData(msgBytes);
var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
secp256k1.Sign(signature, msgHash, privateKey);

bool valid = secp256k1.Verify(signature, msgHash, publicKey);
```

**Signing & Verification (After)**
```csharp
byte[] msgHash = SHA256.HashData(msgBytes);
byte[] signature = Secp256k1.Sign(msgHash, secretKey);

bool valid = Secp256k1.Verify(signature, msgHash, publicKey);
```

---

**ECDH Shared Secret (Before)**
```csharp
using var secp256k1 = new Secp256k1();

var secret = new byte[Secp256k1.SECRET_LENGTH];
secp256k1.Ecdh(secret, otherPartyPublicKey, yourPrivateKey);
```

**ECDH Shared Secret (After)**
```csharp
byte[] secret = Secp256k1.ComputeSharedSecret(otherPartyPublicKey, yourSecretKey);
```

---

**DER Signature Parsing (Before)**
```csharp
using var secp256k1 = new Secp256k1();

var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
secp256k1.SignatureParseDer(signatureOutput, derSignatureBytes);

Span<byte> derOutput = new byte[Secp256k1.SERIALIZED_DER_SIGNATURE_MAX_SIZE];
secp256k1.SignatureSerializeDer(derOutput, signature, out int length);
derOutput = derOutput.Slice(0, length);
```

**DER Signature Parsing (After)**
```csharp
byte[] compactSignature = Secp256k1.SignatureFromDer(derSignatureBytes);
byte[] derSignature = Secp256k1.SignatureToDer(compactSignature);
```

---

**Public Key Serialization (Before)**
```csharp
using var secp256k1 = new Secp256k1();

// Parse serialized key to internal format
var internalPubkey = new byte[Secp256k1.PUBKEY_LENGTH];
secp256k1.PublicKeyParse(internalPubkey, serializedCompressedKey);

// Serialize to different format
var uncompressedKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
secp256k1.PublicKeySerialize(uncompressedKey, internalPubkey, Flags.SECP256K1_EC_UNCOMPRESSED);
```

**Public Key Serialization (After)**
```csharp
// Convert between formats directly
byte[] uncompressedKey = Secp256k1.DecompressPublicKey(compressedKey);
byte[] compressedKey = Secp256k1.CompressPublicKey(uncompressedKey);
```

## [1.4.0] and earlier

See [NuGet version history](https://www.nuget.org/packages/Secp256k1.Net#versions-body-tab) for previous releases.

[Unreleased]: https://github.com/zone117x/Secp256k1.Net/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/zone117x/Secp256k1.Net/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/zone117x/Secp256k1.Net/tree/v1.4.0
