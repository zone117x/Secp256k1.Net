# Secp256k1.Net

[![NuGet](https://img.shields.io/nuget/v/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/) [![NuGet](https://img.shields.io/nuget/dt/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/) [![CI](https://github.com/zone117x/Secp256k1.Net/actions/workflows/tests.yml/badge.svg)](https://github.com/zone117x/Secp256k1.Net/actions/workflows/tests.yml) [![codecov](https://codecov.io/gh/zone117x/Secp256k1.Net/branch/master/graph/badge.svg?token=fCERq55vh9)](https://codecov.io/gh/zone117x/Secp256k1.Net)


Cross platform C# wrapper for the native [`bitcoin-core/secp256k1` C library](https://github.com/zone117x).

```shell
dotnet add package Secp256k1.Net
```

## Platform Support

Pre-compiled binaries are bundled for the following platforms:

| OS | x64 | x86 | arm64 |
|----|:---:|:---:|:-----:|
| Windows | ✓ | ✓ | ✓ |
| Linux (glibc) | ✓ | ✓ | ✓ |
| Linux (musl/Alpine) | ✓ | | ✓ |
| macOS | ✓ | | ✓ |

This library targets `netstandard2.0` and `net8.0`, supporting a wide-range of .NET deployments: .NET Core 2.0+, .NET Framework 4.6.1+, Mono 5.4+, etc. Conditional compilation is used to enable optimized native library interop features available on modern targets (`net8.0` and above).

------

## Quick Start

```csharp
using Secp256k1Net;
using System.Security.Cryptography;
using System.Text;

// Generate a key pair
var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);

// Sign a message (ECDSA)
byte[] message = SHA256.HashData(Encoding.UTF8.GetBytes("Hello, secp256k1!"));
byte[] signature = Secp256k1.Sign(message, secretKey);
bool isValid = Secp256k1.Verify(signature, message, publicKey);

// Schnorr signatures (BIP-340)
var (xOnlyPubKey, _) = Secp256k1.CreateXOnlyPublicKey(secretKey);
byte[] schnorrSig = Secp256k1.SignSchnorr(message, secretKey);
bool schnorrValid = Secp256k1.VerifySchnorr(schnorrSig, message, xOnlyPubKey);

// ECDH shared secret
var (aliceSecret, alicePublic) = Secp256k1.CreateKeyPair(compressed: true);
var (bobSecret, bobPublic) = Secp256k1.CreateKeyPair(compressed: true);
byte[] sharedSecret1 = Secp256k1.ComputeSharedSecret(bobPublic, aliceSecret);
byte[] sharedSecret2 = Secp256k1.ComputeSharedSecret(alicePublic, bobSecret);
// sharedSecret1 == sharedSecret2
```

See the [examples project](Secp256k1.Net.Examples/) for more complete working examples.

## API Reference

The `Secp256k1` class exposes static functions that are idiomatic C#, using a thread-safe internal context:

#### Key Generation & Validation
- `CreateSecretKey()` - Generate a cryptographically secure random secret key ([example](Secp256k1.Net.Examples/KeyGenerationExamples.cs#L31))
- `CreatePublicKey(secretKey, compressed)` - Derive a serialized public key from a secret key ([example](Secp256k1.Net.Examples/KeyGenerationExamples.cs#L48))
- `CreateXOnlyPublicKey(secretKey)` - Derive an x-only public key and parity for BIP-340 ([example](Secp256k1.Net.Examples/KeyGenerationExamples.cs#L69))
- `CreateKeyPair(compressed)` - Generate a new secret key and public key pair ([example](Secp256k1.Net.Examples/KeyGenerationExamples.cs#L85))
- `IsValidSecretKey(secretKey)` - Validate a secret key ([example](Secp256k1.Net.Examples/KeyGenerationExamples.cs#L105))
- `IsValidPublicKey(publicKey)` - Validate a serialized public key ([example](Secp256k1.Net.Examples/KeyGenerationExamples.cs#L132))

#### Public Key Operations
- `CompressPublicKey(publicKey)` - Convert a public key to 33-byte compressed format ([example](Secp256k1.Net.Examples/PublicKeyOperationsExamples.cs#L34))
- `DecompressPublicKey(publicKey)` - Convert a public key to 65-byte uncompressed format ([example](Secp256k1.Net.Examples/PublicKeyOperationsExamples.cs#L57))
- `NegatePublicKey(publicKey, compressed)` - Negate a public key ([example](Secp256k1.Net.Examples/PublicKeyOperationsExamples.cs#L76))
- `CombinePublicKeys(publicKeys, compressed)` - Add multiple public keys together ([example](Secp256k1.Net.Examples/PublicKeyOperationsExamples.cs#L107))

#### ECDSA Signing & Verification
- `Sign(messageHash, secretKey)` - Create a 64-byte compact ECDSA signature ([example](Secp256k1.Net.Examples/EcdsaSigningExamples.cs#L41))
- `Verify(signature, messageHash, publicKey)` - Verify an ECDSA signature ([example](Secp256k1.Net.Examples/EcdsaSigningExamples.cs#L46))
- `SignRecoverable(messageHash, secretKey)` - Create a recoverable signature with recovery ID ([example](Secp256k1.Net.Examples/EcdsaSigningExamples.cs#L62))
- `RecoverPublicKey(signature, recoveryId, messageHash, compressed)` - Recover public key from signature ([example](Secp256k1.Net.Examples/EcdsaSigningExamples.cs#L86))

#### DER Signature Format
- `SignatureToDer(compactSignature)` - Convert compact signature to DER format ([example](Secp256k1.Net.Examples/DerSignatureExamples.cs#L37))
- `SignatureFromDer(derSignature)` - Convert DER signature to compact format ([example](Secp256k1.Net.Examples/DerSignatureExamples.cs#L58))
- `VerifyDer(derSignature, messageHash, publicKey)` - Verify a DER-encoded signature ([example](Secp256k1.Net.Examples/DerSignatureExamples.cs#L82))

#### Signature Normalization
- `NormalizeSignature(signature)` - Normalize signature to lower-S form ([example](Secp256k1.Net.Examples/SignatureNormalizationExamples.cs#L36))
- `IsNormalizedSignature(signature)` - Check if signature is in lower-S form ([example](Secp256k1.Net.Examples/SignatureNormalizationExamples.cs#L67))

#### Schnorr Signatures (BIP-340)
- `SignSchnorr(messageHash, secretKey, auxRand)` - Create a Schnorr signature ([example](Secp256k1.Net.Examples/SchnorrSignatureExamples.cs#L42))
- `VerifySchnorr(signature, message, publicKey)` - Verify a Schnorr signature ([example](Secp256k1.Net.Examples/SchnorrSignatureExamples.cs#L66))

#### ECDH Key Agreement
- `ComputeSharedSecret(publicKey, secretKey)` - Compute ECDH shared secret ([example](Secp256k1.Net.Examples/EcdhExamples.cs#L35))

#### Key Tweaking (BIP-32 HD Wallets)
- `TweakSecretKeyAdd(secretKey, tweak)` - Add a tweak to a secret key ([example](Secp256k1.Net.Examples/KeyTweakingExamples.cs#L37))
- `TweakPublicKeyAdd(publicKey, tweak, compressed)` - Add a tweak to a public key ([example](Secp256k1.Net.Examples/KeyTweakingExamples.cs#L60))
- `TweakSecretKeyMul(secretKey, tweak)` - Multiply a secret key by a tweak ([example](Secp256k1.Net.Examples/KeyTweakingExamples.cs#L87))
- `TweakPublicKeyMul(publicKey, tweak, compressed)` - Multiply a public key by a tweak ([example](Secp256k1.Net.Examples/KeyTweakingExamples.cs#L107))
- `NegateSecretKey(secretKey)` - Negate a secret key ([example](Secp256k1.Net.Examples/KeyTweakingExamples.cs#L134))

#### Hashing
- `TaggedHash(tag, message)` - Compute a BIP-340 tagged hash ([example](Secp256k1.Net.Examples/HashingExamples.cs#L32))

## Advanced Usage

The `Secp256k1` class also provides instance methods that are direct wrappers for the native C library, with near one-to-one API mapping. These offer more control over memory allocation and access to additional features:

- [Custom ECDH hash functions](Secp256k1.Net.Examples/AdvancedUsageExamples.cs#L119) - Use custom hash functions for ECDH
- [Custom nonce functions](Secp256k1.Net.Examples/AdvancedUsageExamples.cs#L179) - Provide custom nonce generation for signing
- [Public key sorting](Secp256k1.Net.Examples/AdvancedUsageExamples.cs#L273) - Sort public keys lexicographically
- [Keypair operations](Secp256k1.Net.Examples/AdvancedUsageExamples.cs#L307) - Work with 96-byte keypair objects
- [X-only pubkey tweaking](Secp256k1.Net.Examples/AdvancedUsageExamples.cs#L430) - Taproot-style key tweaking (BIP-341)
- [ElligatorSwift encoding](Secp256k1.Net.Examples/AdvancedUsageExamples.cs#L493) - BIP-324 encrypted transport
- [MuSig2 multi-signatures](Secp256k1.Net.Examples/MuSig2Examples.cs#L57) - Aggregate Schnorr signatures from multiple signers 

# Benchmarks

`Secp256k1.Net` is consistently 5-10x faster than the next best library (`NBitcoin`) and 20-100x faster than pure managed implementations like `BouncyCastle`, `Nethereum`, and `StarkBank`.

```

BenchmarkDotNet v0.15.8, macOS Sequoia 15.7.1 (24G231) [Darwin 24.6.0]
Apple M3 Max, 1 CPU, 14 logical and 14 physical cores
.NET SDK 10.0.102
  [Host]     : .NET 10.0.2 (10.0.2, 10.0.225.61305), Arm64 RyuJIT armv8.0-a
  DefaultJob : .NET 10.0.2 (10.0.2, 10.0.225.61305), Arm64 RyuJIT armv8.0-a


```
| Method       | Categories           | Mean         | Error      | StdDev     | Ratio  | RatioSD |
|------------- |--------------------- |-------------:|-----------:|-----------:|-------:|--------:|
| Secp256k1Net | Ecdh                 |    22.964 μs |  0.1813 μs |  0.1607 μs |   1.00 |    0.01 |
| NBitcoin     | Ecdh                 |   167.133 μs |  0.6087 μs |  0.5694 μs |   7.28 |    0.05 |
| Nethereum    | Ecdh                 |   500.696 μs |  3.4009 μs |  3.1812 μs |  21.80 |    0.20 |
| BouncyCastle | Ecdh                 |   503.882 μs |  6.4419 μs |  6.0257 μs |  21.94 |    0.29 |
|              |                      |              |            |            |        |         |
| Secp256k1Net | EcdsaRecover         |    36.042 μs |  0.1504 μs |  0.1333 μs |   1.00 |    0.01 |
| NBitcoin     | EcdsaRecover         |   268.565 μs |  1.1492 μs |  1.0187 μs |   7.45 |    0.04 |
| Nethereum    | EcdsaRecover         | 1,977.580 μs | 14.0846 μs | 12.4856 μs |  54.87 |    0.39 |
| BouncyCastle | EcdsaRecover         | 2,270.418 μs | 27.8990 μs | 26.0967 μs |  62.99 |    0.74 |
|              |                      |              |            |            |        |         |
| Secp256k1Net | EcdsaSign            |    15.231 μs |  0.0491 μs |  0.0436 μs |   1.00 |    0.00 |
| NBitcoin     | EcdsaSign            |   133.297 μs |  0.5326 μs |  0.4721 μs |   8.75 |    0.04 |
| Nethereum    | EcdsaSign            |   319.805 μs |  2.8822 μs |  2.6960 μs |  21.00 |    0.18 |
| BouncyCastle | EcdsaSign            |   312.781 μs |  2.3212 μs |  1.9383 μs |  20.54 |    0.14 |
| StarkBank    | EcdsaSign            | 1,085.330 μs |  6.0425 μs |  5.6522 μs |  71.26 |    0.41 |
| Chainers     | EcdsaSign            |   293.091 μs |  4.1747 μs |  3.9051 μs |  19.24 |    0.25 |
|              |                      |              |            |            |        |         |
| Secp256k1Net | EcdsaSignRecoverable |    15.052 μs |  0.0400 μs |  0.0312 μs |   1.00 |    0.00 |
| NBitcoin     | EcdsaSignRecoverable |   133.714 μs |  0.7474 μs |  0.6626 μs |   8.88 |    0.05 |
| Nethereum    | EcdsaSignRecoverable | 1,376.987 μs | 12.3970 μs | 10.9896 μs |  91.48 |    0.73 |
| BouncyCastle | EcdsaSignRecoverable | 1,630.056 μs | 17.9736 μs | 16.8126 μs | 108.29 |    1.10 |
|              |                      |              |            |            |        |         |
| Secp256k1Net | EcdsaVerify          |    20.045 μs |  0.1364 μs |  0.1276 μs |   1.00 |    0.01 |
| NBitcoin     | EcdsaVerify          |   128.001 μs |  1.1558 μs |  1.0246 μs |   6.39 |    0.06 |
| Nethereum    | EcdsaVerify          |   588.907 μs | 10.3029 μs |  9.1332 μs |  29.38 |    0.48 |
| BouncyCastle | EcdsaVerify          |   582.463 μs |  8.7357 μs |  8.1713 μs |  29.06 |    0.43 |
| StarkBank    | EcdsaVerify          | 2,105.913 μs | 31.3613 μs | 29.3354 μs | 105.06 |    1.56 |
|              |                      |              |            |            |        |         |
| Secp256k1Net | PubKeyCreate         |     9.759 μs |  0.0638 μs |  0.0566 μs |   1.00 |    0.01 |
| NBitcoin     | PubKeyCreate         |    95.283 μs |  0.5591 μs |  0.4956 μs |   9.76 |    0.07 |
| Nethereum    | PubKeyCreate         |   378.257 μs |  2.0409 μs |  1.9091 μs |  38.76 |    0.29 |
| BouncyCastle | PubKeyCreate         |   377.224 μs |  3.0774 μs |  2.5698 μs |  38.65 |    0.33 |
| StarkBank    | PubKeyCreate         |   990.958 μs |  9.6931 μs |  9.0669 μs | 101.54 |    1.06 |
| Chainers     | PubKeyCreate         |    57.937 μs |  0.5150 μs |  0.4818 μs |   5.94 |    0.06 |
|              |                      |              |            |            |        |         |
| Secp256k1Net | SchnorrSign          |    20.296 μs |  0.1379 μs |  0.1290 μs |   1.00 |    0.01 |
| NBitcoin     | SchnorrSign          |   194.996 μs |  1.0752 μs |  0.9531 μs |   9.61 |    0.07 |
|              |                      |              |            |            |        |         |
| Secp256k1Net | SchnorrVerify        |    20.199 μs |  0.1088 μs |  0.1018 μs |   1.00 |    0.01 |
| NBitcoin     | SchnorrVerify        |   192.977 μs |  0.4276 μs |  0.3999 μs |   9.55 |    0.05 |

---

```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26100.7462/24H2/2024Update/HudsonValley) (Hyper-V)
Intel Xeon Platinum 8370C CPU 2.80GHz (Max: 2.79GHz), 1 CPU, 4 logical and 2 physical cores
.NET SDK 10.0.102
  [Host]   : .NET 10.0.2 (10.0.2, 10.0.225.61305), X64 RyuJIT x86-64-v4
  ShortRun : .NET 10.0.2 (10.0.2, 10.0.225.61305), X64 RyuJIT x86-64-v4

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

```
| Method       | Categories           | Mean        | Error        | StdDev     | Ratio | RatioSD |
|------------- |--------------------- |------------:|-------------:|-----------:|------:|--------:|
| Secp256k1Net | Ecdh                 |    52.42 μs |     9.141 μs |   0.501 μs |  1.00 |    0.01 |
| NBitcoin     | Ecdh                 |   298.68 μs |     4.568 μs |   0.250 μs |  5.70 |    0.05 |
| Nethereum    | Ecdh                 |   928.84 μs |    78.708 μs |   4.314 μs | 17.72 |    0.16 |
| BouncyCastle | Ecdh                 | 1,028.87 μs |   408.540 μs |  22.393 μs | 19.63 |    0.40 |
|              |                      |             |              |            |       |         |
| Secp256k1Net | EcdsaRecover         |    83.14 μs |    52.429 μs |   2.874 μs |  1.00 |    0.04 |
| NBitcoin     | EcdsaRecover         |   521.88 μs |   182.631 μs |  10.011 μs |  6.28 |    0.21 |
| Nethereum    | EcdsaRecover         | 4,204.95 μs | 1,926.313 μs | 105.588 μs | 50.61 |    1.87 |
| BouncyCastle | EcdsaRecover         | 4,681.68 μs | 3,295.534 μs | 180.639 μs | 56.35 |    2.52 |
|              |                      |             |              |            |       |         |
| Secp256k1Net | EcdsaSign            |    34.74 μs |    17.371 μs |   0.952 μs |  1.00 |    0.03 |
| NBitcoin     | EcdsaSign            |   235.00 μs |     9.356 μs |   0.513 μs |  6.77 |    0.16 |
| Nethereum    | EcdsaSign            |   615.69 μs |    77.304 μs |   4.237 μs | 17.73 |    0.43 |
| BouncyCastle | EcdsaSign            |   603.43 μs |    51.399 μs |   2.817 μs | 17.38 |    0.42 |
| StarkBank    | EcdsaSign            | 1,610.20 μs |   322.548 μs |  17.680 μs | 46.37 |    1.18 |
| Chainers     | EcdsaSign            |   645.17 μs |   356.116 μs |  19.520 μs | 18.58 |    0.66 |
|              |                      |             |              |            |       |         |
| Secp256k1Net | EcdsaSignRecoverable |    33.44 μs |     0.760 μs |   0.042 μs |  1.00 |    0.00 |
| NBitcoin     | EcdsaSignRecoverable |   239.78 μs |   161.529 μs |   8.854 μs |  7.17 |    0.23 |
| Nethereum    | EcdsaSignRecoverable | 2,486.05 μs |   349.196 μs |  19.141 μs | 74.35 |    0.50 |
| BouncyCastle | EcdsaSignRecoverable | 3,058.70 μs | 1,589.421 μs |  87.122 μs | 91.47 |    2.26 |
|              |                      |             |              |            |       |         |
| Secp256k1Net | EcdsaVerify          |    44.77 μs |     4.161 μs |   0.228 μs |  1.00 |    0.01 |
| NBitcoin     | EcdsaVerify          |   244.93 μs |    11.689 μs |   0.641 μs |  5.47 |    0.03 |
| Nethereum    | EcdsaVerify          | 1,108.03 μs |    93.805 μs |   5.142 μs | 24.75 |    0.15 |
| BouncyCastle | EcdsaVerify          | 1,142.20 μs |   138.179 μs |   7.574 μs | 25.51 |    0.18 |
| StarkBank    | EcdsaVerify          | 3,164.81 μs |   456.649 μs |  25.030 μs | 70.69 |    0.58 |
|              |                      |             |              |            |       |         |
| Secp256k1Net | PubKeyCreate         |    23.61 μs |     5.538 μs |   0.304 μs |  1.00 |    0.02 |
| NBitcoin     | PubKeyCreate         |   180.93 μs |     3.066 μs |   0.168 μs |  7.66 |    0.08 |
| Nethereum    | PubKeyCreate         |   721.42 μs |    41.428 μs |   2.271 μs | 30.56 |    0.35 |
| BouncyCastle | PubKeyCreate         |   748.16 μs |    42.694 μs |   2.340 μs | 31.69 |    0.36 |
| StarkBank    | PubKeyCreate         | 1,579.52 μs |    48.830 μs |   2.677 μs | 66.91 |    0.75 |
| Chainers     | PubKeyCreate         |   117.26 μs |     3.038 μs |   0.167 μs |  4.97 |    0.06 |
|              |                      |             |              |            |       |         |
| Secp256k1Net | SchnorrSign          |    45.42 μs |     1.347 μs |   0.074 μs |  1.00 |    0.00 |
| NBitcoin     | SchnorrSign          |   373.44 μs |    27.746 μs |   1.521 μs |  8.22 |    0.03 |
|              |                      |             |              |            |       |         |
| Secp256k1Net | SchnorrVerify        |    38.90 μs |     8.268 μs |   0.453 μs |  1.00 |    0.01 |
| NBitcoin     | SchnorrVerify        |   384.05 μs |     9.204 μs |   0.505 μs |  9.87 |    0.10 |

---

```

BenchmarkDotNet v0.15.8, Linux Ubuntu 24.04.3 LTS (Noble Numbat)
Intel Xeon Platinum 8370C CPU 2.80GHz (Max: 3.39GHz), 1 CPU, 4 logical and 2 physical cores
.NET SDK 10.0.102
  [Host]   : .NET 10.0.2 (10.0.2, 10.0.225.61305), X64 RyuJIT x86-64-v4
  ShortRun : .NET 10.0.2 (10.0.2, 10.0.225.61305), X64 RyuJIT x86-64-v4

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

```
| Method       | Categories           | Mean        | Error      | StdDev    | Ratio | RatioSD |
|------------- |--------------------- |------------:|-----------:|----------:|------:|--------:|
| Secp256k1Net | Ecdh                 |    53.32 μs |   4.543 μs |  0.249 μs |  1.00 |    0.01 |
| NBitcoin     | Ecdh                 |   291.39 μs |  36.415 μs |  1.996 μs |  5.47 |    0.04 |
| Nethereum    | Ecdh                 | 1,059.77 μs | 348.103 μs | 19.081 μs | 19.88 |    0.32 |
| BouncyCastle | Ecdh                 | 1,031.91 μs | 129.167 μs |  7.080 μs | 19.35 |    0.14 |
|              |                      |             |            |           |       |         |
| Secp256k1Net | EcdsaRecover         |    79.91 μs |   1.059 μs |  0.058 μs |  1.00 |    0.00 |
| NBitcoin     | EcdsaRecover         |   486.64 μs |   6.764 μs |  0.371 μs |  6.09 |    0.01 |
| Nethereum    | EcdsaRecover         | 4,022.64 μs | 707.698 μs | 38.791 μs | 50.34 |    0.42 |
| BouncyCastle | EcdsaRecover         | 4,793.43 μs | 863.738 μs | 47.344 μs | 59.99 |    0.51 |
|              |                      |             |            |           |       |         |
| Secp256k1Net | EcdsaSign            |    38.09 μs |   0.881 μs |  0.048 μs |  1.00 |    0.00 |
| NBitcoin     | EcdsaSign            |   232.55 μs |   8.640 μs |  0.474 μs |  6.11 |    0.01 |
| Nethereum    | EcdsaSign            |   667.88 μs |  26.910 μs |  1.475 μs | 17.53 |    0.04 |
| BouncyCastle | EcdsaSign            |   668.15 μs |  86.774 μs |  4.756 μs | 17.54 |    0.11 |
| StarkBank    | EcdsaSign            | 1,611.32 μs |  50.303 μs |  2.757 μs | 42.30 |    0.08 |
| Chainers     | EcdsaSign            |   660.49 μs | 151.176 μs |  8.286 μs | 17.34 |    0.19 |
|              |                      |             |            |           |       |         |
| Secp256k1Net | EcdsaSignRecoverable |    37.37 μs |   1.007 μs |  0.055 μs |  1.00 |    0.00 |
| NBitcoin     | EcdsaSignRecoverable |   232.93 μs |   5.037 μs |  0.276 μs |  6.23 |    0.01 |
| Nethereum    | EcdsaSignRecoverable | 2,755.96 μs | 242.894 μs | 13.314 μs | 73.75 |    0.32 |
| BouncyCastle | EcdsaSignRecoverable | 3,459.83 μs | 473.894 μs | 25.976 μs | 92.58 |    0.61 |
|              |                      |             |            |           |       |         |
| Secp256k1Net | EcdsaVerify          |    44.42 μs |   0.426 μs |  0.023 μs |  1.00 |    0.00 |
| NBitcoin     | EcdsaVerify          |   236.92 μs |   4.157 μs |  0.228 μs |  5.33 |    0.01 |
| Nethereum    | EcdsaVerify          | 1,221.70 μs | 529.962 μs | 29.049 μs | 27.51 |    0.57 |
| BouncyCastle | EcdsaVerify          | 1,210.26 μs |  83.885 μs |  4.598 μs | 27.25 |    0.09 |
| StarkBank    | EcdsaVerify          | 3,176.97 μs | 376.794 μs | 20.653 μs | 71.53 |    0.40 |
|              |                      |             |            |           |       |         |
| Secp256k1Net | PubKeyCreate         |    27.53 μs |   0.828 μs |  0.045 μs |  1.00 |    0.00 |
| NBitcoin     | PubKeyCreate         |   170.63 μs |   1.680 μs |  0.092 μs |  6.20 |    0.01 |
| Nethereum    | PubKeyCreate         |   795.21 μs | 126.844 μs |  6.953 μs | 28.89 |    0.22 |
| BouncyCastle | PubKeyCreate         |   773.25 μs | 234.863 μs | 12.874 μs | 28.09 |    0.41 |
| StarkBank    | PubKeyCreate         | 1,536.89 μs |  53.979 μs |  2.959 μs | 55.83 |    0.12 |
| Chainers     | PubKeyCreate         |   118.50 μs |   5.219 μs |  0.286 μs |  4.30 |    0.01 |
|              |                      |             |            |           |       |         |
| Secp256k1Net | SchnorrSign          |    53.37 μs |   1.060 μs |  0.058 μs |  1.00 |    0.00 |
| NBitcoin     | SchnorrSign          |   354.83 μs |  38.171 μs |  2.092 μs |  6.65 |    0.03 |
|              |                      |             |            |           |       |         |
| Secp256k1Net | SchnorrVerify        |    37.96 μs |   0.644 μs |  0.035 μs |  1.00 |    0.00 |
| NBitcoin     | SchnorrVerify        |   369.41 μs |   8.029 μs |  0.440 μs |  9.73 |    0.01 |
