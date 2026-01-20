# Secp256k1.Net

[![NuGet](https://img.shields.io/nuget/v/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/) [![NuGet](https://img.shields.io/nuget/dt/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/) [![CI](https://github.com/zone117x/Secp256k1.Net/actions/workflows/tests.yml/badge.svg)](https://github.com/zone117x/Secp256k1.Net/actions/workflows/tests.yml) [![codecov](https://codecov.io/gh/zone117x/Secp256k1.Net/branch/master/graph/badge.svg?token=fCERq55vh9)](https://codecov.io/gh/zone117x/Secp256k1.Net)


Cross platform C# wrapper for the native [`bitcoin-core/secp256k1` C library](https://github.com/zone117x).

```shell
dotnet add package Secp256k1.Net
```

## Platform Support

This library includes pre-compiled binaries for the following platforms:

| OS | x64 | x86 | arm64 |
|----|:---:|:---:|:-----:|
| Windows | ✓ | ✓ | ✓ |
| Linux (glibc) | ✓ | ✓ | ✓ |
| Linux (musl/Alpine) | ✓ | | ✓ |
| macOS | ✓ | | ✓ |

This library targets `netstandard2.0` and `net8.0`, supporting a wide-range of .NET deployments: .NET Core 2.0+, .NET Framework 4.6.1+, Mono 5.4+, etc. Conditional compilation is used to enable optimized native library interop features available on modern targets (`net8.0` and above).

------

## Usage

The `Secp256k1` class provides instance methods that are wrappers for the native `secp256k1` C library with a near 1-1 API. These functions are generated from the C header files. For advanced usage, create an instance of the `Secp256k1` class and use these methods directly.

The `Secp256k1` class also exposes static functions that are idiomatic C#, using a thread-safe internal context. The following is an overview of those static functions:

#### Key Generation & Validation
- `CreateSecretKey()` - Generate a cryptographically secure random secret key
- `CreatePublicKey(secretKey, compressed)` - Derive a serialized public key from a secret key
- `CreateXOnlyPublicKey(secretKey)` - Derive an x-only public key and parity for BIP-340
- `CreateKeyPair(compressed)` - Generate a new secret key and public key pair
- `IsValidSecretKey(secretKey)` - Validate a secret key
- `IsValidPublicKey(publicKey)` - Validate a serialized public key

#### Public Key Operations
- `CompressPublicKey(publicKey)` - Convert a public key to 33-byte compressed format
- `DecompressPublicKey(publicKey)` - Convert a public key to 65-byte uncompressed format
- `NegatePublicKey(publicKey, compressed)` - Negate a public key
- `CombinePublicKeys(publicKeys, compressed)` - Add multiple public keys together

#### ECDSA Signing & Verification
- `Sign(messageHash, secretKey)` - Create a 64-byte compact ECDSA signature
- `Verify(signature, messageHash, publicKey)` - Verify an ECDSA signature
- `SignRecoverable(messageHash, secretKey)` - Create a recoverable signature with recovery ID
- `RecoverPublicKey(signature, recoveryId, messageHash, compressed)` - Recover public key from signature

#### DER Signature Format
- `SignatureToDer(compactSignature)` - Convert compact signature to DER format
- `SignatureFromDer(derSignature)` - Convert DER signature to compact format
- `VerifyDer(derSignature, messageHash, publicKey)` - Verify a DER-encoded signature

#### Signature Normalization
- `NormalizeSignature(signature)` - Normalize signature to lower-S form
- `IsNormalizedSignature(signature)` - Check if signature is in lower-S form

#### Schnorr Signatures (BIP-340)
- `SignSchnorr(messageHash, secretKey, auxRand)` - Create a Schnorr signature
- `VerifySchnorr(signature, message, publicKey)` - Verify a Schnorr signature

#### ECDH Key Agreement
- `ComputeSharedSecret(publicKey, secretKey)` - Compute ECDH shared secret

#### Key Tweaking (BIP-32 HD Wallets)
- `TweakSecretKeyAdd(secretKey, tweak)` - Add a tweak to a secret key
- `TweakPublicKeyAdd(publicKey, tweak, compressed)` - Add a tweak to a public key
- `TweakSecretKeyMul(secretKey, tweak)` - Multiply a secret key by a tweak
- `TweakPublicKeyMul(publicKey, tweak, compressed)` - Multiply a public key by a tweak
- `NegateSecretKey(secretKey)` - Negate a secret key

#### Hashing
- `TaggedHash(tag, message)` - Compute a BIP-340 tagged hash

## Example Usage

#### Generate key pair
```csharp
using var secp256k1 = new Secp256k1();

// Generate a private key
var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH];
var rnd = System.Security.Cryptography.RandomNumberGenerator.Create();
do { rnd.GetBytes(privateKey); }
while (!secp256k1.SecretKeyVerify(privateKey));

// Derive public key bytes
var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
Assert.True(secp256k1.PublicKeyCreate(publicKey, privateKey));

// Serialize the public key to compressed format
var serializedCompressedPublicKey = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
Assert.True(secp256k1.PublicKeySerialize(serializedCompressedPublicKey, publicKey, Flags.SECP256K1_EC_COMPRESSED));

// Serialize the public key to uncompressed format
var serializedUncompressedPublicKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
Assert.True(secp256k1.PublicKeySerialize(serializedUncompressedPublicKey, publicKey, Flags.SECP256K1_EC_UNCOMPRESSED));

// Parse public key from serialized compressed public key
var parsedPublicKey1 = new byte[Secp256k1.PUBKEY_LENGTH];
Assert.IsTrue(secp256k1.PublicKeyParse(parsedPublicKey1, serializedCompressedPublicKey));
Assert.AreEqual(Convert.ToHexString(publicKey), Convert.ToHexString(parsedPublicKey1));

// Parse public key from serialied uncompressed public key
var parsedPublicKey2 = new byte[Secp256k1.PUBKEY_LENGTH];
Assert.IsTrue(secp256k1.PublicKeyParse(parsedPublicKey2, serializedUncompressedPublicKey));
Assert.AreEqual(Convert.ToHexString(publicKey), Convert.ToHexString(parsedPublicKey2));
```

#### Sign and verify message
```csharp
using var secp256k1 = new Secp256k1();
var keypair = new
{
    PrivateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe"),
    PublicKey = Convert.FromHexString("2208d5dc41d4f3ed555aff761e9bb0b99fbe6d1503b98711944be6a362242ebfa1c788c7a4e13f6aaa4099f9d2175fc031e5aa3ba08eb280e87dfb43bdae207f")
};

// Create message hash
var msgBytes = System.Text.Encoding.UTF8.GetBytes("Hello!!");
var msgHash = System.Security.Cryptography.SHA256.HashData(msgBytes);
Assert.Equal(Secp256k1.HASH_LENGTH, msgHash.Length);

// Sign then verify message hash
var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
Assert.True(secp256k1.Sign(signature, msgHash, keypair.PrivateKey));
Assert.True(secp256k1.Verify(signature, msgHash, keypair.PublicKey));
```

#### Compute an ECDH (EC Diffie-Hellman) secret
```csharp
using var secp256k1 = new Secp256k1();
            
var aliceKeyPair = new
{
  PrivateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe"),
  PublicKey = Convert.FromHexString("2208d5dc41d4f3ed555aff761e9bb0b99fbe6d1503b98711944be6a362242ebfa1c788c7a4e13f6aaa4099f9d2175fc031e5aa3ba08eb280e87dfb43bdae207f")
};
var bobKeyPair = new
{
  PrivateKey = Convert.FromHexString("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda"),
  PublicKey = Convert.FromHexString("62127c4563f711169b1d3e56a34f218302a2587c3725bd418b9388933373e095d45ec4d74ca734599598c89d7719bda5fb799afeec89c6940d569e05bd5a1bba")
};

// Create secret using Alice's public key and Bob's private key
var secret1 = new byte[Secp256k1.SECRET_LENGTH];
Assert.True(secp256k1.Ecdh(secret1, aliceKeyPair.PublicKey, bobKeyPair.PrivateKey));

// Create secret using Bob's public key and Alice's private key
var secret2 = new byte[Secp256k1.SECRET_LENGTH];
Assert.True(secp256k1.Ecdh(secret2, bobKeyPair.PublicKey, aliceKeyPair.PrivateKey));

// Validate secrets match
Assert.Equal(Convert.ToHexString(secret1), Convert.ToHexString(secret2));
```

#### Parsing and serializing DER signatures
```csharp
using var secp256k1 = new Secp256k1();

// Parse DER signature
var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
var derSignature = Convert.FromHexString("30440220484ECE2B365D2B2C2EAD34B518328BBFEF0F4409349EEEC9CB19837B5795A5F5022040C4F6901FE489F923C49D4104554FD08595EAF864137F87DADDD0E3619B0605");                
Assert.True(secp256k1.SignatureParseDer(signatureOutput, derSignature));

// Serialize DER signature
Span<byte> derSignatureOutput = new byte[Secp256k1.SERIALIZED_DER_SIGNATURE_MAX_SIZE];
Assert.True(secp256k1.SignatureSerializeDer(derSignatureOutput, signatureOutput, out int signatureOutputLength));
derSignatureOutput = derSignatureOutput.Slice(0, signatureOutputLength);

// Validate signature is the same after round trip parse and serialize
Assert.Equal(Convert.ToHexString(derSignature), Convert.ToHexString(derSignatureOutput));
```

See the [tests project](Secp256k1.Net.Test/Tests.cs) for more examples. 

# Benchmarks

`Secp256k1.Net` is consistently 5-10x faster than the next best library (`NBitcoin`) and 20-100x faster than pure managed implementations like `BouncyCastle`, `Nethereum`, and `StarkBank`.

```

BenchmarkDotNet v0.15.8, macOS Sequoia 15.7.1 (24G231) [Darwin 24.6.0]
Apple M3 Max, 1 CPU, 14 logical and 14 physical cores
.NET SDK 10.0.102
  [Host]     : .NET 10.0.2 (10.0.2, 10.0.225.61305), Arm64 RyuJIT armv8.0-a
  DefaultJob : .NET 10.0.2 (10.0.2, 10.0.225.61305), Arm64 RyuJIT armv8.0-a


```
| Method       | Categories           | Mean        | Error     | StdDev    | Ratio  | RatioSD |
|------------- |--------------------- |------------:|----------:|----------:|-------:|--------:|
| Secp256k1Net | Ecdh                 |    24.22 μs |  0.091 μs |  0.080 μs |   1.00 |    0.00 |
| NBitcoin     | Ecdh                 |   166.38 μs |  0.937 μs |  0.876 μs |   6.87 |    0.04 |
| Nethereum    | Ecdh                 |   504.34 μs |  9.122 μs |  8.532 μs |  20.82 |    0.35 |
| BouncyCastle | Ecdh                 |   502.33 μs |  2.923 μs |  2.734 μs |  20.74 |    0.13 |
|              |                      |             |           |           |        |         |
| Secp256k1Net | EcdsaRecover         |    37.26 μs |  0.130 μs |  0.122 μs |   1.00 |    0.00 |
| NBitcoin     | EcdsaRecover         |   272.45 μs |  1.350 μs |  1.263 μs |   7.31 |    0.04 |
| Nethereum    | EcdsaRecover         | 1,992.73 μs | 16.378 μs | 14.519 μs |  53.48 |    0.41 |
| BouncyCastle | EcdsaRecover         | 2,292.69 μs | 43.517 μs | 44.689 μs |  61.53 |    1.18 |
|              |                      |             |           |           |        |         |
| Secp256k1Net | EcdsaSign            |    16.58 μs |  0.069 μs |  0.064 μs |   1.00 |    0.01 |
| NBitcoin     | EcdsaSign            |   132.70 μs |  0.685 μs |  0.640 μs |   8.00 |    0.05 |
| Nethereum    | EcdsaSign            |   309.83 μs |  0.898 μs |  0.750 μs |  18.69 |    0.08 |
| BouncyCastle | EcdsaSign            |   309.78 μs |  1.156 μs |  0.966 μs |  18.69 |    0.09 |
| StarkBank    | EcdsaSign            | 1,080.47 μs |  3.760 μs |  3.334 μs |  65.17 |    0.31 |
| Chainers     | EcdsaSign            |   289.83 μs |  3.314 μs |  3.100 μs |  17.48 |    0.19 |
|              |                      |             |           |           |        |         |
| Secp256k1Net | EcdsaSignRecoverable |    16.40 μs |  0.052 μs |  0.049 μs |   1.00 |    0.00 |
| NBitcoin     | EcdsaSignRecoverable |   132.17 μs |  0.367 μs |  0.344 μs |   8.06 |    0.03 |
| Nethereum    | EcdsaSignRecoverable | 1,310.32 μs |  6.890 μs |  6.445 μs |  79.92 |    0.45 |
| BouncyCastle | EcdsaSignRecoverable | 1,641.76 μs | 30.547 μs | 28.574 μs | 100.14 |    1.71 |
|              |                      |             |           |           |        |         |
| Secp256k1Net | EcdsaVerify          |    21.45 μs |  0.161 μs |  0.151 μs |   1.00 |    0.01 |
| NBitcoin     | EcdsaVerify          |   126.02 μs |  0.528 μs |  0.494 μs |   5.87 |    0.05 |
| Nethereum    | EcdsaVerify          |   577.03 μs |  3.442 μs |  3.052 μs |  26.90 |    0.23 |
| BouncyCastle | EcdsaVerify          |   577.13 μs |  2.090 μs |  1.955 μs |  26.91 |    0.20 |
| StarkBank    | EcdsaVerify          | 2,046.77 μs | 40.200 μs | 37.603 μs |  95.42 |    1.82 |
|              |                      |             |           |           |        |         |
| Secp256k1Net | PubKeyCreate         |    11.17 μs |  0.130 μs |  0.122 μs |   1.00 |    0.01 |
| NBitcoin     | PubKeyCreate         |    96.99 μs |  0.300 μs |  0.266 μs |   8.68 |    0.09 |
| Nethereum    | PubKeyCreate         |   391.79 μs |  3.126 μs |  2.924 μs |  35.07 |    0.45 |
| BouncyCastle | PubKeyCreate         |   393.72 μs |  1.596 μs |  1.415 μs |  35.25 |    0.39 |
| StarkBank    | PubKeyCreate         |   976.27 μs | 11.036 μs | 10.323 μs |  87.40 |    1.28 |
| Chainers     | PubKeyCreate         |    58.44 μs |  0.306 μs |  0.239 μs |   5.23 |    0.06 |
|              |                      |             |           |           |        |         |
| Secp256k1Net | SchnorrSign          |    22.05 μs |  0.111 μs |  0.104 μs |   1.00 |    0.01 |
| NBitcoin     | SchnorrSign          |   198.06 μs |  1.010 μs |  0.945 μs |   8.98 |    0.06 |
|              |                      |             |           |           |        |         |
| Secp256k1Net | SchnorrVerify        |    19.32 μs |  0.056 μs |  0.049 μs |   1.00 |    0.00 |
| NBitcoin     | SchnorrVerify        |   198.89 μs |  1.268 μs |  1.186 μs |  10.29 |    0.06 |

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
