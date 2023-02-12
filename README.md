# Secp256k1.Net

[![NuGet](https://img.shields.io/nuget/v/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/) [![NuGet](https://img.shields.io/nuget/dt/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/) [![CI](https://github.com/zone117x/Secp256k1.Net/actions/workflows/tests.yml/badge.svg)](https://github.com/zone117x/Secp256k1.Net/actions/workflows/tests.yml) [![codecov](https://codecov.io/gh/zone117x/Secp256k1.Net/branch/master/graph/badge.svg?token=fCERq55vh9)](https://codecov.io/gh/zone117x/Secp256k1.Net)


Cross platform C# wrapper for the native [secp256k1 library](https://github.com/zone117x/secp256k1/blob/master/Secp256k1.Native.nuspec).

The nuget package supports win-x64, win-x86, win-arm64, macOS-x64, macOS-arm64 (Apple Silcon), linux-x64, linux-x86, and linux-arm64 out of the box. The native libraries are bundled from the [Secp256k1.Native package](https://www.nuget.org/packages/Secp256k1.Native/). This wrapper should work on any other platform that supports netstandard2.0 (.NET Core 2.0+, Mono 5.4+, etc) but requires that the [native secp256k1](https://github.com/zone117x/secp256k1) library be compiled from source. 

------

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

``` ini

BenchmarkDotNet=v0.13.4, OS=macOS Monterey 12.6.2 (21G320) [Darwin 21.6.0]
Apple M1 Pro, 1 CPU, 10 logical and 10 physical cores
.NET SDK=7.0.102
  [Host]     : .NET 7.0.2 (7.0.222.60605), Arm64 RyuJIT AdvSIMD
  DefaultJob : .NET 7.0.2 (7.0.222.60605), Arm64 RyuJIT AdvSIMD


```
|       Method |       feature |        Mean |     Error |    StdDev | Ratio | RatioSD |
|------------- |-------------- |------------:|----------:|----------:|------:|--------:|
| **Secp256k1Net** |      **SignOnly** |    **53.00 μs** |  **0.044 μs** |  **0.037 μs** |  **1.00** |    **0.00** |
|     Nbitcoin |      SignOnly |   186.25 μs |  0.255 μs |  0.226 μs |  3.51 |    0.01 |
|    Nethereum |      SignOnly |   579.06 μs |  1.272 μs |  0.993 μs | 10.93 |    0.02 |
| BouncyCastle |      SignOnly |   582.83 μs |  6.968 μs |  5.818 μs | 11.00 |    0.11 |
|     Chainers |      SignOnly |   778.34 μs | 15.176 μs | 14.905 μs | 14.72 |    0.30 |
|    StarkBank |      SignOnly | 1,800.91 μs |  4.751 μs |  4.444 μs | 34.00 |    0.10 |
|              |               |             |           |           |       |         |
| **Secp256k1Net** | **SignAndVerify** |    **90.97 μs** |  **0.084 μs** |  **0.075 μs** |  **1.00** |    **0.00** |
|     Nbitcoin | SignAndVerify |   373.22 μs |  1.822 μs |  1.521 μs |  4.10 |    0.02 |
|    Nethereum | SignAndVerify | 1,679.02 μs |  3.984 μs |  3.327 μs | 18.46 |    0.04 |
| BouncyCastle | SignAndVerify | 1,701.31 μs | 18.157 μs | 16.985 μs | 18.72 |    0.18 |
|    StarkBank | SignAndVerify | 5,315.49 μs | 15.796 μs | 14.002 μs | 58.43 |    0.15 |

---

``` ini

BenchmarkDotNet=v0.13.4, OS=macOS Monterey 12.6.3 (21G419) [Darwin 21.6.0]
Intel Xeon CPU E5-1650 v2 3.50GHz (Max: 3.34GHz), 1 CPU, 3 logical and 3 physical cores
.NET SDK=7.0.102
  [Host]     : .NET 7.0.2 (7.0.222.60605), X64 RyuJIT AVX
  DefaultJob : .NET 7.0.2 (7.0.222.60605), X64 RyuJIT AVX


```
|       Method |       feature |        Mean |      Error |     StdDev |      Median | Ratio | RatioSD |
|------------- |-------------- |------------:|-----------:|-----------:|------------:|------:|--------:|
| **Secp256k1Net** |      **SignOnly** |    **97.17 μs** |   **4.112 μs** |  **11.666 μs** |    **93.27 μs** |  **1.00** |    **0.00** |
|     Nbitcoin |      SignOnly |   362.74 μs |  15.863 μs |  45.769 μs |   357.29 μs |  3.79 |    0.65 |
|    Nethereum |      SignOnly | 1,122.70 μs |  28.246 μs |  78.740 μs | 1,098.21 μs | 11.71 |    1.46 |
| BouncyCastle |      SignOnly | 1,079.60 μs |  21.453 μs |  43.823 μs | 1,067.88 μs | 11.18 |    1.36 |
|     Chainers |      SignOnly | 1,300.33 μs |  23.165 μs |  30.121 μs | 1,301.86 μs | 12.49 |    1.65 |
|    StarkBank |      SignOnly | 2,564.26 μs |  41.055 μs |  40.322 μs | 2,566.36 μs | 25.16 |    2.97 |
|              |               |             |            |            |             |       |         |
| **Secp256k1Net** | **SignAndVerify** |   **146.25 μs** |   **2.679 μs** |   **2.506 μs** |   **145.54 μs** |  **1.00** |    **0.00** |
|     Nbitcoin | SignAndVerify |   724.20 μs |   7.401 μs |   6.561 μs |   723.84 μs |  4.95 |    0.09 |
|    Nethereum | SignAndVerify | 3,048.38 μs |  59.507 μs |  55.663 μs | 3,058.23 μs | 20.85 |    0.57 |
| BouncyCastle | SignAndVerify | 2,997.17 μs |  51.521 μs |  45.672 μs | 2,999.00 μs | 20.48 |    0.41 |
|    StarkBank | SignAndVerify | 8,008.58 μs | 159.859 μs | 304.149 μs | 8,022.61 μs | 53.30 |    2.05 |

---

``` ini

BenchmarkDotNet=v0.13.4, OS=ubuntu 22.04
Intel Xeon Platinum 8370C CPU 2.80GHz, 1 CPU, 2 logical and 2 physical cores
.NET SDK=7.0.102
  [Host]     : .NET 7.0.2 (7.0.222.60605), X64 RyuJIT AVX2
  DefaultJob : .NET 7.0.2 (7.0.222.60605), X64 RyuJIT AVX2


```
|       Method |       feature |        Mean |     Error |    StdDev | Ratio | RatioSD |
|------------- |-------------- |------------:|----------:|----------:|------:|--------:|
| **Secp256k1Net** |      **SignOnly** |    **88.61 μs** |  **0.047 μs** |  **0.041 μs** |  **1.00** |    **0.00** |
|     Nbitcoin |      SignOnly |   303.01 μs |  0.478 μs |  0.447 μs |  3.42 |    0.01 |
|    Nethereum |      SignOnly |   988.51 μs |  4.649 μs |  4.348 μs | 11.16 |    0.05 |
| BouncyCastle |      SignOnly | 1,005.06 μs |  4.370 μs |  4.087 μs | 11.35 |    0.05 |
|     Chainers |      SignOnly | 1,545.85 μs | 29.765 μs | 29.233 μs | 17.42 |    0.35 |
|    StarkBank |      SignOnly | 2,441.18 μs |  5.709 μs |  5.340 μs | 27.55 |    0.06 |
|              |               |             |           |           |       |         |
| **Secp256k1Net** | **SignAndVerify** |   **146.08 μs** |  **0.047 μs** |  **0.039 μs** |  **1.00** |    **0.00** |
|     Nbitcoin | SignAndVerify |   631.46 μs |  0.782 μs |  0.693 μs |  4.32 |    0.01 |
|    Nethereum | SignAndVerify | 2,800.69 μs | 19.084 μs | 17.851 μs | 19.17 |    0.13 |
| BouncyCastle | SignAndVerify | 2,878.09 μs | 16.666 μs | 14.774 μs | 19.71 |    0.10 |
|    StarkBank | SignAndVerify | 7,121.17 μs | 13.625 μs | 12.745 μs | 48.77 |    0.08 |

---

``` ini

BenchmarkDotNet=v0.13.4, OS=Windows 10 (10.0.20348.1487), VM=Hyper-V
Intel Xeon CPU E5-2673 v4 2.30GHz, 1 CPU, 2 logical and 2 physical cores
.NET SDK=7.0.102
  [Host]     : .NET 7.0.2 (7.0.222.60605), X64 RyuJIT AVX2
  DefaultJob : .NET 7.0.2 (7.0.222.60605), X64 RyuJIT AVX2


```
|       Method |       feature |       Mean |     Error |    StdDev | Ratio | RatioSD |
|------------- |-------------- |-----------:|----------:|----------:|------:|--------:|
| **Secp256k1Net** |      **SignOnly** |   **165.8 μs** |   **3.28 μs** |   **3.07 μs** |  **1.00** |    **0.00** |
|     Nbitcoin |      SignOnly |   374.1 μs |   7.43 μs |   8.84 μs |  2.25 |    0.06 |
|    Nethereum |      SignOnly | 1,206.2 μs |  20.57 μs |  20.21 μs |  7.28 |    0.21 |
| BouncyCastle |      SignOnly | 1,200.1 μs |  20.21 μs |  18.91 μs |  7.24 |    0.17 |
|     Chainers |      SignOnly | 1,613.4 μs |  31.76 μs |  50.38 μs |  9.78 |    0.31 |
|    StarkBank |      SignOnly | 3,341.0 μs |  63.47 μs |  73.09 μs | 20.17 |    0.57 |
|              |               |            |           |           |       |         |
| **Secp256k1Net** | **SignAndVerify** |   **274.4 μs** |   **5.30 μs** |   **7.26 μs** |  **1.00** |    **0.00** |
|     Nbitcoin | SignAndVerify |   807.3 μs |  16.02 μs |  32.00 μs |  3.00 |    0.16 |
|    Nethereum | SignAndVerify | 3,490.7 μs |  68.01 μs | 101.79 μs | 12.74 |    0.47 |
| BouncyCastle | SignAndVerify | 3,438.9 μs |  68.07 μs | 109.93 μs | 12.52 |    0.52 |
|    StarkBank | SignAndVerify | 9,331.1 μs | 184.57 μs | 318.37 μs | 34.38 |    1.49 |
