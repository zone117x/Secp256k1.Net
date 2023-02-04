# Secp256k1.Net

[![NuGet](https://img.shields.io/nuget/v/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/) [![NuGet](https://img.shields.io/nuget/dt/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/)


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
Assert.True(secp256k1.PublicKeyCreate(publicKey, privateKey), "Public key creation failed");

// Serialize the public key to compressed format
var serializedCompressedPublicKey = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
Assert.True(secp256k1.PublicKeySerialize(serializedCompressedPublicKey, publicKey, Flags.SECP256K1_EC_COMPRESSED));

// Serialize the public key to uncompressed format
var serializedUncompressedPublicKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
Assert.True(secp256k1.PublicKeySerialize(serializedUncompressedPublicKey, publicKey, Flags.SECP256K1_EC_UNCOMPRESSED));
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
