# Secp256k1.Net

[![NuGet](https://img.shields.io/nuget/v/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/) [![NuGet](https://img.shields.io/nuget/dt/Secp256k1.Net.svg)](https://www.nuget.org/packages/Secp256k1.Net/)


Cross platform C# wrapper for the native [secp256k1 library](https://github.com/MeadowSuite/secp256k1/blob/master/Secp256k1.Native.nuspec).

The nuget package supports win-x64, win-x86, win-arm64, macOS-x64, macOS-arm64 (Apple Silcon), linux-x64, linux-x86, and linux-arm64 out of the box. The native libraries are bundled from the [Secp256k1.Native package](https://www.nuget.org/packages/Secp256k1.Native/). This wrapper should work on any other platform that supports netstandard2.0 (.NET Core 2.0+, Mono 5.4+, etc) but requires that the [native secp256k1](https://github.com/MeadowSuite/secp256k1) library be compiled from source. 

------

### Example Usage

```csharp
// Create a secp256k1 context (ensure disposal to prevent unmanaged memory leaks).
using (var secp256k1 = new Secp256k1())
{

    // Generate a private key.
    var privateKey = new byte[32];
    var rnd = System.Security.Cryptography.RandomNumberGenerator.Create();
    do { rnd.GetBytes(privateKey); }
    while (!secp256k1.SecretKeyVerify(privateKey));


    // Create public key from private key.
    var publicKey = new byte[64];
    Debug.Assert(secp256k1.PublicKeyCreate(publicKey, privateKey));


    // Sign a message hash.
    var messageBytes = Encoding.UTF8.GetBytes("Hello world.");
    var messageHash = System.Security.Cryptography.SHA256.Create().ComputeHash(messageBytes);
    var signature = new byte[64];
    Debug.Assert(secp256k1.Sign(signature, messageHash, privateKey));


    // Verify message hash.
    Debug.Assert(secp256k1.Verify(signature, messageHash, publicKey));

}
```


See the [tests project](Secp256k1.Net.Test/Tests.cs) for more complex examples of using recoverable and serialization functions. 
