using System.Security.Cryptography;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating signature normalization (lower-S form).
/// </summary>
public static class SignatureNormalizationExamples
{
    public static void Run()
    {
        Console.WriteLine("=== Signature Normalization Examples ===\n");

        NormalizeSignatureExample();
        IsNormalizedSignatureExample();
        WhyNormalizationMatters();
    }

    /// <summary>
    /// NormalizeSignature(signature) - Normalize signature to lower-S form
    /// </summary>
    static void NormalizeSignatureExample()
    {
        Console.WriteLine("--- NormalizeSignature ---");

        var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] messageHash = SHA256.HashData("Normalization test"u8);

        // Create a signature (the library already creates normalized signatures by default)
        byte[] signature = Secp256k1.Sign(messageHash, secretKey);

        Console.WriteLine($"Original signature: {Convert.ToHexString(signature)}");

        // Normalize the signature (converts high-S to low-S if necessary)
        byte[] normalizedSignature = Secp256k1.NormalizeSignature(signature);

        Console.WriteLine($"Normalized signature: {Convert.ToHexString(normalizedSignature)}");

        // Both signatures are valid
        bool originalValid = Secp256k1.Verify(signature, messageHash, publicKey);
        bool normalizedValid = Secp256k1.Verify(normalizedSignature, messageHash, publicKey);

        Console.WriteLine($"Original valid: {originalValid}");
        Console.WriteLine($"Normalized valid: {normalizedValid}");
        Console.WriteLine();
    }

    /// <summary>
    /// IsNormalizedSignature(signature) - Check if signature is in lower-S form
    /// </summary>
    static void IsNormalizedSignatureExample()
    {
        Console.WriteLine("--- IsNormalizedSignature ---");

        var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] messageHash = SHA256.HashData("Check normalization"u8);

        // Create a signature
        byte[] signature = Secp256k1.Sign(messageHash, secretKey);
        Console.WriteLine($"Signature: {Convert.ToHexString(signature)}");

        // The secp256k1 library produces normalized (low-S) signatures by default
        // NormalizeSignature can be used to normalize signatures from external sources

        // After normalization, the signature should be valid
        byte[] normalized = Secp256k1.NormalizeSignature(signature);
        Console.WriteLine($"Normalized: {Convert.ToHexString(normalized)}");

        // Verify the normalized signature works
        bool isValid = Secp256k1.Verify(normalized, messageHash, publicKey);
        Console.WriteLine($"Normalized signature valid: {isValid}");

        // Check if normalization changed the signature
        bool unchanged = Convert.ToHexString(signature) == Convert.ToHexString(normalized);
        Console.WriteLine($"Signature was already normalized: {unchanged}");
        Console.WriteLine();
    }

    /// <summary>
    /// Explains why signature normalization matters.
    /// </summary>
    static void WhyNormalizationMatters()
    {
        Console.WriteLine("--- Why Normalization Matters ---");

        Console.WriteLine(@"
ECDSA signatures have a malleability property: for any valid signature (r, s),
the signature (r, n - s) is also valid, where n is the curve order.

This means the same message can have two valid signatures, which can cause
problems in systems that rely on signature uniqueness (like Bitcoin).

BIP-62 and BIP-146 (Bitcoin) require 'low-S' signatures where s <= n/2.
This is also required by Ethereum for transaction signatures.

The secp256k1 library produces low-S signatures by default, but if you
receive signatures from external sources, you may need to normalize them.

Use cases for normalization:
  - Bitcoin transaction signatures (required by consensus rules)
  - Ethereum transaction signatures (required)
  - Any system that needs unique/canonical signatures
  - Preventing transaction malleability attacks
");
        Console.WriteLine();
    }
}
