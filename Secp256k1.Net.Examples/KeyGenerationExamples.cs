using System.Security.Cryptography;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating key generation and validation functions.
/// </summary>
public static class KeyGenerationExamples
{
    public static void Run()
    {
        Console.WriteLine("=== Key Generation & Validation Examples ===\n");

        CreateSecretKeyExample();
        CreatePublicKeyExample();
        CreateXOnlyPublicKeyExample();
        CreateKeyPairExample();
        IsValidSecretKeyExample();
        IsValidPublicKeyExample();
    }

    /// <summary>
    /// CreateSecretKey() - Generate a cryptographically secure random secret key
    /// </summary>
    static void CreateSecretKeyExample()
    {
        Console.WriteLine("--- CreateSecretKey ---");

        // Generate a new random 32-byte secret key
        byte[] secretKey = Secp256k1.CreateSecretKey();

        Console.WriteLine($"Secret key length: {secretKey.Length} bytes");
        Console.WriteLine($"Secret key (hex): {Convert.ToHexString(secretKey)}");
        Console.WriteLine();
    }

    /// <summary>
    /// CreatePublicKey(secretKey, compressed) - Derive a serialized public key from a secret key
    /// </summary>
    static void CreatePublicKeyExample()
    {
        Console.WriteLine("--- CreatePublicKey ---");

        byte[] secretKey = Secp256k1.CreateSecretKey();

        // Create a compressed public key (33 bytes, starts with 02 or 03)
        byte[] compressedPubKey = Secp256k1.CreatePublicKey(secretKey, compressed: true);
        Console.WriteLine($"Compressed public key length: {compressedPubKey.Length} bytes");
        Console.WriteLine($"Compressed public key: {Convert.ToHexString(compressedPubKey)}");

        // Create an uncompressed public key (65 bytes, starts with 04)
        byte[] uncompressedPubKey = Secp256k1.CreatePublicKey(secretKey, compressed: false);
        Console.WriteLine($"Uncompressed public key length: {uncompressedPubKey.Length} bytes");
        Console.WriteLine($"Uncompressed public key: {Convert.ToHexString(uncompressedPubKey)}");
        Console.WriteLine();
    }

    /// <summary>
    /// CreateXOnlyPublicKey(secretKey) - Derive an x-only public key and parity for BIP-340
    /// </summary>
    static void CreateXOnlyPublicKeyExample()
    {
        Console.WriteLine("--- CreateXOnlyPublicKey ---");

        byte[] secretKey = Secp256k1.CreateSecretKey();

        // Create an x-only public key (32 bytes) with parity byte for BIP-340 Schnorr signatures
        (byte[] xOnlyPubKey, byte parity) = Secp256k1.CreateXOnlyPublicKey(secretKey);

        Console.WriteLine($"X-only public key length: {xOnlyPubKey.Length} bytes");
        Console.WriteLine($"X-only public key: {Convert.ToHexString(xOnlyPubKey)}");
        Console.WriteLine($"Parity: {parity} (0 = even, 1 = odd)");
        Console.WriteLine();
    }

    /// <summary>
    /// CreateKeyPair(compressed) - Generate a new secret key and public key pair
    /// </summary>
    static void CreateKeyPairExample()
    {
        Console.WriteLine("--- CreateKeyPair ---");

        // Generate a complete key pair in one call (compressed public key)
        (byte[] secretKey, byte[] publicKey) = Secp256k1.CreateKeyPair(compressed: true);

        Console.WriteLine($"Secret key: {Convert.ToHexString(secretKey)}");
        Console.WriteLine($"Public key: {Convert.ToHexString(publicKey)}");

        // Generate with uncompressed public key
        var (secretKey2, uncompressedPubKey) = Secp256k1.CreateKeyPair(compressed: false);
        Console.WriteLine($"Uncompressed public key length: {uncompressedPubKey.Length} bytes");
        Console.WriteLine();
    }

    /// <summary>
    /// IsValidSecretKey(secretKey) - Validate a secret key
    /// </summary>
    static void IsValidSecretKeyExample()
    {
        Console.WriteLine("--- IsValidSecretKey ---");

        // Valid secret key
        byte[] validKey = Secp256k1.CreateSecretKey();
        Console.WriteLine($"Valid random key: {Secp256k1.IsValidSecretKey(validKey)}");

        // Invalid: all zeros (not allowed)
        byte[] zeroKey = new byte[32];
        Console.WriteLine($"All zeros key: {Secp256k1.IsValidSecretKey(zeroKey)}");

        // Invalid: greater than or equal to the curve order
        byte[] tooLargeKey = new byte[32];
        Array.Fill(tooLargeKey, (byte)0xFF);
        Console.WriteLine($"All 0xFF key (too large): {Secp256k1.IsValidSecretKey(tooLargeKey)}");

        // Invalid: wrong length
        byte[] wrongLength = new byte[16];
        Console.WriteLine($"Wrong length (16 bytes): {Secp256k1.IsValidSecretKey(wrongLength)}");
        Console.WriteLine();
    }

    /// <summary>
    /// IsValidPublicKey(publicKey) - Validate a serialized public key
    /// </summary>
    static void IsValidPublicKeyExample()
    {
        Console.WriteLine("--- IsValidPublicKey ---");

        var (_, publicKey) = Secp256k1.CreateKeyPair(compressed: true);

        // Valid compressed public key
        Console.WriteLine($"Valid compressed key: {Secp256k1.IsValidPublicKey(publicKey)}");

        // Valid uncompressed public key
        byte[] uncompressed = Secp256k1.DecompressPublicKey(publicKey);
        Console.WriteLine($"Valid uncompressed key: {Secp256k1.IsValidPublicKey(uncompressed)}");

        // Invalid: corrupted key (wrong prefix)
        byte[] corrupted = (byte[])publicKey.Clone();
        corrupted[0] = 0x05; // Invalid prefix
        Console.WriteLine($"Corrupted key (bad prefix): {Secp256k1.IsValidPublicKey(corrupted)}");

        // Invalid: wrong length
        byte[] wrongLength = new byte[20];
        Console.WriteLine($"Wrong length (20 bytes): {Secp256k1.IsValidPublicKey(wrongLength)}");
        Console.WriteLine();
    }
}
