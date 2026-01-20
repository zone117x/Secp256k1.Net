using System.Security.Cryptography;
using System.Text;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating Schnorr signatures (BIP-340).
/// </summary>
public static class SchnorrSignatureExamples
{
    public static void Run()
    {
        Console.WriteLine("=== Schnorr Signatures (BIP-340) Examples ===\n");

        SignSchnorrExample();
        VerifySchnorrExample();
        SchnorrWithAuxRandExample();
        SchnorrVsEcdsaComparison();
    }

    /// <summary>
    /// SignSchnorr(messageHash, secretKey, auxRand) - Create a Schnorr signature
    /// </summary>
    static void SignSchnorrExample()
    {
        Console.WriteLine("--- SignSchnorr ---");

        // Generate a key pair
        var (secretKey, _) = Secp256k1.CreateKeyPair(compressed: true);

        // Get the x-only public key for Schnorr
        (byte[] xOnlyPubKey, byte parity) = Secp256k1.CreateXOnlyPublicKey(secretKey);

        // Create a 32-byte message hash (BIP-340 requires exactly 32 bytes)
        byte[] messageHash = SHA256.HashData("Schnorr signature test"u8);

        // Generate auxiliary randomness (optional but recommended for side-channel resistance)
        byte[] auxRand = RandomNumberGenerator.GetBytes(32);

        // Create the Schnorr signature
        byte[] signature = Secp256k1.SignSchnorr(messageHash, secretKey, auxRand);

        Console.WriteLine($"Secret key: {Convert.ToHexString(secretKey)}");
        Console.WriteLine($"X-only public key: {Convert.ToHexString(xOnlyPubKey)}");
        Console.WriteLine($"Message hash: {Convert.ToHexString(messageHash)}");
        Console.WriteLine($"Schnorr signature ({signature.Length} bytes): {Convert.ToHexString(signature)}");
        Console.WriteLine();
    }

    /// <summary>
    /// VerifySchnorr(signature, message, publicKey) - Verify a Schnorr signature
    /// </summary>
    static void VerifySchnorrExample()
    {
        Console.WriteLine("--- VerifySchnorr ---");

        var (secretKey, compressedPubKey) = Secp256k1.CreateKeyPair(compressed: true);
        (byte[] xOnlyPubKey, _) = Secp256k1.CreateXOnlyPublicKey(secretKey);

        byte[] messageHash = SHA256.HashData("Verify Schnorr test"u8);
        byte[] auxRand = RandomNumberGenerator.GetBytes(32);
        byte[] signature = Secp256k1.SignSchnorr(messageHash, secretKey, auxRand);

        // Verify with x-only public key (32 bytes)
        bool validWithXOnly = Secp256k1.VerifySchnorr(signature, messageHash, xOnlyPubKey);
        Console.WriteLine($"Valid with x-only pubkey (32 bytes): {validWithXOnly}");

        // Verify with compressed public key (33 bytes) - also works!
        bool validWithCompressed = Secp256k1.VerifySchnorr(signature, messageHash, compressedPubKey);
        Console.WriteLine($"Valid with compressed pubkey (33 bytes): {validWithCompressed}");

        // Verify with uncompressed public key (65 bytes) - also works!
        byte[] uncompressedPubKey = Secp256k1.DecompressPublicKey(compressedPubKey);
        bool validWithUncompressed = Secp256k1.VerifySchnorr(signature, messageHash, uncompressedPubKey);
        Console.WriteLine($"Valid with uncompressed pubkey (65 bytes): {validWithUncompressed}");

        // Verification failure with wrong message
        byte[] wrongHash = SHA256.HashData("Wrong message"u8);
        bool invalidWrongMessage = Secp256k1.VerifySchnorr(signature, wrongHash, xOnlyPubKey);
        Console.WriteLine($"Invalid (wrong message): {invalidWrongMessage}");
        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates the role of auxiliary randomness in Schnorr signing.
    /// </summary>
    static void SchnorrWithAuxRandExample()
    {
        Console.WriteLine("--- Auxiliary Randomness in Schnorr ---");

        var (secretKey, _) = Secp256k1.CreateKeyPair(compressed: true);
        (byte[] xOnlyPubKey, _) = Secp256k1.CreateXOnlyPublicKey(secretKey);
        byte[] messageHash = SHA256.HashData("Aux rand test"u8);

        // Sign with different auxiliary randomness produces different signatures
        byte[] auxRand1 = RandomNumberGenerator.GetBytes(32);
        byte[] auxRand2 = RandomNumberGenerator.GetBytes(32);

        byte[] sig1 = Secp256k1.SignSchnorr(messageHash, secretKey, auxRand1);
        byte[] sig2 = Secp256k1.SignSchnorr(messageHash, secretKey, auxRand2);

        Console.WriteLine($"Signature 1: {Convert.ToHexString(sig1)}");
        Console.WriteLine($"Signature 2: {Convert.ToHexString(sig2)}");
        Console.WriteLine($"Signatures are different: {!Convert.ToHexString(sig1).Equals(Convert.ToHexString(sig2))}");

        // Both signatures are valid
        Console.WriteLine($"Signature 1 valid: {Secp256k1.VerifySchnorr(sig1, messageHash, xOnlyPubKey)}");
        Console.WriteLine($"Signature 2 valid: {Secp256k1.VerifySchnorr(sig2, messageHash, xOnlyPubKey)}");

        Console.WriteLine();
        Console.WriteLine("Note: Auxiliary randomness provides protection against side-channel attacks.");
        Console.WriteLine("      Even without it, BIP-340 uses deterministic nonce generation,");
        Console.WriteLine("      so the signature scheme is still secure.");
        Console.WriteLine();
    }

    /// <summary>
    /// Compares Schnorr and ECDSA signatures.
    /// </summary>
    static void SchnorrVsEcdsaComparison()
    {
        Console.WriteLine("--- Schnorr vs ECDSA Comparison ---");

        var (secretKey, compressedPubKey) = Secp256k1.CreateKeyPair(compressed: true);
        (byte[] xOnlyPubKey, _) = Secp256k1.CreateXOnlyPublicKey(secretKey);
        byte[] messageHash = SHA256.HashData("Comparison test"u8);

        // ECDSA signature
        byte[] ecdsaSig = Secp256k1.Sign(messageHash, secretKey);

        // Schnorr signature
        byte[] auxRand = RandomNumberGenerator.GetBytes(32);
        byte[] schnorrSig = Secp256k1.SignSchnorr(messageHash, secretKey, auxRand);

        Console.WriteLine($"ECDSA signature ({ecdsaSig.Length} bytes):   {Convert.ToHexString(ecdsaSig)}");
        Console.WriteLine($"Schnorr signature ({schnorrSig.Length} bytes): {Convert.ToHexString(schnorrSig)}");

        Console.WriteLine();
        Console.WriteLine("Key differences:");
        Console.WriteLine("  - Both signatures are 64 bytes");
        Console.WriteLine("  - Schnorr uses x-only public keys (32 bytes) vs compressed (33 bytes)");
        Console.WriteLine("  - Schnorr signatures are linear (can be aggregated)");
        Console.WriteLine("  - Schnorr has provable security under standard assumptions");
        Console.WriteLine("  - Bitcoin uses Schnorr for Taproot (BIP-340/341/342)");
        Console.WriteLine();
    }
}
