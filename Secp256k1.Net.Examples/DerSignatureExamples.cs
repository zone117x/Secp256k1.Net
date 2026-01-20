using System.Security.Cryptography;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating DER signature format operations.
/// </summary>
public static class DerSignatureExamples
{
    public static void Run()
    {
        Console.WriteLine("=== DER Signature Format Examples ===\n");

        SignatureToDerExample();
        SignatureFromDerExample();
        VerifyDerExample();
        DerFormatExplanation();
    }

    /// <summary>
    /// SignatureToDer(compactSignature) - Convert compact signature to DER format
    /// </summary>
    static void SignatureToDerExample()
    {
        Console.WriteLine("--- SignatureToDer ---");

        var (secretKey, _) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] messageHash = SHA256.HashData("DER conversion test"u8);

        // Create a compact signature (64 bytes: 32 bytes r + 32 bytes s)
        byte[] compactSignature = Secp256k1.Sign(messageHash, secretKey);

        Console.WriteLine($"Compact signature ({compactSignature.Length} bytes): {Convert.ToHexString(compactSignature)}");

        // Convert to DER format (variable length, typically 70-72 bytes)
        byte[] derSignature = Secp256k1.SignatureToDer(compactSignature);

        Console.WriteLine($"DER signature ({derSignature.Length} bytes): {Convert.ToHexString(derSignature)}");
        Console.WriteLine();
    }

    /// <summary>
    /// SignatureFromDer(derSignature) - Convert DER signature to compact format
    /// </summary>
    static void SignatureFromDerExample()
    {
        Console.WriteLine("--- SignatureFromDer ---");

        var (secretKey, _) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] messageHash = SHA256.HashData("DER roundtrip test"u8);

        // Create and convert to DER
        byte[] originalCompact = Secp256k1.Sign(messageHash, secretKey);
        byte[] derSignature = Secp256k1.SignatureToDer(originalCompact);

        // Convert back to compact format
        byte[] recoveredCompact = Secp256k1.SignatureFromDer(derSignature);

        Console.WriteLine($"Original compact:  {Convert.ToHexString(originalCompact)}");
        Console.WriteLine($"DER intermediate:  {Convert.ToHexString(derSignature)}");
        Console.WriteLine($"Recovered compact: {Convert.ToHexString(recoveredCompact)}");
        Console.WriteLine($"Roundtrip successful: {Convert.ToHexString(originalCompact).Equals(Convert.ToHexString(recoveredCompact))}");
        Console.WriteLine();
    }

    /// <summary>
    /// VerifyDer(derSignature, messageHash, publicKey) - Verify a DER-encoded signature
    /// </summary>
    static void VerifyDerExample()
    {
        Console.WriteLine("--- VerifyDer ---");

        var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] messageHash = SHA256.HashData("DER verification test"u8);

        // Create a signature and convert to DER
        byte[] compactSignature = Secp256k1.Sign(messageHash, secretKey);
        byte[] derSignature = Secp256k1.SignatureToDer(compactSignature);

        // Verify the DER signature directly (no need to convert back to compact)
        bool isValid = Secp256k1.VerifyDer(derSignature, messageHash, publicKey);

        Console.WriteLine($"DER signature: {Convert.ToHexString(derSignature)}");
        Console.WriteLine($"DER signature valid: {isValid}");

        // Also verify that the compact signature works
        bool compactValid = Secp256k1.Verify(compactSignature, messageHash, publicKey);
        Console.WriteLine($"Compact signature valid: {compactValid}");
        Console.WriteLine();
    }

    /// <summary>
    /// Explains the DER format structure.
    /// </summary>
    static void DerFormatExplanation()
    {
        Console.WriteLine("--- DER Format Explanation ---");

        var (secretKey, _) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] messageHash = SHA256.HashData("DER format example"u8);
        byte[] derSignature = Secp256k1.SignatureToDer(Secp256k1.Sign(messageHash, secretKey));

        Console.WriteLine("DER signature structure:");
        Console.WriteLine($"  Byte 0: 0x{derSignature[0]:X2} (SEQUENCE tag)");
        Console.WriteLine($"  Byte 1: 0x{derSignature[1]:X2} (Total length of r + s: {derSignature[1]} bytes)");
        Console.WriteLine($"  Byte 2: 0x{derSignature[2]:X2} (INTEGER tag for r)");
        Console.WriteLine($"  Byte 3: 0x{derSignature[3]:X2} (Length of r: {derSignature[3]} bytes)");

        int sOffset = 4 + derSignature[3];
        Console.WriteLine($"  Byte {sOffset}: 0x{derSignature[sOffset]:X2} (INTEGER tag for s)");
        Console.WriteLine($"  Byte {sOffset + 1}: 0x{derSignature[sOffset + 1]:X2} (Length of s: {derSignature[sOffset + 1]} bytes)");

        Console.WriteLine();
        Console.WriteLine("Note: DER encoding adds a 0x00 prefix to integers with high bit set");
        Console.WriteLine("      to prevent them from being interpreted as negative numbers.");
        Console.WriteLine("      This makes DER signatures variable-length (typically 70-72 bytes).");
        Console.WriteLine();
    }
}
