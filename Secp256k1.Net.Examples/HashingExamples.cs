using System.Security.Cryptography;
using System.Text;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating BIP-340 tagged hashing.
/// </summary>
public static class HashingExamples
{
    public static void Run()
    {
        Console.WriteLine("=== Hashing Examples ===\n");

        TaggedHashExample();
        TaggedHashUseCases();
        TaggedHashVsPlainHash();
    }

    /// <summary>
    /// TaggedHash(tag, message) - Compute a BIP-340 tagged hash
    /// </summary>
    static void TaggedHashExample()
    {
        Console.WriteLine("--- TaggedHash ---");

        // BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || message)
        byte[] tag = "BIP0340/challenge"u8.ToArray();
        byte[] message = Encoding.UTF8.GetBytes("Hello, tagged hash!");

        byte[] taggedHash = Secp256k1.TaggedHash(tag, message);

        Console.WriteLine($"Tag: \"BIP0340/challenge\"");
        Console.WriteLine($"Message: \"Hello, tagged hash!\"");
        Console.WriteLine($"Tagged hash ({taggedHash.Length} bytes): {Convert.ToHexString(taggedHash)}");
        Console.WriteLine();
    }

    /// <summary>
    /// Shows common use cases for tagged hashes.
    /// </summary>
    static void TaggedHashUseCases()
    {
        Console.WriteLine("--- Tagged Hash Use Cases ---");

        byte[] message = Encoding.UTF8.GetBytes("example message");

        // BIP-340 Schnorr signature challenge
        byte[] schnorrChallenge = Secp256k1.TaggedHash("BIP0340/challenge"u8, message);
        Console.WriteLine($"BIP0340/challenge: {Convert.ToHexString(schnorrChallenge)}");

        // BIP-340 auxiliary randomness
        byte[] auxRand = Secp256k1.TaggedHash("BIP0340/aux"u8, message);
        Console.WriteLine($"BIP0340/aux: {Convert.ToHexString(auxRand)}");

        // BIP-340 nonce derivation
        byte[] nonce = Secp256k1.TaggedHash("BIP0340/nonce"u8, message);
        Console.WriteLine($"BIP0340/nonce: {Convert.ToHexString(nonce)}");

        // BIP-341 Taproot leaf hash
        byte[] tapLeaf = Secp256k1.TaggedHash("TapLeaf"u8, message);
        Console.WriteLine($"TapLeaf: {Convert.ToHexString(tapLeaf)}");

        // BIP-341 Taproot branch hash
        byte[] tapBranch = Secp256k1.TaggedHash("TapBranch"u8, message);
        Console.WriteLine($"TapBranch: {Convert.ToHexString(tapBranch)}");

        // BIP-341 Taproot tweak
        byte[] tapTweak = Secp256k1.TaggedHash("TapTweak"u8, message);
        Console.WriteLine($"TapTweak: {Convert.ToHexString(tapTweak)}");

        // Custom application tag
        byte[] customTag = Secp256k1.TaggedHash("MyApp/v1/signature"u8, message);
        Console.WriteLine($"MyApp/v1/signature: {Convert.ToHexString(customTag)}");

        Console.WriteLine();
    }

    /// <summary>
    /// Compares tagged hash with plain SHA256.
    /// </summary>
    static void TaggedHashVsPlainHash()
    {
        Console.WriteLine("--- Tagged Hash vs Plain SHA256 ---");

        byte[] message = Encoding.UTF8.GetBytes("test message");

        // Plain SHA256
        byte[] plainHash = SHA256.HashData(message);

        // Tagged hash with same message
        byte[] taggedHash = Secp256k1.TaggedHash("test"u8, message);

        Console.WriteLine($"Plain SHA256:   {Convert.ToHexString(plainHash)}");
        Console.WriteLine($"Tagged hash:    {Convert.ToHexString(taggedHash)}");
        Console.WriteLine($"Hashes differ:  {!Convert.ToHexString(plainHash).Equals(Convert.ToHexString(taggedHash))}");

        Console.WriteLine();
        Console.WriteLine("Tagged hash formula: SHA256(SHA256(tag) || SHA256(tag) || message)");
        Console.WriteLine();

        // Manually compute the tagged hash to verify
        byte[] tagHash = SHA256.HashData(Encoding.UTF8.GetBytes("test"));
        byte[] prefixedMessage = new byte[tagHash.Length * 2 + message.Length];
        tagHash.CopyTo(prefixedMessage, 0);
        tagHash.CopyTo(prefixedMessage, tagHash.Length);
        message.CopyTo(prefixedMessage, tagHash.Length * 2);
        byte[] manualTaggedHash = SHA256.HashData(prefixedMessage);

        Console.WriteLine($"Manual computation: {Convert.ToHexString(manualTaggedHash)}");
        Console.WriteLine($"Matches library:    {Convert.ToHexString(taggedHash).Equals(Convert.ToHexString(manualTaggedHash))}");

        Console.WriteLine();
        Console.WriteLine("Why tagged hashes?");
        Console.WriteLine("  - Domain separation: prevents hash collisions between different protocols");
        Console.WriteLine("  - Security: ensures hashes for one purpose can't be reused for another");
        Console.WriteLine("  - Standard: defined in BIP-340 for Bitcoin Schnorr signatures");
        Console.WriteLine();
    }
}
