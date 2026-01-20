using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating public key operations.
/// </summary>
public static class PublicKeyOperationsExamples
{
    public static void Run()
    {
        Console.WriteLine("=== Public Key Operations Examples ===\n");

        CompressPublicKeyExample();
        DecompressPublicKeyExample();
        NegatePublicKeyExample();
        CombinePublicKeysExample();
    }

    /// <summary>
    /// CompressPublicKey(publicKey) - Convert a public key to 33-byte compressed format
    /// </summary>
    static void CompressPublicKeyExample()
    {
        Console.WriteLine("--- CompressPublicKey ---");

        // Start with an uncompressed public key (65 bytes)
        var (secretKey, _) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] uncompressedKey = Secp256k1.CreatePublicKey(secretKey, compressed: false);

        Console.WriteLine($"Uncompressed key ({uncompressedKey.Length} bytes): {Convert.ToHexString(uncompressedKey)}");

        // Compress it to 33 bytes
        byte[] compressedKey = Secp256k1.CompressPublicKey(uncompressedKey);

        Console.WriteLine($"Compressed key ({compressedKey.Length} bytes): {Convert.ToHexString(compressedKey)}");

        // Compressing an already-compressed key returns it unchanged
        byte[] recompressed = Secp256k1.CompressPublicKey(compressedKey);
        Console.WriteLine($"Re-compressed (same): {Convert.ToHexString(compressedKey).Equals(Convert.ToHexString(recompressed))}");
        Console.WriteLine();
    }

    /// <summary>
    /// DecompressPublicKey(publicKey) - Convert a public key to 65-byte uncompressed format
    /// </summary>
    static void DecompressPublicKeyExample()
    {
        Console.WriteLine("--- DecompressPublicKey ---");

        // Start with a compressed public key (33 bytes)
        var (_, compressedKey) = Secp256k1.CreateKeyPair(compressed: true);

        Console.WriteLine($"Compressed key ({compressedKey.Length} bytes): {Convert.ToHexString(compressedKey)}");

        // Decompress it to 65 bytes
        byte[] uncompressedKey = Secp256k1.DecompressPublicKey(compressedKey);

        Console.WriteLine($"Uncompressed key ({uncompressedKey.Length} bytes): {Convert.ToHexString(uncompressedKey)}");
        Console.WriteLine($"Prefix byte: 0x{uncompressedKey[0]:X2} (should be 0x04 for uncompressed)");
        Console.WriteLine();
    }

    /// <summary>
    /// NegatePublicKey(publicKey, compressed) - Negate a public key
    /// </summary>
    static void NegatePublicKeyExample()
    {
        Console.WriteLine("--- NegatePublicKey ---");

        var (_, publicKey) = Secp256k1.CreateKeyPair(compressed: true);

        Console.WriteLine($"Original public key: {Convert.ToHexString(publicKey)}");

        // Negate the public key (returns -P where P is the original point)
        byte[] negatedKey = Secp256k1.NegatePublicKey(publicKey, compressed: true);

        Console.WriteLine($"Negated public key:  {Convert.ToHexString(negatedKey)}");

        // Negating twice returns the original key
        byte[] doubleNegated = Secp256k1.NegatePublicKey(negatedKey, compressed: true);
        Console.WriteLine($"Double negated equals original: {Convert.ToHexString(publicKey).Equals(Convert.ToHexString(doubleNegated))}");

        // The x-coordinate is the same, only the y-coordinate changes (reflected in the prefix)
        Console.WriteLine($"X-coordinates equal: {Convert.ToHexString(publicKey[1..]).Equals(Convert.ToHexString(negatedKey[1..]))}");
        Console.WriteLine();
    }

    /// <summary>
    /// CombinePublicKeys(publicKeys, compressed) - Add multiple public keys together
    /// </summary>
    static void CombinePublicKeysExample()
    {
        Console.WriteLine("--- CombinePublicKeys ---");

        // Generate three key pairs
        var (secret1, pubKey1) = Secp256k1.CreateKeyPair(compressed: true);
        var (secret2, pubKey2) = Secp256k1.CreateKeyPair(compressed: true);
        var (secret3, pubKey3) = Secp256k1.CreateKeyPair(compressed: true);

        Console.WriteLine($"Public key 1: {Convert.ToHexString(pubKey1)}");
        Console.WriteLine($"Public key 2: {Convert.ToHexString(pubKey2)}");
        Console.WriteLine($"Public key 3: {Convert.ToHexString(pubKey3)}");

        // Combine (add) the public keys: P1 + P2 + P3
        byte[][] keysToAdd = [pubKey1, pubKey2, pubKey3];
        byte[] combinedKey = Secp256k1.CombinePublicKeys(keysToAdd, compressed: true);

        Console.WriteLine($"Combined key (P1+P2+P3): {Convert.ToHexString(combinedKey)}");

        // This is useful for multi-sig schemes where the combined public key
        // corresponds to the sum of individual secret keys
        Console.WriteLine();

        // Demonstrate with two keys
        byte[] twoKeyCombined = Secp256k1.CombinePublicKeys([pubKey1, pubKey2], compressed: true);
        Console.WriteLine($"Combined key (P1+P2): {Convert.ToHexString(twoKeyCombined)}");

        // Adding a key and its negation results in the point at infinity (which will throw)
        byte[] negatedPubKey1 = Secp256k1.NegatePublicKey(pubKey1, compressed: true);
        try
        {
            Secp256k1.CombinePublicKeys([pubKey1, negatedPubKey1], compressed: true);
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Adding P + (-P) throws: {ex.Message}");
        }
        Console.WriteLine();
    }
}
