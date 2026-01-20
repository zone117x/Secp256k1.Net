using System.Security.Cryptography;
using System.Text;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating ECDH (Elliptic Curve Diffie-Hellman) key agreement.
/// </summary>
public static class EcdhExamples
{
    public static void Run()
    {
        Console.WriteLine("=== ECDH Key Agreement Examples ===\n");

        ComputeSharedSecretExample();
        TwoPartyKeyExchange();
        EncryptionWithSharedSecret();
    }

    /// <summary>
    /// ComputeSharedSecret(publicKey, secretKey) - Compute ECDH shared secret
    /// </summary>
    static void ComputeSharedSecretExample()
    {
        Console.WriteLine("--- ComputeSharedSecret ---");

        // Alice generates her key pair
        var (aliceSecret, alicePublic) = Secp256k1.CreateKeyPair(compressed: true);

        // Bob generates his key pair
        var (bobSecret, bobPublic) = Secp256k1.CreateKeyPair(compressed: true);

        // Alice computes shared secret using Bob's public key and her secret key
        byte[] aliceSharedSecret = Secp256k1.ComputeSharedSecret(bobPublic, aliceSecret);

        // Bob computes shared secret using Alice's public key and his secret key
        byte[] bobSharedSecret = Secp256k1.ComputeSharedSecret(alicePublic, bobSecret);

        Console.WriteLine($"Alice's public key: {Convert.ToHexString(alicePublic)}");
        Console.WriteLine($"Bob's public key:   {Convert.ToHexString(bobPublic)}");
        Console.WriteLine($"Alice's shared secret: {Convert.ToHexString(aliceSharedSecret)}");
        Console.WriteLine($"Bob's shared secret:   {Convert.ToHexString(bobSharedSecret)}");
        Console.WriteLine($"Shared secrets match: {Convert.ToHexString(aliceSharedSecret).Equals(Convert.ToHexString(bobSharedSecret))}");
        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates a complete key exchange protocol.
    /// </summary>
    static void TwoPartyKeyExchange()
    {
        Console.WriteLine("--- Two-Party Key Exchange Protocol ---");

        Console.WriteLine("1. Alice and Bob each generate their own key pairs");
        var (alicePrivate, alicePublic) = Secp256k1.CreateKeyPair(compressed: true);
        var (bobPrivate, bobPublic) = Secp256k1.CreateKeyPair(compressed: true);

        Console.WriteLine("2. They exchange public keys over an insecure channel");
        Console.WriteLine($"   Alice sends: {Convert.ToHexString(alicePublic)}");
        Console.WriteLine($"   Bob sends:   {Convert.ToHexString(bobPublic)}");

        Console.WriteLine("3. Each party computes the shared secret locally");
        byte[] aliceComputed = Secp256k1.ComputeSharedSecret(bobPublic, alicePrivate);
        byte[] bobComputed = Secp256k1.ComputeSharedSecret(alicePublic, bobPrivate);

        Console.WriteLine("4. Both arrive at the same 32-byte shared secret");
        Console.WriteLine($"   Shared secret: {Convert.ToHexString(aliceComputed)}");

        Console.WriteLine("5. This shared secret can be used to derive encryption keys");
        // In practice, you'd use a KDF like HKDF to derive actual encryption keys
        byte[] encryptionKey = SHA256.HashData(aliceComputed);
        Console.WriteLine($"   Derived key (SHA256): {Convert.ToHexString(encryptionKey)}");
        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates using ECDH for message encryption.
    /// </summary>
    static void EncryptionWithSharedSecret()
    {
        Console.WriteLine("--- Encryption with ECDH Shared Secret ---");

        // Setup: Alice and Bob have exchanged public keys
        var (alicePrivate, alicePublic) = Secp256k1.CreateKeyPair(compressed: true);
        var (bobPrivate, bobPublic) = Secp256k1.CreateKeyPair(compressed: true);

        // Compute shared secret
        byte[] sharedSecret = Secp256k1.ComputeSharedSecret(bobPublic, alicePrivate);

        // Derive an encryption key from the shared secret
        byte[] encryptionKey = SHA256.HashData(sharedSecret);

        // Example message
        string message = "Hello Bob, this is a secret message!";
        byte[] plaintext = Encoding.UTF8.GetBytes(message);

        Console.WriteLine($"Original message: {message}");

        // Simple XOR encryption (for demonstration - use AES in production)
        byte[] ciphertext = new byte[plaintext.Length];
        for (int i = 0; i < plaintext.Length; i++)
        {
            ciphertext[i] = (byte)(plaintext[i] ^ encryptionKey[i % encryptionKey.Length]);
        }
        Console.WriteLine($"Encrypted (hex): {Convert.ToHexString(ciphertext)}");

        // Bob decrypts using the same shared secret
        byte[] bobSharedSecret = Secp256k1.ComputeSharedSecret(alicePublic, bobPrivate);
        byte[] bobKey = SHA256.HashData(bobSharedSecret);

        byte[] decrypted = new byte[ciphertext.Length];
        for (int i = 0; i < ciphertext.Length; i++)
        {
            decrypted[i] = (byte)(ciphertext[i] ^ bobKey[i % bobKey.Length]);
        }
        string decryptedMessage = Encoding.UTF8.GetString(decrypted);
        Console.WriteLine($"Decrypted message: {decryptedMessage}");

        Console.WriteLine();
        Console.WriteLine("Note: This example uses simple XOR for demonstration.");
        Console.WriteLine("      In production, use AES-GCM or ChaCha20-Poly1305 with the derived key.");
        Console.WriteLine();
    }
}
