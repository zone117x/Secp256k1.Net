using System.Security.Cryptography;
using System.Text;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating ECDSA signing and verification.
/// </summary>
public static class EcdsaSigningExamples
{
    public static void Run()
    {
        Console.WriteLine("=== ECDSA Signing & Verification Examples ===\n");

        SignAndVerifyExample();
        SignRecoverableExample();
        RecoverPublicKeyExample();
        VerificationFailureExample();
    }

    /// <summary>
    /// Sign(messageHash, secretKey) - Create a 64-byte compact ECDSA signature
    /// Verify(signature, messageHash, publicKey) - Verify an ECDSA signature
    /// </summary>
    static void SignAndVerifyExample()
    {
        Console.WriteLine("--- Sign and Verify ---");

        // Generate a key pair
        var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);

        // Create a message and hash it (ECDSA signs the hash, not the raw message)
        string message = "Hello, secp256k1!";
        byte[] messageHash = SHA256.HashData(Encoding.UTF8.GetBytes(message));

        Console.WriteLine($"Message: {message}");
        Console.WriteLine($"Message hash: {Convert.ToHexString(messageHash)}");

        // Sign the message hash
        byte[] signature = Secp256k1.Sign(messageHash, secretKey);

        Console.WriteLine($"Signature ({signature.Length} bytes): {Convert.ToHexString(signature)}");

        // Verify the signature
        bool isValid = Secp256k1.Verify(signature, messageHash, publicKey);
        Console.WriteLine($"Signature valid: {isValid}");
        Console.WriteLine();
    }

    /// <summary>
    /// SignRecoverable(messageHash, secretKey) - Create a recoverable signature with recovery ID
    /// </summary>
    static void SignRecoverableExample()
    {
        Console.WriteLine("--- SignRecoverable ---");

        var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] messageHash = SHA256.HashData("Recoverable signature example"u8);

        // Create a recoverable signature (includes recovery ID)
        (byte[] signature, byte recoveryId) = Secp256k1.SignRecoverable(messageHash, secretKey);

        Console.WriteLine($"Signature: {Convert.ToHexString(signature)}");
        Console.WriteLine($"Recovery ID: {recoveryId} (range 0-3)");

        // The recovery ID allows reconstructing the public key from the signature
        // This is used in Ethereum for transaction signatures (v, r, s format)
        Console.WriteLine();
    }

    /// <summary>
    /// RecoverPublicKey(signature, recoveryId, messageHash, compressed) - Recover public key from signature
    /// </summary>
    static void RecoverPublicKeyExample()
    {
        Console.WriteLine("--- RecoverPublicKey ---");

        var (secretKey, originalPublicKey) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] messageHash = SHA256.HashData("Recovery test message"u8);

        // Create a recoverable signature
        (byte[] signature, byte recoveryId) = Secp256k1.SignRecoverable(messageHash, secretKey);

        // Recover the public key using only the signature, recovery ID, and message hash
        byte[] recoveredPublicKey = Secp256k1.RecoverPublicKey(signature, recoveryId, messageHash, compressed: true);

        Console.WriteLine($"Original public key:  {Convert.ToHexString(originalPublicKey)}");
        Console.WriteLine($"Recovered public key: {Convert.ToHexString(recoveredPublicKey)}");
        Console.WriteLine($"Keys match: {Convert.ToHexString(originalPublicKey).Equals(Convert.ToHexString(recoveredPublicKey))}");

        // Can also recover to uncompressed format
        byte[] recoveredUncompressed = Secp256k1.RecoverPublicKey(signature, recoveryId, messageHash, compressed: false);
        Console.WriteLine($"Recovered uncompressed ({recoveredUncompressed.Length} bytes): {Convert.ToHexString(recoveredUncompressed)}");
        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates verification failures.
    /// </summary>
    static void VerificationFailureExample()
    {
        Console.WriteLine("--- Verification Failure Cases ---");

        var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] messageHash = SHA256.HashData("Original message"u8);
        byte[] signature = Secp256k1.Sign(messageHash, secretKey);

        // Verify with correct data
        Console.WriteLine($"Correct verification: {Secp256k1.Verify(signature, messageHash, publicKey)}");

        // Wrong message hash
        byte[] wrongHash = SHA256.HashData("Different message"u8);
        Console.WriteLine($"Wrong message hash: {Secp256k1.Verify(signature, wrongHash, publicKey)}");

        // Wrong public key
        var (_, wrongPublicKey) = Secp256k1.CreateKeyPair(compressed: true);
        Console.WriteLine($"Wrong public key: {Secp256k1.Verify(signature, messageHash, wrongPublicKey)}");

        // Corrupted signature
        byte[] corruptedSig = (byte[])signature.Clone();
        corruptedSig[0] ^= 0xFF;
        Console.WriteLine($"Corrupted signature: {Secp256k1.Verify(corruptedSig, messageHash, publicKey)}");
        Console.WriteLine();
    }
}
