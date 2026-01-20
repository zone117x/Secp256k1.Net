using System.Security.Cryptography;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating key tweaking operations for BIP-32 HD wallets.
/// </summary>
public static class KeyTweakingExamples
{
    public static void Run()
    {
        Console.WriteLine("=== Key Tweaking (BIP-32 HD Wallets) Examples ===\n");

        TweakSecretKeyAddExample();
        TweakPublicKeyAddExample();
        TweakSecretKeyMulExample();
        TweakPublicKeyMulExample();
        NegateSecretKeyExample();
        Bip32DerivationExample();
    }

    /// <summary>
    /// TweakSecretKeyAdd(secretKey, tweak) - Add a tweak to a secret key
    /// </summary>
    static void TweakSecretKeyAddExample()
    {
        Console.WriteLine("--- TweakSecretKeyAdd ---");

        byte[] secretKey = Secp256k1.CreateSecretKey();
        byte[] tweak = SHA256.HashData("child derivation tweak"u8);

        Console.WriteLine($"Original secret key: {Convert.ToHexString(secretKey)}");
        Console.WriteLine($"Tweak: {Convert.ToHexString(tweak)}");

        // Add tweak to secret key: newKey = (secretKey + tweak) mod n
        byte[] tweakedSecretKey = Secp256k1.TweakSecretKeyAdd(secretKey, tweak);

        Console.WriteLine($"Tweaked secret key: {Convert.ToHexString(tweakedSecretKey)}");

        // The tweaked key is different from the original
        Console.WriteLine($"Keys are different: {!Convert.ToHexString(secretKey).Equals(Convert.ToHexString(tweakedSecretKey))}");
        Console.WriteLine();
    }

    /// <summary>
    /// TweakPublicKeyAdd(publicKey, tweak, compressed) - Add a tweak to a public key
    /// </summary>
    static void TweakPublicKeyAddExample()
    {
        Console.WriteLine("--- TweakPublicKeyAdd ---");

        var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] tweak = SHA256.HashData("public key tweak"u8);

        Console.WriteLine($"Original public key: {Convert.ToHexString(publicKey)}");
        Console.WriteLine($"Tweak: {Convert.ToHexString(tweak)}");

        // Add tweak to public key: newPubKey = pubKey + tweak*G
        byte[] tweakedPublicKey = Secp256k1.TweakPublicKeyAdd(publicKey, tweak, compressed: true);

        Console.WriteLine($"Tweaked public key: {Convert.ToHexString(tweakedPublicKey)}");

        // Verify: tweaking the secret key and deriving public key gives same result
        byte[] tweakedSecretKey = Secp256k1.TweakSecretKeyAdd(secretKey, tweak);
        byte[] derivedPublicKey = Secp256k1.CreatePublicKey(tweakedSecretKey, compressed: true);

        Console.WriteLine($"Derived from tweaked secret: {Convert.ToHexString(derivedPublicKey)}");
        Console.WriteLine($"Public keys match: {Convert.ToHexString(tweakedPublicKey).Equals(Convert.ToHexString(derivedPublicKey))}");
        Console.WriteLine();
    }

    /// <summary>
    /// TweakSecretKeyMul(secretKey, tweak) - Multiply a secret key by a tweak
    /// </summary>
    static void TweakSecretKeyMulExample()
    {
        Console.WriteLine("--- TweakSecretKeyMul ---");

        byte[] secretKey = Secp256k1.CreateSecretKey();
        byte[] tweak = SHA256.HashData("multiplication tweak"u8);

        Console.WriteLine($"Original secret key: {Convert.ToHexString(secretKey)}");
        Console.WriteLine($"Tweak: {Convert.ToHexString(tweak)}");

        // Multiply secret key by tweak: newKey = (secretKey * tweak) mod n
        byte[] tweakedSecretKey = Secp256k1.TweakSecretKeyMul(secretKey, tweak);

        Console.WriteLine($"Tweaked secret key: {Convert.ToHexString(tweakedSecretKey)}");
        Console.WriteLine();
    }

    /// <summary>
    /// TweakPublicKeyMul(publicKey, tweak, compressed) - Multiply a public key by a tweak
    /// </summary>
    static void TweakPublicKeyMulExample()
    {
        Console.WriteLine("--- TweakPublicKeyMul ---");

        var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: true);
        byte[] tweak = SHA256.HashData("public key mul tweak"u8);

        Console.WriteLine($"Original public key: {Convert.ToHexString(publicKey)}");
        Console.WriteLine($"Tweak: {Convert.ToHexString(tweak)}");

        // Multiply public key by tweak: newPubKey = tweak * pubKey
        byte[] tweakedPublicKey = Secp256k1.TweakPublicKeyMul(publicKey, tweak, compressed: true);

        Console.WriteLine($"Tweaked public key: {Convert.ToHexString(tweakedPublicKey)}");

        // Verify: multiplying the secret key and deriving public key gives same result
        byte[] tweakedSecretKey = Secp256k1.TweakSecretKeyMul(secretKey, tweak);
        byte[] derivedPublicKey = Secp256k1.CreatePublicKey(tweakedSecretKey, compressed: true);

        Console.WriteLine($"Derived from tweaked secret: {Convert.ToHexString(derivedPublicKey)}");
        Console.WriteLine($"Public keys match: {Convert.ToHexString(tweakedPublicKey).Equals(Convert.ToHexString(derivedPublicKey))}");
        Console.WriteLine();
    }

    /// <summary>
    /// NegateSecretKey(secretKey) - Negate a secret key
    /// </summary>
    static void NegateSecretKeyExample()
    {
        Console.WriteLine("--- NegateSecretKey ---");

        byte[] secretKey = Secp256k1.CreateSecretKey();
        byte[] publicKey = Secp256k1.CreatePublicKey(secretKey, compressed: true);

        Console.WriteLine($"Original secret key: {Convert.ToHexString(secretKey)}");
        Console.WriteLine($"Original public key: {Convert.ToHexString(publicKey)}");

        // Negate the secret key: newKey = -secretKey mod n
        byte[] negatedSecretKey = Secp256k1.NegateSecretKey(secretKey);
        byte[] negatedPublicKey = Secp256k1.CreatePublicKey(negatedSecretKey, compressed: true);

        Console.WriteLine($"Negated secret key: {Convert.ToHexString(negatedSecretKey)}");
        Console.WriteLine($"Negated public key: {Convert.ToHexString(negatedPublicKey)}");

        // The negated public key should equal NegatePublicKey result
        byte[] publicKeyNegated = Secp256k1.NegatePublicKey(publicKey, compressed: true);
        Console.WriteLine($"NegatePublicKey result: {Convert.ToHexString(publicKeyNegated)}");
        Console.WriteLine($"Results match: {Convert.ToHexString(negatedPublicKey).Equals(Convert.ToHexString(publicKeyNegated))}");

        // Double negation returns original
        byte[] doubleNegated = Secp256k1.NegateSecretKey(negatedSecretKey);
        Console.WriteLine($"Double negation equals original: {Convert.ToHexString(secretKey).Equals(Convert.ToHexString(doubleNegated))}");
        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates BIP-32-like child key derivation using tweaking.
    /// </summary>
    static void Bip32DerivationExample()
    {
        Console.WriteLine("--- BIP-32-like Child Key Derivation ---");

        // Master key (in real BIP-32, this comes from a seed)
        byte[] masterSecret = Secp256k1.CreateSecretKey();
        byte[] masterPublic = Secp256k1.CreatePublicKey(masterSecret, compressed: true);

        Console.WriteLine($"Master public key: {Convert.ToHexString(masterPublic)}");

        // Derive child keys using index-based tweaks (simplified version)
        for (int childIndex = 0; childIndex < 3; childIndex++)
        {
            // Create a deterministic tweak from the parent public key and index
            byte[] tweakInput = new byte[masterPublic.Length + 4];
            masterPublic.CopyTo(tweakInput, 0);
            BitConverter.GetBytes(childIndex).CopyTo(tweakInput, masterPublic.Length);
            byte[] tweak = SHA256.HashData(tweakInput);

            // Derive child keys
            byte[] childSecret = Secp256k1.TweakSecretKeyAdd(masterSecret, tweak);
            byte[] childPublic = Secp256k1.TweakPublicKeyAdd(masterPublic, tweak, compressed: true);

            // Verify the relationship
            byte[] derivedPublic = Secp256k1.CreatePublicKey(childSecret, compressed: true);
            bool matches = Convert.ToHexString(childPublic).Equals(Convert.ToHexString(derivedPublic));

            Console.WriteLine($"Child {childIndex}: {Convert.ToHexString(childPublic)[..32]}... (verified: {matches})");
        }

        Console.WriteLine();
        Console.WriteLine("Note: This is a simplified example. Real BIP-32 uses HMAC-SHA512");
        Console.WriteLine("      and has separate chain codes for proper derivation paths.");
        Console.WriteLine();
    }
}
