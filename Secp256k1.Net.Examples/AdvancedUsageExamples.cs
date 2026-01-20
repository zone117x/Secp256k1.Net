using System.Security.Cryptography;
using System.Text;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Advanced examples demonstrating low-level Secp256k1 instance methods.
/// These methods provide more control over memory allocation and internal data formats.
/// </summary>
public static class AdvancedUsageExamples
{
    public static void Run()
    {
        Console.WriteLine("=== Advanced Usage Examples (Instance Methods) ===\n");

        InstanceBasics();
        WorkingWithInternalFormats();
        CustomEcdhHashFunction();
        CustomNonceFunction();
        Rfc6979NonceFunction();
        PublicKeyComparison();
        PublicKeySorting();
        KeypairOperations();
        SchnorrWithKeypair();
        XonlyPubkeyTweakingExample();
        ElligatorSwiftExample();
        ErrorCallbackExample();
    }

    /// <summary>
    /// Basic instance creation and disposal.
    /// </summary>
    static void InstanceBasics()
    {
        Console.WriteLine("--- Instance Basics ---");

        // Create a Secp256k1 instance (manages native context)
        using var secp256k1 = new Secp256k1();

        Console.WriteLine($"Native library path: {Secp256k1.LibPath}");

        // Run self-tests (optional, useful for verifying library integrity)
        secp256k1.Selftest();
        Console.WriteLine("Self-test passed");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates working with internal (unserialized) public key format.
    /// Internal format is 64 bytes, different from compressed (33) or uncompressed (65) serialized forms.
    /// </summary>
    static void WorkingWithInternalFormats()
    {
        Console.WriteLine("--- Working with Internal Formats ---");

        using var secp256k1 = new Secp256k1();

        // Generate a secret key
        Span<byte> secretKey = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKey);
        while (!secp256k1.EcSeckeyVerify(secretKey))
        {
            RandomNumberGenerator.Fill(secretKey);
        }

        // Create internal public key (64 bytes, not directly serializable)
        Span<byte> internalPubkey = stackalloc byte[64];
        bool created = secp256k1.EcPubkeyCreate(internalPubkey, secretKey);
        Console.WriteLine($"Public key created: {created}");
        Console.WriteLine($"Internal pubkey size: {internalPubkey.Length} bytes");

        // Serialize to compressed format (33 bytes)
        Span<byte> compressedPubkey = stackalloc byte[33];
        nuint compressedLen = 33;
        secp256k1.EcPubkeySerialize(compressedPubkey, ref compressedLen, internalPubkey, Secp256k1EcFlags.Compressed);
        Console.WriteLine($"Compressed pubkey ({compressedLen} bytes): {Convert.ToHexString(compressedPubkey)}");

        // Serialize to uncompressed format (65 bytes)
        Span<byte> uncompressedPubkey = stackalloc byte[65];
        nuint uncompressedLen = 65;
        secp256k1.EcPubkeySerialize(uncompressedPubkey, ref uncompressedLen, internalPubkey, Secp256k1EcFlags.Uncompressed);
        Console.WriteLine($"Uncompressed pubkey ({uncompressedLen} bytes): {Convert.ToHexString(uncompressedPubkey)}");

        // Parse a serialized public key back to internal format
        Span<byte> parsedInternal = stackalloc byte[64];
        bool parsed = secp256k1.EcPubkeyParse(parsedInternal, compressedPubkey);
        Console.WriteLine($"Parsed back to internal: {parsed}");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates using a custom hash function with ECDH.
    /// </summary>
    static void CustomEcdhHashFunction()
    {
        Console.WriteLine("--- Custom ECDH Hash Function ---");

        using var secp256k1 = new Secp256k1();

        // Create two keypairs
        Span<byte> secretKeyA = stackalloc byte[32];
        Span<byte> secretKeyB = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKeyA);
        RandomNumberGenerator.Fill(secretKeyB);

        Span<byte> internalPubkeyA = stackalloc byte[64];
        Span<byte> internalPubkeyB = stackalloc byte[64];
        secp256k1.EcPubkeyCreate(internalPubkeyA, secretKeyA);
        secp256k1.EcPubkeyCreate(internalPubkeyB, secretKeyB);

        // Standard ECDH (SHA256 hash of shared point)
        Span<byte> sharedSecretStandard = stackalloc byte[32];
        secp256k1.Ecdh(sharedSecretStandard, internalPubkeyB, secretKeyA);
        Console.WriteLine($"Standard ECDH: {Convert.ToHexString(sharedSecretStandard)}");

        // Custom ECDH hash function that returns raw X coordinate
        EcdhHashFunction rawXCoordinate = (Span<byte> output, ReadOnlySpan<byte> x32, ReadOnlySpan<byte> y32, IntPtr data) =>
        {
            // Simply copy the X coordinate as the shared secret
            x32.CopyTo(output);
            return 1;
        };

        Span<byte> sharedSecretRawX = stackalloc byte[32];
        secp256k1.Ecdh(sharedSecretRawX, internalPubkeyB, secretKeyA, rawXCoordinate, IntPtr.Zero);
        Console.WriteLine($"Raw X coord ECDH: {Convert.ToHexString(sharedSecretRawX)}");

        // Custom ECDH with concatenated X||Y hashed
        EcdhHashFunction hashXY = (Span<byte> output, ReadOnlySpan<byte> x32, ReadOnlySpan<byte> y32, IntPtr data) =>
        {
            Span<byte> combined = stackalloc byte[64];
            x32.CopyTo(combined);
            y32.CopyTo(combined[32..]);
            SHA256.HashData(combined, output);
            return 1;
        };

        Span<byte> sharedSecretXY = stackalloc byte[32];
        secp256k1.Ecdh(sharedSecretXY, internalPubkeyB, secretKeyA, hashXY, IntPtr.Zero);
        Console.WriteLine($"Hash(X||Y) ECDH: {Convert.ToHexString(sharedSecretXY)}");

        // Using the built-in SHA256 hash function as a callback
        // The library provides EcdhHashFunctionSha256 which can be wrapped in a delegate
        EcdhHashFunction builtInSha256 = (Span<byte> output, ReadOnlySpan<byte> x32, ReadOnlySpan<byte> y32, IntPtr data) =>
        {
            // Delegate to the built-in implementation
            return secp256k1.EcdhHashFunctionSha256(output, x32, y32, Span<byte>.Empty) ? 1 : 0;
        };

        Span<byte> sharedSecretBuiltIn = stackalloc byte[32];
        secp256k1.Ecdh(sharedSecretBuiltIn, internalPubkeyB, secretKeyA, builtInSha256, IntPtr.Zero);
        Console.WriteLine($"Built-in SHA256 ECDH: {Convert.ToHexString(sharedSecretBuiltIn)}");
        Console.WriteLine($"Matches standard: {sharedSecretStandard.SequenceEqual(sharedSecretBuiltIn)}");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates using a custom nonce function for signing.
    /// </summary>
    static void CustomNonceFunction()
    {
        Console.WriteLine("--- Custom Nonce Function ---");

        using var secp256k1 = new Secp256k1();

        // Create a keypair
        Span<byte> secretKey = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKey);
        while (!secp256k1.EcSeckeyVerify(secretKey))
        {
            RandomNumberGenerator.Fill(secretKey);
        }

        Span<byte> internalPubkey = stackalloc byte[64];
        secp256k1.EcPubkeyCreate(internalPubkey, secretKey);

        byte[] messageHash = SHA256.HashData("Custom nonce example"u8);

        // Standard signing (uses default RFC6979 nonce)
        Span<byte> internalSig = stackalloc byte[64];
        secp256k1.EcdsaSign(internalSig, messageHash, secretKey);

        Span<byte> compactSig = stackalloc byte[64];
        secp256k1.EcdsaSignatureSerializeCompact(compactSig, internalSig);
        Console.WriteLine($"Standard signature: {Convert.ToHexString(compactSig)}");

        // Custom deterministic nonce function
        // WARNING: This is for demonstration only. In production, use the default RFC6979 nonce.
        NonceFunction customNonce = (Span<byte> nonce32, ReadOnlySpan<byte> msg32, ReadOnlySpan<byte> key32,
                                      ReadOnlySpan<byte> algo16, IntPtr data, uint attempt) =>
        {
            // Simple deterministic nonce: SHA256(key || msg || attempt)
            // NOTE: This is NOT a secure nonce function - use only for demonstration
            Span<byte> combined = stackalloc byte[32 + 32 + 4];
            key32.CopyTo(combined);
            msg32.CopyTo(combined[32..]);
            BitConverter.GetBytes(attempt).CopyTo(combined[64..]);
            SHA256.HashData(combined, nonce32);
            return 1;
        };

        Span<byte> customInternalSig = stackalloc byte[64];
        secp256k1.EcdsaSign(customInternalSig, messageHash, secretKey, customNonce, IntPtr.Zero);

        Span<byte> customCompactSig = stackalloc byte[64];
        secp256k1.EcdsaSignatureSerializeCompact(customCompactSig, customInternalSig);
        Console.WriteLine($"Custom nonce signature: {Convert.ToHexString(customCompactSig)}");

        // Verify both signatures work
        bool standardValid = secp256k1.EcdsaVerify(internalSig, messageHash, internalPubkey);
        bool customValid = secp256k1.EcdsaVerify(customInternalSig, messageHash, internalPubkey);
        Console.WriteLine($"Standard sig valid: {standardValid}, Custom sig valid: {customValid}");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates using the RFC6979 nonce function directly.
    /// RFC6979 provides deterministic nonce generation for ECDSA signatures,
    /// ensuring the same message and key always produce the same signature.
    /// </summary>
    static void Rfc6979NonceFunction()
    {
        Console.WriteLine("--- RFC6979 Nonce Function ---");

        using var secp256k1 = new Secp256k1();

        // Create a keypair
        Span<byte> secretKey = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKey);
        while (!secp256k1.EcSeckeyVerify(secretKey))
        {
            RandomNumberGenerator.Fill(secretKey);
        }

        Span<byte> internalPubkey = stackalloc byte[64];
        secp256k1.EcPubkeyCreate(internalPubkey, secretKey);

        byte[] messageHash = SHA256.HashData("RFC6979 nonce example"u8);

        // Generate a nonce using RFC6979 directly
        // This is the same algorithm used internally by EcdsaSign when no custom nonce function is provided
        Span<byte> nonce = stackalloc byte[32];
        bool nonceGenerated = secp256k1.NonceFunctionRfc6979(
            nonce,
            messageHash,
            secretKey,
            ReadOnlySpan<byte>.Empty, // algo16: optional algorithm identifier (usually empty)
            Span<byte>.Empty,          // data: optional extra entropy (usually empty)
            0                          // attempt: retry counter (usually 0)
        );
        Console.WriteLine($"Nonce generated: {nonceGenerated}");
        Console.WriteLine($"RFC6979 nonce: {Convert.ToHexString(nonce)}");

        // Demonstrate determinism: same inputs always produce the same nonce
        Span<byte> nonce2 = stackalloc byte[32];
        secp256k1.NonceFunctionRfc6979(nonce2, messageHash, secretKey, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, 0);
        Console.WriteLine($"Same nonce on retry: {nonce.SequenceEqual(nonce2)}");

        // Using extra entropy (ndata) for additional randomization
        // When provided, RFC6979 mixes this into the nonce generation
        Span<byte> extraEntropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(extraEntropy);

        Span<byte> nonceWithEntropy = stackalloc byte[32];
        secp256k1.NonceFunctionRfc6979(
            nonceWithEntropy,
            messageHash,
            secretKey,
            ReadOnlySpan<byte>.Empty,
            extraEntropy,  // 32 bytes of extra entropy
            0
        );
        Console.WriteLine($"Nonce with extra entropy: {Convert.ToHexString(nonceWithEntropy)}");
        Console.WriteLine($"Different from base nonce: {!nonce.SequenceEqual(nonceWithEntropy)}");

        // The attempt parameter is used when the generated nonce would produce an invalid signature
        // (extremely rare). Each attempt produces a different nonce.
        Span<byte> nonceAttempt1 = stackalloc byte[32];
        secp256k1.NonceFunctionRfc6979(nonceAttempt1, messageHash, secretKey, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, 1);
        Console.WriteLine($"Nonce with attempt=1: {Convert.ToHexString(nonceAttempt1)}");
        Console.WriteLine($"Different from attempt=0: {!nonce.SequenceEqual(nonceAttempt1)}");

        // Sign using the default nonce function (which uses RFC6979 internally)
        // This produces the same signature every time for the same message/key
        Span<byte> sig1 = stackalloc byte[64];
        Span<byte> sig2 = stackalloc byte[64];
        secp256k1.EcdsaSign(sig1, messageHash, secretKey);
        secp256k1.EcdsaSign(sig2, messageHash, secretKey);

        Span<byte> compact1 = stackalloc byte[64];
        Span<byte> compact2 = stackalloc byte[64];
        secp256k1.EcdsaSignatureSerializeCompact(compact1, sig1);
        secp256k1.EcdsaSignatureSerializeCompact(compact2, sig2);

        Console.WriteLine($"\nDeterministic signatures (RFC6979):");
        Console.WriteLine($"Signature 1: {Convert.ToHexString(compact1)}");
        Console.WriteLine($"Signature 2: {Convert.ToHexString(compact2)}");
        Console.WriteLine($"Signatures identical: {compact1.SequenceEqual(compact2)}");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates public key comparison operations.
    /// </summary>
    static void PublicKeyComparison()
    {
        Console.WriteLine("--- Public Key Comparison ---");

        using var secp256k1 = new Secp256k1();

        // Create three public keys
        Span<byte> secretKey1 = stackalloc byte[32];
        Span<byte> secretKey2 = stackalloc byte[32];
        Span<byte> secretKey3 = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKey1);
        RandomNumberGenerator.Fill(secretKey2);
        RandomNumberGenerator.Fill(secretKey3);

        Span<byte> pubkey1 = stackalloc byte[64];
        Span<byte> pubkey2 = stackalloc byte[64];
        Span<byte> pubkey3 = stackalloc byte[64];
        secp256k1.EcPubkeyCreate(pubkey1, secretKey1);
        secp256k1.EcPubkeyCreate(pubkey2, secretKey2);
        secp256k1.EcPubkeyCreate(pubkey3, secretKey3);

        // Compare public keys (lexicographic order of compressed serialization)
        int cmp12 = secp256k1.EcPubkeyCmp(pubkey1, pubkey2);
        int cmp21 = secp256k1.EcPubkeyCmp(pubkey2, pubkey1);
        int cmp11 = secp256k1.EcPubkeyCmp(pubkey1, pubkey1);

        Console.WriteLine($"Compare(pk1, pk2): {cmp12} (negative = pk1 < pk2)");
        Console.WriteLine($"Compare(pk2, pk1): {cmp21} (positive = pk2 > pk1)");
        Console.WriteLine($"Compare(pk1, pk1): {cmp11} (zero = equal)");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates sorting multiple public keys.
    /// </summary>
    static void PublicKeySorting()
    {
        Console.WriteLine("--- Public Key Sorting ---");

        using var secp256k1 = new Secp256k1();

        // Create an array of public keys (internal format)
        byte[][] publicKeys = new byte[5][];
        for (int i = 0; i < 5; i++)
        {
            publicKeys[i] = new byte[64];
            byte[] secretKey = new byte[32];
            RandomNumberGenerator.Fill(secretKey);
            secp256k1.EcPubkeyCreate(publicKeys[i], secretKey);
        }

        // Display before sorting (showing compressed form for readability)
        Console.WriteLine("Before sorting:");
        Span<byte> compressed = stackalloc byte[33];
        for (int i = 0; i < publicKeys.Length; i++)
        {
            nuint len = 33;
            secp256k1.EcPubkeySerialize(compressed, ref len, publicKeys[i], Secp256k1EcFlags.Compressed);
            Console.WriteLine($"  [{i}]: {Convert.ToHexString(compressed)[..20]}...");
        }

        // Sort the public keys in-place (lexicographic order)
        bool sorted = secp256k1.EcPubkeySort(publicKeys);
        Console.WriteLine($"\nSort successful: {sorted}");

        // Display after sorting
        Console.WriteLine("\nAfter sorting:");
        for (int i = 0; i < publicKeys.Length; i++)
        {
            nuint len = 33;
            secp256k1.EcPubkeySerialize(compressed, ref len, publicKeys[i], Secp256k1EcFlags.Compressed);
            Console.WriteLine($"  [{i}]: {Convert.ToHexString(compressed)[..20]}...");
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates the keypair object for efficient Schnorr operations.
    /// </summary>
    static void KeypairOperations()
    {
        Console.WriteLine("--- Keypair Operations ---");

        using var secp256k1 = new Secp256k1();

        // Create a secret key
        Span<byte> secretKey = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKey);
        while (!secp256k1.EcSeckeyVerify(secretKey))
        {
            RandomNumberGenerator.Fill(secretKey);
        }

        // Create a keypair (96 bytes, contains both secret and public key data)
        Span<byte> keypair = stackalloc byte[96];
        bool created = secp256k1.KeypairCreate(keypair, secretKey);
        Console.WriteLine($"Keypair created: {created}");

        // Extract secret key from keypair
        Span<byte> extractedSecret = stackalloc byte[32];
        secp256k1.KeypairSec(extractedSecret, keypair);
        Console.WriteLine($"Extracted secret matches: {extractedSecret.SequenceEqual(secretKey)}");

        // Extract public key from keypair (internal format)
        Span<byte> extractedPubkey = stackalloc byte[64];
        secp256k1.KeypairPub(extractedPubkey, keypair);

        // Extract x-only public key with parity
        Span<byte> xonlyPubkey = stackalloc byte[64];
        secp256k1.KeypairXonlyPub(xonlyPubkey, out int parity, keypair);

        // Serialize x-only public key (32 bytes)
        Span<byte> xonlySerialized = stackalloc byte[32];
        secp256k1.XonlyPubkeySerialize(xonlySerialized, xonlyPubkey);
        Console.WriteLine($"X-only pubkey: {Convert.ToHexString(xonlySerialized)}");
        Console.WriteLine($"Parity: {parity} (0 = even Y, 1 = odd Y)");

        // Tweak the keypair
        byte[] tweak = SHA256.HashData("keypair tweak"u8);
        Span<byte> tweakedKeypair = stackalloc byte[96];
        keypair.CopyTo(tweakedKeypair);
        bool tweaked = secp256k1.KeypairXonlyTweakAdd(tweakedKeypair, tweak);
        Console.WriteLine($"Keypair tweaked: {tweaked}");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates Schnorr signing using the low-level keypair API.
    /// </summary>
    static void SchnorrWithKeypair()
    {
        Console.WriteLine("--- Schnorr with Keypair ---");

        using var secp256k1 = new Secp256k1();

        // Create keypair
        Span<byte> secretKey = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKey);
        while (!secp256k1.EcSeckeyVerify(secretKey))
        {
            RandomNumberGenerator.Fill(secretKey);
        }

        Span<byte> keypair = stackalloc byte[96];
        secp256k1.KeypairCreate(keypair, secretKey);

        // Get x-only public key for verification
        Span<byte> xonlyPubkey = stackalloc byte[64];
        secp256k1.KeypairXonlyPub(xonlyPubkey, out _, keypair);

        // Message hash
        byte[] messageHash = SHA256.HashData("Schnorr keypair example"u8);

        // Auxiliary randomness (32 bytes)
        Span<byte> auxRand = stackalloc byte[32];
        RandomNumberGenerator.Fill(auxRand);

        // Sign with Schnorr
        Span<byte> signature = stackalloc byte[64];
        bool signed = secp256k1.SchnorrsigSign32(signature, messageHash, keypair, auxRand);
        Console.WriteLine($"Schnorr signed: {signed}");
        Console.WriteLine($"Signature: {Convert.ToHexString(signature)}");

        // Verify
        bool verified = secp256k1.SchnorrsigVerify(signature, messageHash, xonlyPubkey);
        Console.WriteLine($"Schnorr verified: {verified}");

        // Sign with variable-length message (using SchnorrsigSignCustom)
        byte[] variableLengthMsg = Encoding.UTF8.GetBytes("This is a variable length message for Schnorr signing");
        Span<byte> signature2 = stackalloc byte[64];
        bool signed2 = secp256k1.SchnorrsigSignCustom(signature2, variableLengthMsg, keypair, Span<byte>.Empty);
        Console.WriteLine($"\nVariable-length message signed: {signed2}");

        // Verify variable-length signature
        bool verified2 = secp256k1.SchnorrsigVerify(signature2, variableLengthMsg, xonlyPubkey);
        Console.WriteLine($"Variable-length verified: {verified2}");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates X-only public key tweaking for Taproot (BIP-341).
    /// </summary>
    static void XonlyPubkeyTweakingExample()
    {
        Console.WriteLine("--- X-only Public Key Tweaking (Taproot) ---");

        using var secp256k1 = new Secp256k1();

        // Create a keypair
        Span<byte> secretKey = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKey);
        while (!secp256k1.EcSeckeyVerify(secretKey))
        {
            RandomNumberGenerator.Fill(secretKey);
        }

        // Create internal public key (used as Taproot internal key)
        Span<byte> internalPubkey = stackalloc byte[64];
        secp256k1.EcPubkeyCreate(internalPubkey, secretKey);

        // Convert to x-only format
        Span<byte> xonlyInternal = stackalloc byte[64];
        secp256k1.XonlyPubkeyFromPubkey(xonlyInternal, out int internalParity, internalPubkey);

        // Serialize the x-only key
        Span<byte> xonlySerialized = stackalloc byte[32];
        secp256k1.XonlyPubkeySerialize(xonlySerialized, xonlyInternal);
        Console.WriteLine($"Internal x-only pubkey: {Convert.ToHexString(xonlySerialized)}");
        Console.WriteLine($"Internal key parity: {internalParity}");

        // Create a tweak (in Taproot, this would be derived from the script tree)
        byte[] tweak = SHA256.HashData("TapTweak example"u8);
        Console.WriteLine($"Tweak: {Convert.ToHexString(tweak)}");

        // Tweak the x-only public key (result is a regular pubkey, not x-only)
        Span<byte> tweakedPubkey = stackalloc byte[64];
        bool tweakSuccess = secp256k1.XonlyPubkeyTweakAdd(tweakedPubkey, xonlyInternal, tweak);
        Console.WriteLine($"Tweak successful: {tweakSuccess}");

        // Convert tweaked key to x-only and get its parity
        Span<byte> tweakedXonly = stackalloc byte[64];
        secp256k1.XonlyPubkeyFromPubkey(tweakedXonly, out int tweakedParity, tweakedPubkey);

        Span<byte> tweakedSerialized = stackalloc byte[32];
        secp256k1.XonlyPubkeySerialize(tweakedSerialized, tweakedXonly);
        Console.WriteLine($"Tweaked x-only pubkey: {Convert.ToHexString(tweakedSerialized)}");
        Console.WriteLine($"Tweaked key parity: {tweakedParity}");

        // Verify the tweak was applied correctly (important for Taproot validation)
        bool tweakValid = secp256k1.XonlyPubkeyTweakAddCheck(
            tweakedSerialized, tweakedParity, xonlyInternal, tweak);
        Console.WriteLine($"Tweak verification: {tweakValid}");

        Console.WriteLine();
        Console.WriteLine("Taproot use case:");
        Console.WriteLine("  - Internal key: the key that can spend without revealing scripts");
        Console.WriteLine("  - Tweak: derived from Merkle root of script tree (or empty for key-path only)");
        Console.WriteLine("  - Tweaked key: the actual output key committed to in the transaction");
        Console.WriteLine("  - TweakAddCheck: verifies a claimed internal key matches the output key");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates ElligatorSwift encoding for BIP-324 encrypted transport.
    /// </summary>
    static void ElligatorSwiftExample()
    {
        Console.WriteLine("--- ElligatorSwift (BIP-324) ---");

        using var secp256k1 = new Secp256k1();

        // Create two parties for key exchange
        // Party A
        Span<byte> secretKeyA = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKeyA);
        while (!secp256k1.EcSeckeyVerify(secretKeyA))
        {
            RandomNumberGenerator.Fill(secretKeyA);
        }

        // Party B
        Span<byte> secretKeyB = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKeyB);
        while (!secp256k1.EcSeckeyVerify(secretKeyB))
        {
            RandomNumberGenerator.Fill(secretKeyB);
        }

        // Create ElligatorSwift encoded public keys (64 bytes each)
        // These look like random data, providing privacy
        Span<byte> auxRandA = stackalloc byte[32];
        Span<byte> auxRandB = stackalloc byte[32];
        RandomNumberGenerator.Fill(auxRandA);
        RandomNumberGenerator.Fill(auxRandB);

        Span<byte> ellswiftA = stackalloc byte[64];
        Span<byte> ellswiftB = stackalloc byte[64];

        bool createdA = secp256k1.EllswiftCreate(ellswiftA, secretKeyA, auxRandA);
        bool createdB = secp256k1.EllswiftCreate(ellswiftB, secretKeyB, auxRandB);

        Console.WriteLine($"Party A ElligatorSwift pubkey: {Convert.ToHexString(ellswiftA)[..40]}...");
        Console.WriteLine($"Party B ElligatorSwift pubkey: {Convert.ToHexString(ellswiftB)[..40]}...");

        // Decode ElligatorSwift back to regular public key
        Span<byte> decodedPubkeyA = stackalloc byte[64];
        secp256k1.EllswiftDecode(decodedPubkeyA, ellswiftA);

        // Verify it matches the original public key
        Span<byte> originalPubkeyA = stackalloc byte[64];
        secp256k1.EcPubkeyCreate(originalPubkeyA, secretKeyA);

        // Serialize both to compare
        Span<byte> decodedCompressed = stackalloc byte[33];
        Span<byte> originalCompressed = stackalloc byte[33];
        nuint len = 33;
        secp256k1.EcPubkeySerialize(decodedCompressed, ref len, decodedPubkeyA, Secp256k1EcFlags.Compressed);
        len = 33;
        secp256k1.EcPubkeySerialize(originalCompressed, ref len, originalPubkeyA, Secp256k1EcFlags.Compressed);

        Console.WriteLine($"\nDecoded pubkey matches original: {decodedCompressed.SequenceEqual(originalCompressed)}");

        // ElligatorSwift ECDH - compute shared secret directly from encoded keys
        // This is more efficient than decoding + ECDH

        // Custom hash function for ElligatorSwift XDH
        EllswiftXdhHashFunction hashFunc = (Span<byte> output, ReadOnlySpan<byte> x32,
            ReadOnlySpan<byte> ell_a64, ReadOnlySpan<byte> ell_b64, IntPtr data) =>
        {
            // BIP-324 style: hash the shared secret with both encoded public keys
            Span<byte> combined = stackalloc byte[32 + 64 + 64];
            x32.CopyTo(combined);
            ell_a64.CopyTo(combined[32..]);
            ell_b64.CopyTo(combined[96..]);
            SHA256.HashData(combined, output);
            return 1;
        };

        // Party A computes shared secret (party=0 means we are party A)
        Span<byte> sharedSecretA = stackalloc byte[32];
        secp256k1.EllswiftXdh(sharedSecretA, ellswiftA, ellswiftB, secretKeyA, 0, hashFunc, IntPtr.Zero);

        // Party B computes shared secret (party=1 means we are party B)
        Span<byte> sharedSecretB = stackalloc byte[32];
        secp256k1.EllswiftXdh(sharedSecretB, ellswiftA, ellswiftB, secretKeyB, 1, hashFunc, IntPtr.Zero);

        Console.WriteLine($"\nParty A shared secret (custom hash): {Convert.ToHexString(sharedSecretA)}");
        Console.WriteLine($"Party B shared secret (custom hash): {Convert.ToHexString(sharedSecretB)}");
        Console.WriteLine($"Shared secrets match: {sharedSecretA.SequenceEqual(sharedSecretB)}");

        // Using the built-in BIP-324 hash function as a callback
        // This is the standard hash function for Bitcoin P2P encrypted transport
        EllswiftXdhHashFunction bip324Hash = (Span<byte> output, ReadOnlySpan<byte> x32,
            ReadOnlySpan<byte> ell_a64, ReadOnlySpan<byte> ell_b64, IntPtr data) =>
        {
            // Delegate to the built-in BIP-324 implementation
            return secp256k1.EllswiftXdhHashFunctionBip324(output, x32, ell_a64, ell_b64, Span<byte>.Empty) ? 1 : 0;
        };

        Span<byte> sharedSecretBip324A = stackalloc byte[32];
        Span<byte> sharedSecretBip324B = stackalloc byte[32];
        secp256k1.EllswiftXdh(sharedSecretBip324A, ellswiftA, ellswiftB, secretKeyA, 0, bip324Hash, IntPtr.Zero);
        secp256k1.EllswiftXdh(sharedSecretBip324B, ellswiftA, ellswiftB, secretKeyB, 1, bip324Hash, IntPtr.Zero);

        Console.WriteLine($"\nParty A shared secret (BIP-324): {Convert.ToHexString(sharedSecretBip324A)}");
        Console.WriteLine($"Party B shared secret (BIP-324): {Convert.ToHexString(sharedSecretBip324B)}");
        Console.WriteLine($"BIP-324 secrets match: {sharedSecretBip324A.SequenceEqual(sharedSecretBip324B)}");

        Console.WriteLine();
        Console.WriteLine("BIP-324 use case:");
        Console.WriteLine("  - ElligatorSwift encodes public keys as 64 random-looking bytes");
        Console.WriteLine("  - Makes Bitcoin P2P traffic indistinguishable from random data");
        Console.WriteLine("  - Prevents passive network observers from identifying Bitcoin nodes");
        Console.WriteLine("  - EllswiftXdh combines decoding and ECDH in one efficient operation");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates setting a custom error callback.
    /// </summary>
    static void ErrorCallbackExample()
    {
        Console.WriteLine("--- Custom Error Callback ---");

        string? lastErrorMessage = null;

        // Create instance with custom error callback
        // The callback is invoked by the native secp256k1 library when it detects
        // illegal arguments or internal errors that bypass C# wrapper validation
        ErrorCallbackDelegate errorCallback = (string message, IntPtr data) =>
        {
            lastErrorMessage = message;
            Console.WriteLine($"  Callback received: \"{message}\"");
        };

        using var secp256k1 = new Secp256k1(errorCallback);

        Console.WriteLine("Custom error callback set");

        // Normal operations don't trigger the callback
        Console.WriteLine("\n1. Normal operation (valid secret key):");
        Span<byte> secretKey = stackalloc byte[32];
        RandomNumberGenerator.Fill(secretKey);
        bool isValid = secp256k1.EcSeckeyVerify(secretKey);
        Console.WriteLine($"   Secret key valid: {isValid}");
        Console.WriteLine($"   Error triggered: {lastErrorMessage != null}");

        // Trigger the callback with an invalid recovery ID
        // The recoveryId must be 0-3, but we pass 9 to trigger native validation
        Console.WriteLine("\n2. Invalid operation (bad recovery ID in signature parsing):");
        lastErrorMessage = null;

        // Create a dummy signature (64 bytes)
        Span<byte> serializedSig = stackalloc byte[64];
        RandomNumberGenerator.Fill(serializedSig);
        Span<byte> outputSig = stackalloc byte[65];

        // Pass invalid recoveryId (must be 0-3, we pass 9)
        bool parseResult = secp256k1.EcdsaRecoverableSignatureParseCompact(outputSig, serializedSig, 9);
        Console.WriteLine($"   Parse result: {parseResult}");
        Console.WriteLine($"   Error triggered: {lastErrorMessage != null}");

        Console.WriteLine();
    }
}
