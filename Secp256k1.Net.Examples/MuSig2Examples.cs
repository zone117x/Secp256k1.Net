using System.Security.Cryptography;
using Secp256k1Net;

namespace Secp256k1Net.Examples;

/// <summary>
/// Examples demonstrating MuSig2 multi-signature scheme.
/// MuSig2 allows multiple parties to create a single aggregated signature
/// that is indistinguishable from a regular Schnorr signature.
/// </summary>
public static class MuSig2Examples
{
    public static void Run()
    {
        Console.WriteLine("=== MuSig2 Multi-Signature Examples ===\n");

        MuSig2Overview();
        TwoPartyMuSig();
        ThreePartyMuSig();
        MuSigWithTweaking();
    }

    /// <summary>
    /// Overview of MuSig2 protocol.
    /// </summary>
    static void MuSig2Overview()
    {
        Console.WriteLine("--- MuSig2 Overview ---");

        Console.WriteLine(@"
MuSig2 is a multi-signature scheme that produces a single 64-byte Schnorr signature
from multiple signers. The signature is indistinguishable from a regular signature.

Protocol steps:
  1. Key Aggregation: Combine all signers' public keys into one aggregate key
  2. Nonce Generation: Each signer generates a secret/public nonce pair
  3. Nonce Aggregation: Combine all public nonces into an aggregate nonce
  4. Partial Signing: Each signer creates a partial signature
  5. Signature Aggregation: Combine partial signatures into final signature

Security considerations:
  - NEVER reuse nonces across signing sessions
  - Each signer must use fresh randomness for nonce generation
  - The protocol requires two rounds of communication between signers

Use cases:
  - Bitcoin multisig with smaller on-chain footprint
  - Threshold signatures for custody solutions
  - Privacy-preserving multi-party transactions
");
        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates a complete 2-of-2 MuSig2 signing session.
    /// </summary>
    static void TwoPartyMuSig()
    {
        Console.WriteLine("--- Two-Party MuSig2 Signing ---");

        using var secp256k1 = new Secp256k1();

        // ===== SETUP: Each party generates their keypair =====
        Console.WriteLine("1. Setup: Each party generates a keypair");

        // Party A's keypair
        byte[] secretKeyA = new byte[32];
        RandomNumberGenerator.Fill(secretKeyA);
        while (!secp256k1.EcSeckeyVerify(secretKeyA))
            RandomNumberGenerator.Fill(secretKeyA);

        byte[] keypairA = new byte[96];
        secp256k1.KeypairCreate(keypairA, secretKeyA);

        byte[] internalPubkeyA = new byte[64];
        secp256k1.KeypairPub(internalPubkeyA, keypairA);

        // Party B's keypair
        byte[] secretKeyB = new byte[32];
        RandomNumberGenerator.Fill(secretKeyB);
        while (!secp256k1.EcSeckeyVerify(secretKeyB))
            RandomNumberGenerator.Fill(secretKeyB);

        byte[] keypairB = new byte[96];
        secp256k1.KeypairCreate(keypairB, secretKeyB);

        byte[] internalPubkeyB = new byte[64];
        secp256k1.KeypairPub(internalPubkeyB, keypairB);

        // Display public keys
        Span<byte> compressedA = stackalloc byte[33];
        Span<byte> compressedB = stackalloc byte[33];
        nuint len = 33;
        secp256k1.EcPubkeySerialize(compressedA, ref len, internalPubkeyA, Secp256k1EcFlags.Compressed);
        len = 33;
        secp256k1.EcPubkeySerialize(compressedB, ref len, internalPubkeyB, Secp256k1EcFlags.Compressed);
        Console.WriteLine($"   Party A pubkey: {Convert.ToHexString(compressedA)}");
        Console.WriteLine($"   Party B pubkey: {Convert.ToHexString(compressedB)}");

        // ===== KEY AGGREGATION =====
        Console.WriteLine("\n2. Key Aggregation: Combine public keys");

        // Sort public keys for deterministic aggregation
        byte[][] pubkeys = [internalPubkeyA, internalPubkeyB];
        secp256k1.EcPubkeySort(pubkeys);

        // Aggregate public keys
        Span<byte> aggPubkey = stackalloc byte[64];
        Span<byte> keyaggCache = stackalloc byte[197];
        bool aggSuccess = secp256k1.MusigPubkeyAgg(aggPubkey, keyaggCache, pubkeys);

        // Get x-only aggregate public key
        Span<byte> aggXonly = stackalloc byte[64];
        secp256k1.XonlyPubkeyFromPubkey(aggXonly, out int aggParity, aggPubkey);

        Span<byte> aggXonlySerialized = stackalloc byte[32];
        secp256k1.XonlyPubkeySerialize(aggXonlySerialized, aggXonly);
        Console.WriteLine($"   Aggregate pubkey: {Convert.ToHexString(aggXonlySerialized)}");
        Console.WriteLine($"   Aggregation successful: {aggSuccess}");

        // ===== NONCE GENERATION (Round 1) =====
        Console.WriteLine("\n3. Nonce Generation: Each party generates nonces");

        // The message to sign
        byte[] message = SHA256.HashData("MuSig2 test message"u8);
        Console.WriteLine($"   Message hash: {Convert.ToHexString(message)}");

        // Extra input (optional, can be zeros or additional entropy like current time)
        Span<byte> extraInput = stackalloc byte[32];

        // Party A generates nonce
        Span<byte> secnonceA = stackalloc byte[132];
        Span<byte> pubnonceA = stackalloc byte[132];
        Span<byte> sessionRandA = stackalloc byte[32];
        RandomNumberGenerator.Fill(sessionRandA);

        secp256k1.MusigNonceGen(secnonceA, pubnonceA, sessionRandA, secretKeyA,
            internalPubkeyA, message, keyaggCache, extraInput);

        // Party B generates nonce
        Span<byte> secnonceB = stackalloc byte[132];
        Span<byte> pubnonceB = stackalloc byte[132];
        Span<byte> sessionRandB = stackalloc byte[32];
        RandomNumberGenerator.Fill(sessionRandB);

        secp256k1.MusigNonceGen(secnonceB, pubnonceB, sessionRandB, secretKeyB,
            internalPubkeyB, message, keyaggCache, extraInput);

        // Serialize public nonces for exchange
        Span<byte> pubnonceSerializedA = stackalloc byte[66];
        Span<byte> pubnonceSerializedB = stackalloc byte[66];
        secp256k1.MusigPubnonceSerialize(pubnonceSerializedA, pubnonceA);
        secp256k1.MusigPubnonceSerialize(pubnonceSerializedB, pubnonceB);
        Console.WriteLine($"   Party A pubnonce: {Convert.ToHexString(pubnonceSerializedA)[..40]}...");
        Console.WriteLine($"   Party B pubnonce: {Convert.ToHexString(pubnonceSerializedB)[..40]}...");

        // ===== NONCE AGGREGATION =====
        Console.WriteLine("\n4. Nonce Aggregation: Combine public nonces");

        // Parse received nonces (in real scenario, these come from other parties)
        byte[] parsedNonceA = new byte[132];
        byte[] parsedNonceB = new byte[132];
        secp256k1.MusigPubnonceParse(parsedNonceA, pubnonceSerializedA);
        secp256k1.MusigPubnonceParse(parsedNonceB, pubnonceSerializedB);

        // Aggregate nonces
        Span<byte> aggNonce = stackalloc byte[132];
        byte[][] pubnonces = [parsedNonceA, parsedNonceB];
        bool nonceAggSuccess = secp256k1.MusigNonceAgg(aggNonce, pubnonces);

        Span<byte> aggNonceSerialized = stackalloc byte[66];
        secp256k1.MusigAggnonceSerialize(aggNonceSerialized, aggNonce);
        Console.WriteLine($"   Aggregate nonce: {Convert.ToHexString(aggNonceSerialized)[..40]}...");
        Console.WriteLine($"   Nonce aggregation successful: {nonceAggSuccess}");

        // ===== CREATE SIGNING SESSION =====
        Console.WriteLine("\n5. Create Signing Session");

        Span<byte> session = stackalloc byte[133];
        bool sessionCreated = secp256k1.MusigNonceProcess(session, aggNonce, message, keyaggCache);
        Console.WriteLine($"   Session created: {sessionCreated}");

        // ===== PARTIAL SIGNING (Round 2) =====
        Console.WriteLine("\n6. Partial Signing: Each party creates partial signature");

        // Party A creates partial signature
        Span<byte> partialSigA = stackalloc byte[36];
        bool signedA = secp256k1.MusigPartialSign(partialSigA, secnonceA, keypairA, keyaggCache, session);

        Span<byte> partialSigSerializedA = stackalloc byte[32];
        secp256k1.MusigPartialSigSerialize(partialSigSerializedA, partialSigA);
        Console.WriteLine($"   Party A partial sig: {Convert.ToHexString(partialSigSerializedA)}");

        // Party B creates partial signature
        Span<byte> partialSigB = stackalloc byte[36];
        bool signedB = secp256k1.MusigPartialSign(partialSigB, secnonceB, keypairB, keyaggCache, session);

        Span<byte> partialSigSerializedB = stackalloc byte[32];
        secp256k1.MusigPartialSigSerialize(partialSigSerializedB, partialSigB);
        Console.WriteLine($"   Party B partial sig: {Convert.ToHexString(partialSigSerializedB)}");

        // ===== VERIFY PARTIAL SIGNATURES (optional but recommended) =====
        Console.WriteLine("\n7. Verify Partial Signatures (optional)");

        bool partialVerifyA = secp256k1.MusigPartialSigVerify(partialSigA, pubnonceA, internalPubkeyA, keyaggCache, session);
        bool partialVerifyB = secp256k1.MusigPartialSigVerify(partialSigB, pubnonceB, internalPubkeyB, keyaggCache, session);
        Console.WriteLine($"   Party A partial sig valid: {partialVerifyA}");
        Console.WriteLine($"   Party B partial sig valid: {partialVerifyB}");

        // ===== SIGNATURE AGGREGATION =====
        Console.WriteLine("\n8. Signature Aggregation: Combine partial signatures");

        // Parse partial signatures
        byte[] parsedPartialA = new byte[36];
        byte[] parsedPartialB = new byte[36];
        secp256k1.MusigPartialSigParse(parsedPartialA, partialSigSerializedA);
        secp256k1.MusigPartialSigParse(parsedPartialB, partialSigSerializedB);

        // Aggregate into final signature
        Span<byte> finalSignature = stackalloc byte[64];
        byte[][] partialSigs = [parsedPartialA, parsedPartialB];
        bool aggSigSuccess = secp256k1.MusigPartialSigAgg(finalSignature, session, partialSigs);

        Console.WriteLine($"   Final signature: {Convert.ToHexString(finalSignature)}");
        Console.WriteLine($"   Aggregation successful: {aggSigSuccess}");

        // ===== VERIFY FINAL SIGNATURE =====
        Console.WriteLine("\n9. Verify Final Signature (standard Schnorr verification)");

        bool verified = secp256k1.SchnorrsigVerify(finalSignature, message, aggXonly);
        Console.WriteLine($"   Signature valid: {verified}");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates a 3-of-3 MuSig2 signing session.
    /// </summary>
    static void ThreePartyMuSig()
    {
        Console.WriteLine("--- Three-Party MuSig2 Signing ---");

        using var secp256k1 = new Secp256k1();

        // Setup: Create 3 keypairs
        // We'll store keypair and pubkey together so they stay aligned after sorting
        var signers = new (byte[] Keypair, byte[] Pubkey)[3];

        for (int i = 0; i < 3; i++)
        {
            byte[] secretKey = new byte[32];
            signers[i].Keypair = new byte[96];
            signers[i].Pubkey = new byte[64];

            RandomNumberGenerator.Fill(secretKey);
            while (!secp256k1.EcSeckeyVerify(secretKey))
                RandomNumberGenerator.Fill(secretKey);

            secp256k1.KeypairCreate(signers[i].Keypair, secretKey);
            secp256k1.KeypairPub(signers[i].Pubkey, signers[i].Keypair);
        }

        Console.WriteLine("Created 3 keypairs");

        // Sort signers by their public keys (lexicographic order)
        // This ensures deterministic aggregate key regardless of signer order
        Array.Sort(signers, (a, b) => secp256k1.EcPubkeyCmp(a.Pubkey, b.Pubkey));

        // Extract sorted public keys for aggregation
        byte[][] publicKeys = signers.Select(s => s.Pubkey).ToArray();

        Span<byte> aggPubkey = stackalloc byte[64];
        Span<byte> keyaggCache = stackalloc byte[197];
        secp256k1.MusigPubkeyAgg(aggPubkey, keyaggCache, publicKeys);

        Span<byte> aggXonly = stackalloc byte[64];
        secp256k1.XonlyPubkeyFromPubkey(aggXonly, out _, aggPubkey);

        Span<byte> aggSerialized = stackalloc byte[32];
        secp256k1.XonlyPubkeySerialize(aggSerialized, aggXonly);
        Console.WriteLine($"Aggregate pubkey: {Convert.ToHexString(aggSerialized)}");

        // Message
        byte[] message = SHA256.HashData("Three-party MuSig2 message"u8);

        // Generate nonces for all parties
        byte[][] secnonces = new byte[3][];
        byte[][] pubnonces = new byte[3][];

        // Extra input (optional)
        byte[] extraInput = new byte[32];

        for (int i = 0; i < 3; i++)
        {
            secnonces[i] = new byte[132];
            pubnonces[i] = new byte[132];

            byte[] sessionRand = new byte[32];
            RandomNumberGenerator.Fill(sessionRand);

            // Extract secret key from keypair for nonce generation
            byte[] secretKey = new byte[32];
            secp256k1.KeypairSec(secretKey, signers[i].Keypair);

            secp256k1.MusigNonceGen(secnonces[i], pubnonces[i], sessionRand,
                secretKey, signers[i].Pubkey, message, keyaggCache, extraInput);
        }

        Console.WriteLine("Generated nonces for all 3 parties");

        // Aggregate nonces
        Span<byte> aggNonce = stackalloc byte[132];
        secp256k1.MusigNonceAgg(aggNonce, pubnonces);

        // Create session
        Span<byte> session = stackalloc byte[133];
        secp256k1.MusigNonceProcess(session, aggNonce, message, keyaggCache);

        // Create partial signatures
        byte[][] partialSigs = new byte[3][];
        for (int i = 0; i < 3; i++)
        {
            partialSigs[i] = new byte[36];
            secp256k1.MusigPartialSign(partialSigs[i], secnonces[i], signers[i].Keypair, keyaggCache, session);
        }

        Console.WriteLine("Created 3 partial signatures");

        // Aggregate signatures
        Span<byte> finalSignature = stackalloc byte[64];
        secp256k1.MusigPartialSigAgg(finalSignature, session, partialSigs);

        Console.WriteLine($"Final signature: {Convert.ToHexString(finalSignature)}");

        // Verify
        bool verified = secp256k1.SchnorrsigVerify(finalSignature, message, aggXonly);
        Console.WriteLine($"Signature valid: {verified}");

        Console.WriteLine();
    }

    /// <summary>
    /// Demonstrates MuSig2 with key tweaking for Taproot.
    /// </summary>
    static void MuSigWithTweaking()
    {
        Console.WriteLine("--- MuSig2 with Taproot Tweaking ---");

        using var secp256k1 = new Secp256k1();

        // Create 2 keypairs - keep keypair and pubkey together
        var signers = new (byte[] Keypair, byte[] Pubkey)[2];

        for (int i = 0; i < 2; i++)
        {
            byte[] secretKey = new byte[32];
            signers[i].Keypair = new byte[96];
            signers[i].Pubkey = new byte[64];

            RandomNumberGenerator.Fill(secretKey);
            while (!secp256k1.EcSeckeyVerify(secretKey))
                RandomNumberGenerator.Fill(secretKey);

            secp256k1.KeypairCreate(signers[i].Keypair, secretKey);
            secp256k1.KeypairPub(signers[i].Pubkey, signers[i].Keypair);
        }

        // Sort signers by their public keys
        Array.Sort(signers, (a, b) => secp256k1.EcPubkeyCmp(a.Pubkey, b.Pubkey));

        // Extract sorted public keys for aggregation
        byte[][] publicKeys = signers.Select(s => s.Pubkey).ToArray();

        Span<byte> aggPubkey = stackalloc byte[64];
        Span<byte> keyaggCache = stackalloc byte[197];
        secp256k1.MusigPubkeyAgg(aggPubkey, keyaggCache, publicKeys);

        // Get the untweaked aggregate key
        Span<byte> untweakedXonly = stackalloc byte[64];
        secp256k1.XonlyPubkeyFromPubkey(untweakedXonly, out _, aggPubkey);
        Span<byte> untweakedSerialized = stackalloc byte[32];
        secp256k1.XonlyPubkeySerialize(untweakedSerialized, untweakedXonly);
        Console.WriteLine($"Untweaked aggregate key: {Convert.ToHexString(untweakedSerialized)}");

        // Create a Taproot-style tweak (in practice, this would be derived from script tree)
        byte[] tweak = SHA256.HashData("TapTweak"u8);
        Console.WriteLine($"Tweak: {Convert.ToHexString(tweak)}");

        // Apply x-only tweak to the aggregate key
        // This modifies keyaggCache to account for the tweak during signing
        Span<byte> tweakedPubkey = stackalloc byte[64];
        bool tweakSuccess = secp256k1.MusigPubkeyXonlyTweakAdd(tweakedPubkey, keyaggCache, tweak);
        Console.WriteLine($"Tweak applied: {tweakSuccess}");

        // Get the tweaked x-only key (this is the Taproot output key)
        Span<byte> tweakedXonly = stackalloc byte[64];
        secp256k1.XonlyPubkeyFromPubkey(tweakedXonly, out _, tweakedPubkey);
        Span<byte> tweakedSerialized = stackalloc byte[32];
        secp256k1.XonlyPubkeySerialize(tweakedSerialized, tweakedXonly);
        Console.WriteLine($"Tweaked aggregate key: {Convert.ToHexString(tweakedSerialized)}");

        // Message to sign
        byte[] message = SHA256.HashData("Taproot MuSig2 transaction"u8);

        // Generate nonces (using the TWEAKED keyaggCache)
        byte[][] secnonces = new byte[2][];
        byte[][] pubnonces = new byte[2][];

        // Extra input (optional)
        byte[] extraInput = new byte[32];

        for (int i = 0; i < 2; i++)
        {
            secnonces[i] = new byte[132];
            pubnonces[i] = new byte[132];

            byte[] sessionRand = new byte[32];
            RandomNumberGenerator.Fill(sessionRand);

            // Extract secret key from keypair for nonce generation
            byte[] secretKey = new byte[32];
            secp256k1.KeypairSec(secretKey, signers[i].Keypair);

            // Note: using the tweaked keyaggCache here
            secp256k1.MusigNonceGen(secnonces[i], pubnonces[i], sessionRand,
                secretKey, signers[i].Pubkey, message, keyaggCache, extraInput);
        }

        // Aggregate nonces
        Span<byte> aggNonce = stackalloc byte[132];
        secp256k1.MusigNonceAgg(aggNonce, pubnonces);

        // Create session with tweaked keyaggCache
        Span<byte> session = stackalloc byte[133];
        secp256k1.MusigNonceProcess(session, aggNonce, message, keyaggCache);

        // Create and aggregate partial signatures
        byte[][] partialSigs = new byte[2][];
        for (int i = 0; i < 2; i++)
        {
            partialSigs[i] = new byte[36];
            secp256k1.MusigPartialSign(partialSigs[i], secnonces[i], signers[i].Keypair, keyaggCache, session);
        }

        Span<byte> finalSignature = stackalloc byte[64];
        secp256k1.MusigPartialSigAgg(finalSignature, session, partialSigs);

        Console.WriteLine($"Final signature: {Convert.ToHexString(finalSignature)}");

        // Verify against the TWEAKED public key
        bool verified = secp256k1.SchnorrsigVerify(finalSignature, message, tweakedXonly);
        Console.WriteLine($"Signature valid against tweaked key: {verified}");

        Console.WriteLine();
        Console.WriteLine("Taproot + MuSig2 use case:");
        Console.WriteLine("  - Multiple parties can jointly control a Taproot output");
        Console.WriteLine("  - The aggregate key becomes the internal key");
        Console.WriteLine("  - After tweaking, it becomes the output key on-chain");
        Console.WriteLine("  - Key-path spend requires all parties to sign");
        Console.WriteLine("  - Script-path can provide fallback/recovery options");

        Console.WriteLine();
    }
}
