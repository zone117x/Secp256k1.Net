using Secp256k1Net.Examples;

Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║           Secp256k1.Net Examples                             ║");
Console.WriteLine("║           Cryptographic Operations Demonstration             ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
Console.WriteLine();

// Run all examples by default, or specify which section to run
if (args.Length == 0)
{
    RunAllExamples();
}
else
{
    RunSelectedExample(args[0].ToLowerInvariant());
}

static void RunAllExamples()
{
    KeyGenerationExamples.Run();
    PublicKeyOperationsExamples.Run();
    EcdsaSigningExamples.Run();
    DerSignatureExamples.Run();
    SignatureNormalizationExamples.Run();
    SchnorrSignatureExamples.Run();
    EcdhExamples.Run();
    KeyTweakingExamples.Run();
    HashingExamples.Run();
    AdvancedUsageExamples.Run();
    MuSig2Examples.Run();

    Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
    Console.WriteLine("║           All examples completed successfully!               ║");
    Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
}

static void RunSelectedExample(string section)
{
    switch (section)
    {
        case "keys":
        case "keygen":
        case "key-generation":
            KeyGenerationExamples.Run();
            break;
        case "pubkey":
        case "public-key":
        case "public-key-operations":
            PublicKeyOperationsExamples.Run();
            break;
        case "ecdsa":
        case "sign":
        case "signing":
            EcdsaSigningExamples.Run();
            break;
        case "der":
        case "der-signature":
            DerSignatureExamples.Run();
            break;
        case "normalize":
        case "normalization":
        case "signature-normalization":
            SignatureNormalizationExamples.Run();
            break;
        case "schnorr":
        case "schnorr-signature":
            SchnorrSignatureExamples.Run();
            break;
        case "ecdh":
        case "shared-secret":
            EcdhExamples.Run();
            break;
        case "tweak":
        case "tweaking":
        case "key-tweaking":
        case "bip32":
            KeyTweakingExamples.Run();
            break;
        case "hash":
        case "hashing":
        case "tagged-hash":
            HashingExamples.Run();
            break;
        case "advanced":
        case "instance":
        case "low-level":
            AdvancedUsageExamples.Run();
            break;
        case "musig":
        case "musig2":
        case "multi-sig":
        case "multisig":
            MuSig2Examples.Run();
            break;
        case "all":
            RunAllExamples();
            break;
        default:
            Console.WriteLine($"Unknown section: {section}");
            Console.WriteLine();
            PrintUsage();
            break;
    }
}

static void PrintUsage()
{
    Console.WriteLine("Usage: dotnet run [section]");
    Console.WriteLine();
    Console.WriteLine("Available sections:");
    Console.WriteLine("  keys, keygen, key-generation     - Key Generation & Validation");
    Console.WriteLine("  pubkey, public-key               - Public Key Operations");
    Console.WriteLine("  ecdsa, sign, signing             - ECDSA Signing & Verification");
    Console.WriteLine("  der, der-signature               - DER Signature Format");
    Console.WriteLine("  normalize, normalization         - Signature Normalization");
    Console.WriteLine("  schnorr, schnorr-signature       - Schnorr Signatures (BIP-340)");
    Console.WriteLine("  ecdh, shared-secret              - ECDH Key Agreement");
    Console.WriteLine("  tweak, tweaking, bip32           - Key Tweaking (BIP-32 HD Wallets)");
    Console.WriteLine("  hash, hashing, tagged-hash       - Hashing");
    Console.WriteLine("  advanced, instance, low-level    - Advanced Usage (Instance Methods)");
    Console.WriteLine("  musig, musig2, multisig          - MuSig2 Multi-Signatures");
    Console.WriteLine("  all                              - Run all examples (default)");
    Console.WriteLine();
    Console.WriteLine("Example: dotnet run schnorr");
}
