using System;
using System.Linq;

namespace Secp256k1Net.Bench
{
    // Validation methods for Secp256k1Benchmarks (partial class)
    public partial class Secp256k1Benchmarks
    {
        private void ValidateResults()
        {
            // Validate PubKeyCreate: all libraries should produce the same compressed public key
            ValidateAllMatch("PubKeyCreate",
            [
                ("Secp256k1Net", PubKeyCreate_Secp256k1Net()),
                ("NBitcoin", PubKeyCreate_NBitcoin()),
                ("Nethereum", PubKeyCreate_Nethereum()),
                ("BouncyCastle", PubKeyCreate_BouncyCastle()),
                ("StarkBank", PubKeyCreate_StarkBank()),
                ("Chainers", PubKeyCreate_Chainers()),
            ], inputs.KeyPair.PublicKeyCompressed);

            // Validate ECDSA Sign: all libraries should produce signatures that verify
            ValidateEcdsaSignatures();

            // Validate ECDH: all libraries return SHA256(compressed_point)
            ValidateAllMatch("Ecdh",
            [
                ("Secp256k1Net", Ecdh_Secp256k1Net()),
                ("NBitcoin", Ecdh_NBitcoin()),
                ("Nethereum", Ecdh_Nethereum()),
                ("BouncyCastle", Ecdh_BouncyCastle()),
            ]);

            // Validate EcdsaRecover: recovered public key should match original
            ValidateAllMatch("EcdsaRecover",
            [
                ("Secp256k1Net", EcdsaRecover_Secp256k1Net()),
                ("NBitcoin", EcdsaRecover_NBitcoin()),
                ("Nethereum", EcdsaRecover_Nethereum()),
                ("BouncyCastle", EcdsaRecover_BouncyCastle()),
            ], inputs.KeyPair.PublicKeyCompressed);

            // Validate Schnorr: signatures use random aux data so won't match,
            // but each signature must verify correctly with the same verifier
            ValidateSchnorrSignatures();
        }

        private void ValidateEcdsaSignatures()
        {
            // Verify that each library's ECDSA signature can be verified by Secp256k1Net
            // All libraries now hash MsgBytes internally, so signatures are compatible
            var signatures = new[]
            {
                ("Secp256k1Net", EcdsaSign_Secp256k1Net()),
                ("NBitcoin", EcdsaSign_NBitcoin()),
                ("Nethereum", EcdsaSign_Nethereum()),
                ("BouncyCastle", EcdsaSign_BouncyCastle()),
                ("Chainers", EcdsaSign_Chainers()),
                ("StarkBank", EcdsaSign_StarkBank()),
            };

            foreach (var (name, compactSig) in signatures)
            {
                if (!Secp256k1.Verify(compactSig, inputs.Msg.MsgHash, inputs.KeyPair.PublicKeyCompressed))
                    throw new Exception($"EcdsaSign validation failed: {name} signature did not verify");
            }
        }

        private void ValidateSchnorrSignatures()
        {
            // Schnorr signatures use random aux data, so signatures won't match between libraries.
            // Instead, verify that each library's signature can be verified by Secp256k1Net.
            var signatures = new[]
            {
                ("Secp256k1Net", SchnorrSign_Secp256k1Net()),
                ("NBitcoin", SchnorrSign_NBitcoin()),
            };

            foreach (var (name, sig) in signatures)
            {
                if (!Secp256k1.VerifySchnorr(sig, inputs.Msg.MsgHash, xOnlyPubKey))
                {
                    throw new Exception($"SchnorrSign validation failed: {name} signature did not verify");
                }
            }
        }

        private static void ValidateAllMatch(string category, (string name, byte[] value)[] results, byte[] expected = null)
        {
            var reference = expected ?? results[0].value;
            var referenceName = expected != null ? "expected" : results[0].name;

            foreach (var (name, value) in results)
            {
                if (!value.SequenceEqual(reference))
                {
                    throw new Exception(
                        $"{category} mismatch: {name} produced {Convert.ToHexString(value)} " +
                        $"but {referenceName} produced {Convert.ToHexString(reference)}");
                }
            }
        }
    }
}
