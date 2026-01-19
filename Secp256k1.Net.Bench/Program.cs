using System;
using System.Linq;
using System.Numerics;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;

namespace Secp256k1Net.Bench
{
    [Config(typeof(CiBenchmarkConfig))]
    [CsvMeasurementsExporter]
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    [CategoriesColumn]
    public partial class Secp256k1Benchmarks
    {
        private readonly BenchInputs inputs = new();
        private readonly byte[] auxRand = new byte[32]; // Zero aux randomness for deterministic Schnorr benchmark
        private byte[] schnorrSig;
        private byte[] xOnlyPubKey;

        [GlobalSetup]
        public void Setup()
        {
            // Pre-compute a Schnorr signature for verification benchmarks
            using var secp256k1 = new Secp256k1();
            var keypair = new byte[96];
            if (!secp256k1.KeypairCreate(keypair, inputs.KeyPair.PrivateKey))
                throw new Exception();
            schnorrSig = new byte[64];
            if (!secp256k1.SchnorrsigSign32(schnorrSig, inputs.Msg.MsgHash, keypair, auxRand))
                throw new Exception();
            xOnlyPubKey = new byte[64];
            if (!secp256k1.KeypairXonlyPub(xOnlyPubKey, out _, keypair))
                throw new Exception();

            ValidateResults();
        }

        // ===== ECDSA Sign =====
        // All benchmarks hash MsgBytes internally for fair comparison.
        // StarkBank only supports string input, but since it hashes with SHA256 internally,
        // its signatures are compatible (just need low-S normalization for verification).
        [BenchmarkCategory("EcdsaSign"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public byte[] EcdsaSign_Secp256k1Net()
        {
            using var secp256k1 = new Secp256k1();
            Span<byte> msgHash = stackalloc byte[32];
            System.Security.Cryptography.SHA256.HashData(inputs.Msg.MsgBytes, msgHash);
            Span<byte> sig = stackalloc byte[Secp256k1.SIGNATURE_LENGTH];
            if (!secp256k1.EcdsaSign(sig, msgHash, inputs.KeyPair.PrivateKey))
                throw new Exception();
            var serializedSig = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            if (!secp256k1.EcdsaSignatureSerializeCompact(serializedSig, sig))
                throw new Exception();
            return serializedSig;
        }

        [BenchmarkCategory("EcdsaSign"), Benchmark(Description = "NBitcoin")]
        public byte[] EcdsaSign_NBitcoin()
        {
            var msgHash = System.Security.Cryptography.SHA256.HashData(inputs.Msg.MsgBytes);
            var ecPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(inputs.KeyPair.PrivateKey);
            var sig = ecPrivKey.SignECDSARFC6979(msgHash);
            var serializedSig = new byte[64];
            sig.WriteCompactToSpan(serializedSig);
            return serializedSig;
        }

        [BenchmarkCategory("EcdsaSign"), Benchmark(Description = "Nethereum")]
        public byte[] EcdsaSign_Nethereum()
        {
            var msgHash = System.Security.Cryptography.SHA256.HashData(inputs.Msg.MsgBytes);
            var ecPrivKey = new Nethereum.Signer.EthECKey(inputs.KeyPair.PrivateKey, isPrivate: true);
            var sig = ecPrivKey.Sign(msgHash);
            var serializedSig = new byte[64];
            sig.R.CopyTo(serializedSig, 32 - sig.R.Length);
            sig.S.CopyTo(serializedSig, 64 - sig.S.Length);
            return serializedSig;
        }

        [BenchmarkCategory("EcdsaSign"), Benchmark(Description = "BouncyCastle")]
        public byte[] EcdsaSign_BouncyCastle()
        {
            var msgHash = System.Security.Cryptography.SHA256.HashData(inputs.Msg.MsgBytes);
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var d = new Org.BouncyCastle.Math.BigInteger(1, inputs.KeyPair.PrivateKey);
            var keyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters(d, domain);
            var signer = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner();
            signer.Init(true, keyParameters);
            var signature = signer.GenerateSignature(msgHash);
            var r = signature[0];
            var s = signature[1];
            // Normalize to low-S (required by libsecp256k1)
            var halfN = domain.N.ShiftRight(1);
            if (s.CompareTo(halfN) > 0)
                s = domain.N.Subtract(s);
            var rBytes = r.ToByteArrayUnsigned();
            var sBytes = s.ToByteArrayUnsigned();
            var serializedSig = new byte[64];
            rBytes.CopyTo(serializedSig, 32 - rBytes.Length);
            sBytes.CopyTo(serializedSig, 64 - sBytes.Length);
            return serializedSig;
        }

        [BenchmarkCategory("EcdsaSign"), Benchmark(Description = "StarkBank")]
        public byte[] EcdsaSign_StarkBank()
        {
            // StarkBank hashes internally using SHA256, so pass MsgString directly
            var privateKey = EllipticCurve.PrivateKey.fromString(inputs.KeyPair.PrivateKey);
            var sig = EllipticCurve.Ecdsa.sign(inputs.Msg.MsgString, privateKey);
            var r = sig.r.ToByteArray(isUnsigned: true, isBigEndian: true);
            var serializedSig = new byte[64];
            r.CopyTo(serializedSig, 32 - r.Length);

            // Normalize to low-S (StarkBank doesn't do this)
            var s = sig.s > StarkBankHelper.HalfN ? StarkBankHelper.CurveN - sig.s : sig.s;
            var sBytes = s.ToByteArray(isUnsigned: true, isBigEndian: true);
            sBytes.CopyTo(serializedSig, 64 - sBytes.Length);
            return serializedSig;
        }

        [BenchmarkCategory("EcdsaSign"), Benchmark(Description = "Chainers")]
        public byte[] EcdsaSign_Chainers()
        {
            var msgHash = System.Security.Cryptography.SHA256.HashData(inputs.Msg.MsgBytes);
            // SignCompressedCompact returns 65 bytes (1 byte header + 32 R + 32 S)
            var fullSig = Cryptography.ECDSA.Secp256K1Manager.SignCompressedCompact(msgHash, inputs.KeyPair.PrivateKey);
            var serializedSig = new byte[64];
            Array.Copy(fullSig, 1, serializedSig, 0, 64);
            return serializedSig;
        }

        // ===== ECDSA Verify =====
        [BenchmarkCategory("EcdsaVerify"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public void EcdsaVerify_Secp256k1Net()
        {
            using var secp256k1 = new Secp256k1();
            Span<byte> parsedSig = stackalloc byte[Secp256k1.SIGNATURE_LENGTH];
            if (!secp256k1.EcdsaSignatureParseCompact(parsedSig, inputs.EcdsaSig))
                throw new Exception();
            Span<byte> parsedPubKey = stackalloc byte[Secp256k1.PUBKEY_LENGTH];
            if (!secp256k1.EcPubkeyParse(parsedPubKey, inputs.KeyPair.PublicKeyCompressed))
                throw new Exception();
            if (!secp256k1.EcdsaVerify(parsedSig, inputs.Msg.MsgHash, parsedPubKey))
                throw new Exception();
        }

        [BenchmarkCategory("EcdsaVerify"), Benchmark(Description = "NBitcoin")]
        public void EcdsaVerify_NBitcoin()
        {
            if (!NBitcoin.Secp256k1.SecpECDSASignature.TryCreateFromCompact(inputs.EcdsaSig, out var parsedSig))
                throw new Exception();
            var ecPubKey = NBitcoin.Secp256k1.ECPubKey.Create(inputs.KeyPair.PublicKeyCompressed);
            if (!ecPubKey.SigVerify(parsedSig, inputs.Msg.MsgHash))
                throw new Exception();
        }

        [BenchmarkCategory("EcdsaVerify"), Benchmark(Description = "Nethereum")]
        public void EcdsaVerify_Nethereum()
        {
            var parsedSig = Nethereum.Signer.EthECDSASignatureFactory.FromComponents(inputs.EcdsaSig);
            var pubKey = new Nethereum.Signer.EthECKey(inputs.KeyPair.PublicKeyCompressed, isPrivate: false);
            if (!pubKey.Verify(inputs.Msg.MsgHash, parsedSig))
                throw new Exception();
        }

        [BenchmarkCategory("EcdsaVerify"), Benchmark(Description = "BouncyCastle")]
        public void EcdsaVerify_BouncyCastle()
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var q = curve.Curve.DecodePoint(inputs.KeyPair.PublicKeyCompressed);
            var keyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(q, domain);
            var verifier = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner();
            verifier.Init(false, keyParameters);
            var rp = new Org.BouncyCastle.Math.BigInteger(1, inputs.EcdsaSig.Take(32).ToArray());
            var sp = new Org.BouncyCastle.Math.BigInteger(1, inputs.EcdsaSig.Skip(32).ToArray());
            if (!verifier.VerifySignature(inputs.Msg.MsgHash, rp, sp))
                throw new Exception();
        }

        [BenchmarkCategory("EcdsaVerify"), Benchmark(Description = "StarkBank")]
        public void EcdsaVerify_StarkBank()
        {
            var r = new BigInteger(inputs.EcdsaSig.Take(32).ToArray(), isUnsigned: true, isBigEndian: true);
            var s = new BigInteger(inputs.EcdsaSig.Skip(32).ToArray(), isUnsigned: true, isBigEndian: true);
            var parsedSig = new EllipticCurve.Signature(r, s);
            var pubKey = EllipticCurve.PublicKey.fromString(inputs.KeyPair.PublicKeyUncompressed.Skip(1).ToArray());
            if (!EllipticCurve.Ecdsa.verify(inputs.Msg.MsgString, parsedSig, pubKey))
                throw new Exception();
        }

        // ===== Public Key Creation =====
        [BenchmarkCategory("PubKeyCreate"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public byte[] PubKeyCreate_Secp256k1Net()
        {
            using var secp256k1 = new Secp256k1();
            Span<byte> pubKey = stackalloc byte[Secp256k1.PUBKEY_LENGTH];
            if (!secp256k1.EcPubkeyCreate(pubKey, inputs.KeyPair.PrivateKey))
                throw new Exception();
            // Serialize to compressed format for fair comparison
            var compressed = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
            nuint outputLen = (nuint)compressed.Length;
            if (!secp256k1.EcPubkeySerialize(compressed, ref outputLen, pubKey, Secp256k1EcFlags.Compressed))
                throw new Exception();
            return compressed;
        }

        [BenchmarkCategory("PubKeyCreate"), Benchmark(Description = "NBitcoin")]
        public byte[] PubKeyCreate_NBitcoin()
        {
            var ecPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(inputs.KeyPair.PrivateKey);
            var pubKey = ecPrivKey.CreatePubKey();
            return pubKey.ToBytes(true);
        }

        [BenchmarkCategory("PubKeyCreate"), Benchmark(Description = "Nethereum")]
        public byte[] PubKeyCreate_Nethereum()
        {
            var ecKey = new Nethereum.Signer.EthECKey(inputs.KeyPair.PrivateKey, isPrivate: true);
            return ecKey.GetPubKey(true);
        }

        [BenchmarkCategory("PubKeyCreate"), Benchmark(Description = "BouncyCastle")]
        public byte[] PubKeyCreate_BouncyCastle()
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var d = new Org.BouncyCastle.Math.BigInteger(1, inputs.KeyPair.PrivateKey);
            var q = curve.G.Multiply(d);
            return q.GetEncoded(true);
        }

        [BenchmarkCategory("PubKeyCreate"), Benchmark(Description = "StarkBank")]
        public byte[] PubKeyCreate_StarkBank()
        {
            var privateKey = EllipticCurve.PrivateKey.fromString(inputs.KeyPair.PrivateKey);
            var pubKey = privateKey.publicKey();
            // StarkBank doesn't have a toCompressed() method, so manually compress
            var x = pubKey.point.x.ToByteArray(isUnsigned: true, isBigEndian: true);
            var y = pubKey.point.y;
            var result = new byte[33];
            result[0] = (byte)(y.IsEven ? 0x02 : 0x03);
            x.CopyTo(result, 33 - x.Length);
            return result;
        }

        [BenchmarkCategory("PubKeyCreate"), Benchmark(Description = "Chainers")]
        public byte[] PubKeyCreate_Chainers()
        {
            return Cryptography.ECDSA.Secp256K1Manager.GetPublicKey(inputs.KeyPair.PrivateKey, true);
        }

        // ===== ECDH =====
        // All benchmarks return SHA256(compressed_point) for fair comparison
        [BenchmarkCategory("Ecdh"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public byte[] Ecdh_Secp256k1Net()
        {
            using var secp256k1 = new Secp256k1();
            Span<byte> parsedPubKey = stackalloc byte[Secp256k1.PUBKEY_LENGTH];
            if (!secp256k1.EcPubkeyParse(parsedPubKey, inputs.AlicePubKeyCompressed))
                throw new Exception();
            var output = new byte[32];
            // Default Ecdh returns SHA256(compressed_point)
            if (!secp256k1.Ecdh(output, parsedPubKey, inputs.KeyPair.PrivateKey))
                throw new Exception();
            return output;
        }

        [BenchmarkCategory("Ecdh"), Benchmark(Description = "NBitcoin")]
        public byte[] Ecdh_NBitcoin()
        {
            var bobPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(inputs.KeyPair.PrivateKey);
            var alicePubKey = NBitcoin.Secp256k1.ECPubKey.Create(inputs.AlicePubKeyCompressed);
            var sharedPubKey = alicePubKey.GetSharedPubkey(bobPrivKey);
            // Get compressed point and hash it
            var compressed = sharedPubKey.ToBytes(true);
            return System.Security.Cryptography.SHA256.HashData(compressed);
        }

        [BenchmarkCategory("Ecdh"), Benchmark(Description = "Nethereum")]
        public byte[] Ecdh_Nethereum()
        {
            // Nethereum's CalculateCommonSecret returns only x-coordinate (32 bytes)
            var ecKey = new Nethereum.Signer.EthECKey(inputs.KeyPair.PrivateKey, isPrivate: true);
            var aliceKey = new Nethereum.Signer.EthECKey(inputs.AlicePubKeyCompressed, isPrivate: false);
            var xCoord = ecKey.CalculateCommonSecret(aliceKey);

            // Reconstruct compressed point (0x02 prefix = even y, correct for our test inputs)
            var compressed = new byte[33];
            compressed[0] = 0x02;
            xCoord.CopyTo(compressed, 1);

            return System.Security.Cryptography.SHA256.HashData(compressed);
        }

        [BenchmarkCategory("Ecdh"), Benchmark(Description = "BouncyCastle")]
        public byte[] Ecdh_BouncyCastle()
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var bobD = new Org.BouncyCastle.Math.BigInteger(1, inputs.KeyPair.PrivateKey);
            var aliceQ = curve.Curve.DecodePoint(inputs.AlicePubKeyCompressed);
            // Compute shared point directly: sharedPoint = aliceQ * bobD
            var sharedPoint = aliceQ.Multiply(bobD).Normalize();
            var compressed = sharedPoint.GetEncoded(true);
            return System.Security.Cryptography.SHA256.HashData(compressed);
        }

        // ===== Recoverable Sign =====
        [BenchmarkCategory("EcdsaSignRecoverable"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public byte[] EcdsaSignRecoverable_Secp256k1Net()
        {
            using var secp256k1 = new Secp256k1();
            Span<byte> sig = stackalloc byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            if (!secp256k1.EcdsaSignRecoverable(sig, inputs.Msg.MsgHash, inputs.KeyPair.PrivateKey))
                throw new Exception();
            // Serialize to compact format for fair comparison
            Span<byte> output = stackalloc byte[64];
            if (!secp256k1.EcdsaRecoverableSignatureSerializeCompact(output, out var recId, sig))
                throw new Exception();
            var result = new byte[65];
            output.CopyTo(result);
            result[64] = (byte)recId;
            return result;
        }

        [BenchmarkCategory("EcdsaSignRecoverable"), Benchmark(Description = "NBitcoin")]
        public byte[] EcdsaSignRecoverable_NBitcoin()
        {
            var ecPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(inputs.KeyPair.PrivateKey);
            if (!ecPrivKey.TrySignRecoverable(inputs.Msg.MsgHash, out var sig))
                throw new Exception();
            var output = new byte[65];
            sig.WriteToSpanCompact(output.AsSpan(0, 64), out var recId);
            output[64] = (byte)recId;
            return output;
        }

        [BenchmarkCategory("EcdsaSignRecoverable"), Benchmark(Description = "Nethereum")]
        public byte[] EcdsaSignRecoverable_Nethereum()
        {
            var ecKey = new Nethereum.Signer.EthECKey(inputs.KeyPair.PrivateKey, isPrivate: true);
            var sig = ecKey.SignAndCalculateV(inputs.Msg.MsgHash);
            var output = new byte[65];
            sig.R.CopyTo(output, 32 - sig.R.Length);
            sig.S.CopyTo(output, 64 - sig.S.Length);
            output[64] = (byte)(sig.V.Length > 0 ? sig.V[0] : 0);
            return output;
        }

        [BenchmarkCategory("EcdsaSignRecoverable"), Benchmark(Description = "BouncyCastle")]
        public byte[] EcdsaSignRecoverable_BouncyCastle()
        {
            var (r, s, recId, _, _) = BouncyCastleRecoveryHelper.SignRecoverable(inputs.KeyPair.PrivateKey, inputs.Msg.MsgHash);
            var output = new byte[65];
            var rBytes = r.ToByteArrayUnsigned();
            var sBytes = s.ToByteArrayUnsigned();
            rBytes.CopyTo(output, 32 - rBytes.Length);
            sBytes.CopyTo(output, 64 - sBytes.Length);
            output[64] = (byte)recId;
            return output;
        }

        // ===== Public Key Recovery =====
        [BenchmarkCategory("EcdsaRecover"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public byte[] EcdsaRecover_Secp256k1Net()
        {
            using var secp256k1 = new Secp256k1();
            Span<byte> recSig = stackalloc byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            if (!secp256k1.EcdsaSignRecoverable(recSig, inputs.Msg.MsgHash, inputs.KeyPair.PrivateKey))
                throw new Exception();
            Span<byte> pubKey = stackalloc byte[Secp256k1.PUBKEY_LENGTH];
            if (!secp256k1.EcdsaRecover(pubKey, recSig, inputs.Msg.MsgHash))
                throw new Exception();
            // Serialize to compressed format for fair comparison
            var compressed = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
            nuint outputLen = (nuint)compressed.Length;
            if (!secp256k1.EcPubkeySerialize(compressed, ref outputLen, pubKey, Secp256k1EcFlags.Compressed))
                throw new Exception();
            return compressed;
        }

        [BenchmarkCategory("EcdsaRecover"), Benchmark(Description = "NBitcoin")]
        public byte[] EcdsaRecover_NBitcoin()
        {
            var ecPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(inputs.KeyPair.PrivateKey);
            if (!ecPrivKey.TrySignRecoverable(inputs.Msg.MsgHash, out var recSig))
                throw new Exception();
            if (!NBitcoin.Secp256k1.ECPubKey.TryRecover(
                NBitcoin.Secp256k1.Context.Instance, recSig, inputs.Msg.MsgHash, out var pubKey))
                throw new Exception();
            return pubKey.ToBytes(true);
        }

        [BenchmarkCategory("EcdsaRecover"), Benchmark(Description = "Nethereum")]
        public byte[] EcdsaRecover_Nethereum()
        {
            var ecKey = new Nethereum.Signer.EthECKey(inputs.KeyPair.PrivateKey, isPrivate: true);
            var sig = ecKey.SignAndCalculateV(inputs.Msg.MsgHash);
            var recoveredKey = Nethereum.Signer.EthECKey.RecoverFromSignature(sig, inputs.Msg.MsgHash);
            return recoveredKey.GetPubKey(true);
        }

        [BenchmarkCategory("EcdsaRecover"), Benchmark(Description = "BouncyCastle")]
        public byte[] EcdsaRecover_BouncyCastle()
        {
            var (r, s, recId, curve, domain) = BouncyCastleRecoveryHelper.SignRecoverable(inputs.KeyPair.PrivateKey, inputs.Msg.MsgHash);
            var e = new Org.BouncyCastle.Math.BigInteger(1, inputs.Msg.MsgHash);
            var recovered = BouncyCastleRecoveryHelper.RecoverPublicKey(curve, domain, e, r, s, recId);
            return recovered.GetEncoded(true);
        }

        // ===== Schnorr Sign =====
        [BenchmarkCategory("SchnorrSign"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public byte[] SchnorrSign_Secp256k1Net()
        {
            using var secp256k1 = new Secp256k1();
            Span<byte> keypair = stackalloc byte[96];
            if (!secp256k1.KeypairCreate(keypair, inputs.KeyPair.PrivateKey))
                throw new Exception();
            var sig = new byte[64];
            if (!secp256k1.SchnorrsigSign32(sig, inputs.Msg.MsgHash, keypair, auxRand))
                throw new Exception();
            return sig;
        }

        [BenchmarkCategory("SchnorrSign"), Benchmark(Description = "NBitcoin")]
        public byte[] SchnorrSign_NBitcoin()
        {
            var ecPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(inputs.KeyPair.PrivateKey);
            var sig = ecPrivKey.SignBIP340(inputs.Msg.MsgHash);
            return sig.ToBytes();
        }

        // ===== Schnorr Verify =====
        [BenchmarkCategory("SchnorrVerify"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public bool SchnorrVerify_Secp256k1Net()
        {
            using var secp256k1 = new Secp256k1();
            return secp256k1.SchnorrsigVerify(schnorrSig, inputs.Msg.MsgHash, xOnlyPubKey);
        }

        [BenchmarkCategory("SchnorrVerify"), Benchmark(Description = "NBitcoin")]
        public bool SchnorrVerify_NBitcoin()
        {
            var ecPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(inputs.KeyPair.PrivateKey);
            var xOnlyPub = ecPrivKey.CreateXOnlyPubKey();
            if (!NBitcoin.Secp256k1.SecpSchnorrSignature.TryCreate(schnorrSig, out var sig))
                throw new Exception();
            return xOnlyPub.SigVerifyBIP340(sig, inputs.Msg.MsgHash);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            // Support --validate flag as shortcut for VALIDATE=true
            if (args.Length > 0 && args[0] == "--validate")
            {
                Environment.SetEnvironmentVariable("VALIDATE", "true");
            }

            BenchmarkRunner.Run<Secp256k1Benchmarks>();
            Console.WriteLine("Benchmarks done");
        }
    }
}
