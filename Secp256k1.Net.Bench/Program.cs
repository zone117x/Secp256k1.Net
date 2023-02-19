using System;
using System.Text;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Configs;

namespace Secp256k1Net.Bench
{
    record class KeyPair(byte[] PrivateKey, byte[] PublicKeyCompressed, byte[] PublicKeyUncompressed);
    record class Msg(string MsgString, byte[] MsgBytes, byte[] MsgHash);

    class BenchInputs
    {
        public readonly KeyPair KeyPair;
        public readonly Msg Msg;
        public readonly byte[] EcdsaSig;

        public BenchInputs()
        {
            KeyPair = new(
                Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe"),
                Convert.FromHexString("03bf2e2462a3e64b941187b903156dbe9fb9b09b1e76ff5a55edf3d441dcd50822"),
                Convert.FromHexString("04bf2e2462a3e64b941187b903156dbe9fb9b09b1e76ff5a55edf3d441dcd508227f20aebd43fb7de880b28ea03baae531c05f17d2f99940aa6a3fe1a4c788c7a1")
            );

            var msg = "Message for signing";
            var msgBytes = Encoding.UTF8.GetBytes(msg);
            var msgHash = SHA256.HashData(msgBytes);
            Msg = new(msg, msgBytes, msgHash);

            // 32-byte big endian R value, followed by a 32-byte big endian S value
            EcdsaSig = Convert.FromHexString("8748f4a24fd0ecca9100ef947b73cbb6f11d67d151d2a900ab9fec1dce0051cc687136810ad4aba6812ad39cea0a41ba2cb04cb32d574a443f0d5c03e2dfa44f");
        }
    }

    [CsvMeasurementsExporter]
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    [CategoriesColumn]
    public class EcdsaSignVerify
    {
        private readonly BenchInputs inputs = new BenchInputs();

        [BenchmarkCategory("Sign"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public byte[] Secp256k1NetSign()
        {
            return Secp256k1NetUtil.Sign(inputs.KeyPair, inputs.Msg);
        }

        [BenchmarkCategory("Sign"), Benchmark(Description = "NBitcoin")]
        public byte[] NBitcoinSign()
        {
            return NBitcoinUtil.Sign(inputs.KeyPair, inputs.Msg);
        }

        [BenchmarkCategory("Sign"), Benchmark(Description = "Nethereum")]
        public byte[] NethereumSign()
        {
            return NethereumUtil.Sign(inputs.KeyPair, inputs.Msg);
        }

        [BenchmarkCategory("Sign"), Benchmark(Description = "BouncyCastle")]
        public byte[] BouncyCastleSign()
        {
            return BouncyCastleUtil.Sign(inputs.KeyPair, inputs.Msg);
        }

        [BenchmarkCategory("Sign"), Benchmark(Description = "StarkBank")]
        public byte[] StarkBankSign()
        {
            return StarkBankUtil.Sign(inputs.KeyPair, inputs.Msg);
        }

        [BenchmarkCategory("Sign"), Benchmark(Description = "Chainers")]
        public byte[] ChainersSign()
        {
            return ChainersUtil.Sign(inputs.KeyPair, inputs.Msg);
        }

        [BenchmarkCategory("Verify"), Benchmark(Description = "Secp256k1Net", Baseline = true)]
        public void Secp256k1NetVerify()
        {
            Secp256k1NetUtil.Verify(inputs.KeyPair, inputs.Msg, inputs.EcdsaSig);
        }

        [BenchmarkCategory("Verify"), Benchmark(Description = "NBitcoin")]
        public void NBitcoinVerify()
        {
            NBitcoinUtil.Verify(inputs.KeyPair, inputs.Msg, inputs.EcdsaSig);
        }

        [BenchmarkCategory("Verify"), Benchmark(Description = "Nethereum")]
        public void NethereumVerify()
        {
            NethereumUtil.Verify(inputs.KeyPair, inputs.Msg, inputs.EcdsaSig);
        }

        [BenchmarkCategory("Verify"), Benchmark(Description = "BouncyCastle")]
        public void BouncyCastleVerify()
        {
            BouncyCastleUtil.Verify(inputs.KeyPair, inputs.Msg, inputs.EcdsaSig);
        }

        [BenchmarkCategory("Verify"), Benchmark(Description = "StarkBank")]
        public void StarkBankVerify()
        {
            StarkBankUtil.Verify(inputs.KeyPair, inputs.Msg, inputs.EcdsaSig);
        }
    }

    interface EcdsaSigner
    {
        static abstract byte[] Sign(KeyPair keyPair, Msg msg);
    }

    interface EcdsaVerifier
    {
        static abstract void Verify(KeyPair keyPair, Msg msg, byte[] signature);
    }

    class Secp256k1NetUtil : EcdsaSigner, EcdsaVerifier
    {
        public static byte[] Sign(KeyPair keyPair, Msg msg)
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[Secp256k1.SIGNATURE_LENGTH];
            if (!secp256k1.Sign(sig, msg.MsgHash, keyPair.PrivateKey))
                throw new Exception();
            var serializedSig = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            if (!secp256k1.SignatureSerializeCompact(serializedSig, sig))
                throw new Exception();
            return serializedSig;
        }

        public static void Verify(KeyPair keyPair, Msg msg, byte[] signature)
        {
            using var secp256k1 = new Secp256k1();
            var parsedSig = new byte[Secp256k1.SIGNATURE_LENGTH];
            if (!secp256k1.SignatureParseCompact(parsedSig, signature))
                throw new Exception();
            var parsedPubKey = new byte[Secp256k1.PUBKEY_LENGTH];
            if (!secp256k1.PublicKeyParse(parsedPubKey, keyPair.PublicKeyCompressed))
                throw new Exception();
            if (!secp256k1.Verify(parsedSig, msg.MsgHash, parsedPubKey))
                throw new Exception();
        }
    }

    class NBitcoinUtil : EcdsaSigner, EcdsaVerifier
    {
        public static byte[] Sign(KeyPair keyPair, Msg msg)
        {
            var ecPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(keyPair.PrivateKey);
            var sig = ecPrivKey.SignECDSARFC6979(msg.MsgHash);
            var serializedSig = new byte[64];
            sig.WriteCompactToSpan(serializedSig);
            return serializedSig;
        }

        public static void Verify(KeyPair keyPair, Msg msg, byte[] signature)
        {
            if (!NBitcoin.Secp256k1.SecpECDSASignature.TryCreateFromCompact(signature, out var parsedSig))
                throw new Exception("Failed to parse compact signature");
            var ecPubKey = NBitcoin.Secp256k1.ECPubKey.Create(keyPair.PublicKeyCompressed);
            if (!ecPubKey.SigVerify(parsedSig, msg.MsgHash))
                throw new Exception("Failed to verify signature");
        }
    }

    class NethereumUtil : EcdsaSigner, EcdsaVerifier
    {
        public static byte[] Sign(KeyPair keyPair, Msg msg)
        {
            var ecPrivKey = new Nethereum.Signer.EthECKey(keyPair.PrivateKey, isPrivate: true);
            var sig = ecPrivKey.Sign(msg.MsgHash);
            var serializedSig = sig.To64ByteArray();
            return serializedSig;
        }

        public static void Verify(KeyPair keyPair, Msg msg, byte[] signature)
        {
            var parsedSig = Nethereum.Signer.EthECDSASignatureFactory.FromComponents(signature);
            var pubKey = new Nethereum.Signer.EthECKey(keyPair.PublicKeyCompressed, isPrivate: false);
            if (!pubKey.Verify(msg.MsgHash, parsedSig))
                throw new Exception("Failed to verify signature");
        }
    }

    class BouncyCastleUtil : EcdsaSigner, EcdsaVerifier
    {
        public static byte[] Sign(KeyPair keyPair, Msg msg)
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var d = new Org.BouncyCastle.Math.BigInteger(1, keyPair.PrivateKey);
            var keyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters(d, domain);
            var signer = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner();
            signer.Init(true, keyParameters);
            var signature = signer.GenerateSignature(msg.MsgHash);
            var r = signature[0].ToByteArrayUnsigned();
            var s = signature[1].ToByteArrayUnsigned();
            var serializedSig = new byte[64];
            r.CopyTo(serializedSig, 32 - r.Length);
            s.CopyTo(serializedSig, 64 - s.Length);
            return serializedSig;
        }

        public static void Verify(KeyPair keyPair, Msg msg, byte[] signature)
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var q = curve.Curve.DecodePoint(keyPair.PublicKeyCompressed);
            var keyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(q, domain);
            var verifier = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner();
            verifier.Init(false, keyParameters);
            var rp = new Org.BouncyCastle.Math.BigInteger(1, signature.Take(32).ToArray());
            var sp = new Org.BouncyCastle.Math.BigInteger(1, signature.Skip(32).ToArray());
            if (!verifier.VerifySignature(msg.MsgHash, rp, sp))
                throw new Exception("Failed to verify signature");
        }
    }

    class StarkBankUtil : EcdsaSigner, EcdsaVerifier
    {
        public static byte[] Sign(KeyPair keyPair, Msg msg)
        {
            var privateKey = EllipticCurve.PrivateKey.fromString(keyPair.PrivateKey);
            var sig = EllipticCurve.Ecdsa.sign(msg.MsgString, privateKey);
            var r = sig.r.ToByteArray(isUnsigned: true, isBigEndian: true);
            var s = sig.s.ToByteArray(isUnsigned: true, isBigEndian: true);
            var serializedSig = new byte[64];
            r.CopyTo(serializedSig, 32 - r.Length);
            s.CopyTo(serializedSig, 64 - s.Length);
            return serializedSig;
        }

        public static void Verify(KeyPair keyPair, Msg msg, byte[] signature)
        {
            var r = new BigInteger(signature.Take(32).ToArray(), isUnsigned: true, isBigEndian: true);
            var s = new BigInteger(signature.Skip(32).ToArray(), isUnsigned: true, isBigEndian: true);
            var parsedSig = new EllipticCurve.Signature(r, s);
            var pubKey = EllipticCurve.PublicKey.fromString(keyPair.PublicKeyUncompressed.Skip(1).ToArray());
            if (!EllipticCurve.Ecdsa.verify(msg.MsgString, parsedSig, pubKey))
                throw new Exception("Failed to verify signature");
        }
    }

    class ChainersUtil : EcdsaSigner
    {
        public static byte[] Sign(KeyPair keyPair, Msg msg)
        {
            var sig = Cryptography.ECDSA.Secp256K1Manager.SignCompressedCompact(msg.MsgHash, keyPair.PrivateKey);
            return sig;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<EcdsaSignVerify>();
            Console.WriteLine("Benchmarks done");
        }
    }

}