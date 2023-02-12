using System;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Jobs;
using SHA256 = System.Security.Cryptography.SHA256;
using System.Linq;
using NethereumSigner = Nethereum.Signer;

namespace Secp256k1Net.Bench
{
    [CsvMeasurementsExporter]
    public class EcdsaSignVerify
    {
        private readonly string msg;
        private readonly byte[] msgBytes;
        private readonly (byte[] PrivateKey, byte[] PublicKeyCompressed, byte[] PublicKeyUncompressed) keyPair;
        
        public EcdsaSignVerify()
        {
            keyPair = (
                Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe"),
                Convert.FromHexString("03bf2e2462a3e64b941187b903156dbe9fb9b09b1e76ff5a55edf3d441dcd50822"),
                Convert.FromHexString("04bf2e2462a3e64b941187b903156dbe9fb9b09b1e76ff5a55edf3d441dcd508227f20aebd43fb7de880b28ea03baae531c05f17d2f99940aa6a3fe1a4c788c7a1")
            );
            msg = "Message for signing";
            msgBytes = Encoding.UTF8.GetBytes(msg);
        }

        public enum Feature
        {
            SignOnly,
            SignAndVerify,
        }

        [Benchmark(Baseline = true)]
        [Arguments(Feature.SignAndVerify)]
        [Arguments(Feature.SignOnly)]
        public object Secp256k1Net(Feature feature)
        {
            var msgHash = SHA256.HashData(msgBytes);
            using var secp256k1 = new Secp256k1();

            var sig = new byte[Secp256k1.SIGNATURE_LENGTH];
            if (!secp256k1.Sign(sig, msgHash, keyPair.PrivateKey))
                throw new Exception();
            var serializedSig = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            if (!secp256k1.SignatureSerializeCompact(serializedSig, sig))
                throw new Exception();

            if (feature == Feature.SignOnly)
                return serializedSig;

            if (!secp256k1.SignatureParseCompact(sig, serializedSig))
                throw new Exception();

            var parsedPubKey = new byte[Secp256k1.PUBKEY_LENGTH];
            if (!secp256k1.PublicKeyParse(parsedPubKey, keyPair.PublicKeyCompressed))
                throw new Exception();

            if (!secp256k1.Verify(sig, msgHash, parsedPubKey))
                throw new Exception();

            return serializedSig;
        }

        [Benchmark]
        [Arguments(Feature.SignAndVerify)]
        [Arguments(Feature.SignOnly)]
        public object Nbitcoin(Feature feature)
        {
            var msgHash = SHA256.HashData(msgBytes);
            var ctx = new NBitcoin.Secp256k1.Context();
            var ecPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(keyPair.PrivateKey, ctx);

            var sig = ecPrivKey.SignECDSARFC6979(msgHash);
            var serializedSig = new byte[64];
            sig.WriteCompactToSpan(serializedSig);

            if (feature == Feature.SignOnly)
                return serializedSig;

            if (!NBitcoin.Secp256k1.SecpECDSASignature.TryCreateFromCompact(serializedSig, out var parsedSig))
                throw new Exception("Failed to parse compact signature");

            var ecPubKey = NBitcoin.Secp256k1.ECPubKey.Create(keyPair.PublicKeyCompressed);
            if (!ecPubKey.SigVerify(parsedSig, msgHash))
                throw new Exception("Failed to verify signature");

            return serializedSig;
        }
        
        [Benchmark]
        [Arguments(Feature.SignAndVerify)]
        [Arguments(Feature.SignOnly)]
        public object Nethereum(Feature feature)
        {
            var msgHash = SHA256.HashData(msgBytes);
            var ecPrivKey = new NethereumSigner.EthECKey(keyPair.PrivateKey, isPrivate: true);
            var sig = ecPrivKey.Sign(msgHash);
            var serializedSig = sig.To64ByteArray();

            if (feature == Feature.SignOnly)
                return serializedSig;

            var parsedSig = NethereumSigner.EthECDSASignatureFactory.FromComponents(serializedSig);
            var pubKey = new NethereumSigner.EthECKey(keyPair.PublicKeyCompressed, isPrivate: false);
            if (!pubKey.Verify(msgHash, parsedSig))
                throw new Exception("Failed to verify signature");

            return serializedSig;
        }

        [Benchmark]
        [Arguments(Feature.SignAndVerify)]
        [Arguments(Feature.SignOnly)]
        public object BouncyCastle(Feature feature)
        {
            // https://stackoverflow.com/a/62414581/794962
            byte[] derSignature;
            {
                var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
                var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                var d = new Org.BouncyCastle.Math.BigInteger(1, keyPair.PrivateKey);
                var keyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters(d, domain);
                var signer = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner(new Org.BouncyCastle.Crypto.Signers.HMacDsaKCalculator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest()));
                signer.Init(true, keyParameters);
                var signature = signer.GenerateSignature(msgBytes);
                derSignature = new Org.BouncyCastle.Asn1.DerSequence
                (
                    new Org.BouncyCastle.Asn1.DerInteger(new Org.BouncyCastle.Math.BigInteger(1, signature[0].ToByteArray())),
                    new Org.BouncyCastle.Asn1.DerInteger(new Org.BouncyCastle.Math.BigInteger(1, signature[1].ToByteArray()))
                )
                .GetDerEncoded();
            }

            if (feature == Feature.SignOnly)
                return derSignature;

            {
                var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
                var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                var q = curve.Curve.DecodePoint(keyPair.PublicKeyCompressed);
                var keyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(q, domain);
                var verifier = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner();
                verifier.Init(false, keyParameters);

                using var decoder = new Org.BouncyCastle.Asn1.Asn1InputStream(derSignature);
                var seq = (Org.BouncyCastle.Asn1.DerSequence)decoder.ReadObject();
                var r = (Org.BouncyCastle.Asn1.DerInteger)seq[0];
                var s = (Org.BouncyCastle.Asn1.DerInteger)seq[1];
                var rp = r.PositiveValue;
                var sp = s.PositiveValue;

                if (!verifier.VerifySignature(msgBytes, rp, sp))
                {
                    throw new Exception("Failed to verify signature");
                }
            }
            return derSignature;
        }

        [Benchmark]
        [Arguments(Feature.SignOnly)]
        public object Chainers(Feature feature)
        {
            var msgHash = SHA256.HashData(msgBytes);
            var sig = Cryptography.ECDSA.Secp256K1Manager.SignCompressedCompact(msgHash, keyPair.PrivateKey);
            return sig;
        }

        [Benchmark]
        [Arguments(Feature.SignAndVerify)]
        [Arguments(Feature.SignOnly)]
        public object StarkBank(Feature feature)
        {
            var privateKey = EllipticCurve.PrivateKey.fromString(keyPair.PrivateKey);
            var sig = EllipticCurve.Ecdsa.sign(msg, privateKey);

            if (feature == Feature.SignOnly)
                return sig;

            var parsedSig = new EllipticCurve.Signature(r: sig.r, s: sig.s);
            var pubKey = EllipticCurve.PublicKey.fromString(keyPair.PublicKeyUncompressed.Skip(1).ToArray());
            if (!EllipticCurve.Ecdsa.verify(msg, parsedSig, pubKey))
                throw new Exception("Failed to verify signature");

            return sig;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<EcdsaSignVerify>();
            Console.WriteLine("Benchmarks done");
        }
    }

}