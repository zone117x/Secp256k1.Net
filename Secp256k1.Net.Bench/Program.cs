using System;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Jobs;
using SHA256 = System.Security.Cryptography.SHA256;

namespace Secp256k1Net.Bench
{
    [SimpleJob(RuntimeMoniker.HostProcess)]
    public class EcdsaSignVerify
    {
        private readonly byte[] privKey;
        private readonly string msg;
        private readonly byte[] msgBytes;
        
        public EcdsaSignVerify()
        {
            var privateKey = "97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a";
            privKey = System.Convert.FromHexString(privateKey);

            msg = "Message for signing";
            msgBytes = Encoding.UTF8.GetBytes(msg);
        }

        [Benchmark(Baseline = true)]
        public object Secp256k1Net()
        {
            var msgHash = SHA256.HashData(msgBytes);
            using var secp256k1 = new Secp256k1();
            var sig = new byte[Secp256k1.SIGNATURE_LENGTH];
            if (!secp256k1.Sign(sig, msgHash, privKey))
            {
                throw new Exception();
            }
            var serializedSig = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            if (!secp256k1.SignatureSerializeCompact(serializedSig, sig))
            {
                throw new Exception();
            }
            return serializedSig;
        }

        [Benchmark]
        public object Nbitcoin()
        {
            var msgHash = SHA256.HashData(msgBytes);
            var ecPrivKey = NBitcoin.Secp256k1.ECPrivKey.Create(privKey);
            var sig = ecPrivKey.SignECDSARFC6979(msgHash);
            return sig;
        }
        
        [Benchmark]
        public object Nethereum()
        {
            var msgHash = SHA256.HashData(msgBytes);
            var ecPrivKey = new Nethereum.Signer.EthECKey(privKey, true);
            var sig = ecPrivKey.Sign(msgHash);
            return sig;
        }

        [Benchmark]
        public object BouncyCastle()
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var d = new Org.BouncyCastle.Math.BigInteger(1, privKey);
            var keyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters(d, domain);
            var signer = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner(new Org.BouncyCastle.Crypto.Signers.HMacDsaKCalculator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest()));
            signer.Init(true, keyParameters);
            var signature = signer.GenerateSignature(msgBytes);
            return signature;
        }

        [Benchmark]
        public object Chainers()
        {
            var msgHash = SHA256.HashData(msgBytes);
            var sig = Cryptography.ECDSA.Secp256K1Manager.SignCompressedCompact(msgHash, privKey);
            return sig;
        }

        [Benchmark]
        public object StarkBank()
        {
            var privateKey = EllipticCurve.PrivateKey.fromString(privKey);
            var sig = EllipticCurve.Ecdsa.sign(msg, privateKey);
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