using System;
using System.Text;
using System.Security.Cryptography;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Configs;

namespace Secp256k1Net.Bench
{
    // Configures benchmark job based on execution mode:
    // - VALIDATE=true: Uses Job.Dry (1 launch, 1 warmup, 1 iteration) for quick validation
    // - CI=true: Uses Job.ShortRun for faster CI execution (fewer iterations, less accurate)
    // - Default: Uses Job.Default for accurate results
    public class CiBenchmarkConfig : ManualConfig
    {
        public CiBenchmarkConfig()
        {
            if (Environment.GetEnvironmentVariable("VALIDATE") == "true")
            {
                AddJob(Job.Dry);
            }
            else if (Environment.GetEnvironmentVariable("CI") == "true")
            {
                AddJob(Job.ShortRun);
            }
            else
            {
                AddJob(Job.Default);
            }
        }
    }

    record class KeyPair(byte[] PrivateKey, byte[] PublicKeyCompressed, byte[] PublicKeyUncompressed);
    record class Msg(string MsgString, byte[] MsgBytes, byte[] MsgHash);

    class BenchInputs
    {
        public readonly KeyPair KeyPair;
        public readonly Msg Msg;
        public readonly byte[] EcdsaSig;
        public readonly byte[] AlicePubKeyCompressed;

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

            // Second public key for ECDH (Alice's public key)
            AlicePubKeyCompressed = Convert.FromHexString("02c6b754b20826eb925e052ee2c25285b162b51fdca732bcf67e39d647fb6830ae");
        }
    }

    // Helper for StarkBank low-S normalization
    static class StarkBankHelper
    {
        // secp256k1 curve order N and halfN for low-S normalization
        public static readonly System.Numerics.BigInteger CurveN = new(
            Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
            isUnsigned: true, isBigEndian: true);
        public static readonly System.Numerics.BigInteger HalfN = CurveN >> 1;
    }

    // Helper for BouncyCastle ECDSA recovery operations
    static class BouncyCastleRecoveryHelper
    {
        public static (Org.BouncyCastle.Math.BigInteger r, Org.BouncyCastle.Math.BigInteger s, int recId,
            Org.BouncyCastle.Asn1.X9.X9ECParameters curve, Org.BouncyCastle.Crypto.Parameters.ECDomainParameters domain)
            SignRecoverable(byte[] privateKey, byte[] msgHash)
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var d = new Org.BouncyCastle.Math.BigInteger(1, privateKey);
            var keyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters(d, domain);
            var signer = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner();
            signer.Init(true, keyParameters);
            var signature = signer.GenerateSignature(msgHash);
            var r = signature[0];
            var s = signature[1];
            var pubKeyPoint = curve.G.Multiply(d).Normalize();
            var recId = CalculateRecId(curve, domain, msgHash, r, s, pubKeyPoint);
            return (r, s, recId, curve, domain);
        }

        public static int CalculateRecId(
            Org.BouncyCastle.Asn1.X9.X9ECParameters curve,
            Org.BouncyCastle.Crypto.Parameters.ECDomainParameters domain,
            byte[] msgHash,
            Org.BouncyCastle.Math.BigInteger r,
            Org.BouncyCastle.Math.BigInteger s,
            Org.BouncyCastle.Math.EC.ECPoint expectedPubKey)
        {
            var e = new Org.BouncyCastle.Math.BigInteger(1, msgHash);
            for (int recId = 0; recId < 4; recId++)
            {
                var recovered = RecoverPublicKey(curve, domain, e, r, s, recId);
                if (recovered != null && recovered.Equals(expectedPubKey))
                    return recId;
            }
            throw new Exception("Could not find recovery id");
        }

        public static Org.BouncyCastle.Math.EC.ECPoint RecoverPublicKey(
            Org.BouncyCastle.Asn1.X9.X9ECParameters curve,
            Org.BouncyCastle.Crypto.Parameters.ECDomainParameters domain,
            Org.BouncyCastle.Math.BigInteger e,
            Org.BouncyCastle.Math.BigInteger r,
            Org.BouncyCastle.Math.BigInteger s,
            int recId)
        {
            var n = domain.N;
            var i = Org.BouncyCastle.Math.BigInteger.ValueOf(recId / 2);
            var x = r.Add(i.Multiply(n));

            if (x.CompareTo(curve.Curve.Field.Characteristic) >= 0)
                return null;

            // Decompress point from x coordinate
            var R = DecompressPoint(curve, x, (recId & 1) == 1);
            if (R == null || !R.Multiply(n).IsInfinity)
                return null;

            var eInv = Org.BouncyCastle.Math.BigInteger.Zero.Subtract(e).Mod(n);
            var rInv = r.ModInverse(n);
            var srInv = rInv.Multiply(s).Mod(n);
            var eInvrInv = rInv.Multiply(eInv).Mod(n);

            var q = Org.BouncyCastle.Math.EC.ECAlgorithms.SumOfTwoMultiplies(curve.G, eInvrInv, R, srInv);
            return q.Normalize();
        }

        private static Org.BouncyCastle.Math.EC.ECPoint DecompressPoint(
            Org.BouncyCastle.Asn1.X9.X9ECParameters curve,
            Org.BouncyCastle.Math.BigInteger x,
            bool yOdd)
        {
            var compEnc = new byte[33];
            compEnc[0] = (byte)(yOdd ? 0x03 : 0x02);
            var xBytes = x.ToByteArrayUnsigned();
            Array.Copy(xBytes, 0, compEnc, 33 - xBytes.Length, xBytes.Length);
            return curve.Curve.DecodePoint(compEnc);
        }
        
    }
}
