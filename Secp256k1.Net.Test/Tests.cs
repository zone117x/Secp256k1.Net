using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Secp256k1Net.Test
{
    public class Tests
    {
        ref struct KeyPair
        {
            public Span<byte> PrivateKey;
            public Span<byte> PublicKey;
        }

        Span<byte> GeneratePrivateKey(Secp256k1 secp256k1)
        {
            var rnd = RandomNumberGenerator.Create();
            Span<byte> privateKey = new byte[32];
            do
            {
                rnd.GetBytes(privateKey);
            }
            while (!secp256k1.SecretKeyVerify(privateKey));
            return privateKey;
        }

        KeyPair GenerateKeyPair(Secp256k1 secp256k1)
        {
            var privateKey = GeneratePrivateKey(secp256k1);
            Span<byte> publicKey = new byte[64];
            if (!secp256k1.PublicKeyCreate(publicKey, privateKey))
            {
                throw new Exception("Public key creation failed");
            }
            return new KeyPair { PrivateKey = privateKey, PublicKey = publicKey };
        }

        [Fact]
        public void EcdhTest()
        {
            using (var secp256k1 = new Secp256k1())
            {
                var kp1 = GenerateKeyPair(secp256k1);
                var kp2 = GenerateKeyPair(secp256k1);

                Span<byte> sec1 = new byte[32];
                Assert.True(secp256k1.Ecdh(sec1, kp1.PublicKey, kp2.PrivateKey));

                Span<byte> sec2 = new byte[32];
                Assert.True(secp256k1.Ecdh(sec2, kp2.PublicKey, kp1.PrivateKey));

                Span<byte> sec3 = new byte[32];
                Assert.True(secp256k1.Ecdh(sec3, kp1.PublicKey, kp1.PrivateKey));

                Assert.Equal(sec1.ToHexString(), sec2.ToHexString());
                Assert.NotEqual(sec3.ToHexString(), sec2.ToHexString());
            }
        }

        [Fact]
        public void EcdhTestCustomHash()
        {
            using (var secp256k1 = new Secp256k1())
            {
                var kp1 = GenerateKeyPair(secp256k1);
                var kp2 = GenerateKeyPair(secp256k1);

                EcdhHashFunction hashFunc = (Span<byte> output, Span<byte> x, Span<byte> y, IntPtr data) => 
                {
                    // XOR points together (dumb)
                    for (var i = 0; i < 32; i++)
                    {
                        output[i] = (byte)(x[i] ^ y[i]);
                    }
                    return 1;
                };

                Span<byte> sec1 = new byte[32];
                Assert.True(secp256k1.Ecdh(sec1, kp1.PublicKey, kp2.PrivateKey, hashFunc, IntPtr.Zero));

                Span<byte> sec2 = new byte[32];
                Assert.True(secp256k1.Ecdh(sec2, kp2.PublicKey, kp1.PrivateKey, hashFunc, IntPtr.Zero));

                Span<byte> sec3 = new byte[32];
                Assert.True(secp256k1.Ecdh(sec3, kp1.PublicKey, kp1.PrivateKey, hashFunc, IntPtr.Zero));

                Assert.Equal(sec1.ToHexString(), sec2.ToHexString());
                Assert.NotEqual(sec3.ToHexString(), sec2.ToHexString());
            }
        }

        [Fact]
        public void KeyPairGeneration()
        {
            using (var secp256k1 = new Secp256k1())
            {
                var kp = GenerateKeyPair(secp256k1);
            }
        }

        [Fact]
        public void SignAndVerify()
        {
            using (var secp256k1 = new Secp256k1())
            {
                var kp = GenerateKeyPair(secp256k1);
                Span<byte> msg = new byte[32];
                RandomNumberGenerator.Create().GetBytes(msg);
                Span<byte> signature = new byte[64];
                Assert.True(secp256k1.Sign(signature, msg, kp.PrivateKey));
                Assert.True(secp256k1.Verify(signature, msg, kp.PublicKey));
            }
        }

        [Fact]
        public void ParseDerSignatureTest()
        {
            using (var secp256k1 = new Secp256k1())
            {
                Span<byte> signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];

                Span<byte> validDerSignature = "30440220484ECE2B365D2B2C2EAD34B518328BBFEF0F4409349EEEC9CB19837B5795A5F5022040C4F6901FE489F923C49D4104554FD08595EAF864137F87DADDD0E3619B0605".HexToBytes();                
                Assert.True(secp256k1.SignatureParseDer(signatureOutput, validDerSignature));

                Span<byte> invalidDerSignature = "00".HexToBytes();
                Assert.False(secp256k1.SignatureParseDer(signatureOutput, invalidDerSignature));
            }
        }


        [Fact]
        public void SerializeDerSignatureTest()
        {
            using (var secp256k1 = new Secp256k1())
            {
                Span<byte> signatureOutput = new byte[Secp256k1.SERIALIZED_DER_SIGNATURE_MAX_SIZE];
                int signatureOutputLenght = 0;

                Span<byte> validECDSAsignature = "304502203b8cbc6a72101fd9e6c6149e7ee97e86786082f16008183e6311483f81985b5d02210080bb7228cd91da2cf92dfe99be639eeecc7e4f4f31acb5748af6307f578ac45d".HexToBytes();
                Assert.True(secp256k1.SignatureSerializeDer(signatureOutput, validECDSAsignature, out signatureOutputLenght));
            }
        }

        /*
        [Fact]
        public void SignatureNormalize()
        {
            using (var secp256k1 = new Secp256k1())
            {
                Assert.True(secp256k1.SignatureNormalize()
            }
        }
        */

        [Fact]
        public void SigningTest()
        {
            using (var secp256k1 = new Secp256k1())
            {

                Span<byte> signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
                Span<byte> messageHash = new byte[] { 0xc9, 0xf1, 0xc7, 0x66, 0x85, 0x84, 0x5e, 0xa8, 0x1c, 0xac, 0x99, 0x25, 0xa7, 0x56, 0x58, 0x87, 0xb7, 0x77, 0x1b, 0x34, 0xb3, 0x5e, 0x64, 0x1c, 0xca, 0x85, 0xdb, 0x9f, 0xef, 0xd0, 0xe7, 0x1f };
                Span<byte> secretKey = "e815acba8fcf085a0b4141060c13b8017a08da37f2eb1d6a5416adbb621560ef".HexToBytes();

                bool result = secp256k1.SignRecoverable(signature, messageHash, secretKey);
                Assert.True(result);

                // Recover the public key
                Span<byte> publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
                result = secp256k1.Recover(publicKeyOutput, signature, messageHash);
                Assert.True(result);

                // Serialize the public key
                Span<byte> serializedKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
                result = secp256k1.PublicKeySerialize(serializedKey, publicKeyOutput);
                Assert.True(result);

                // Slice off any prefix.
                serializedKey = serializedKey.Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

                Assert.Equal("0x3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", serializedKey.ToHexString(), true);

                // Verify it works with variables generated from our managed code.
                BigInteger ecdsa_r = BigInteger.Parse("68932463183462156574914988273446447389145511361487771160486080715355143414637");
                BigInteger ecdsa_s = BigInteger.Parse("47416572686988136438359045243120473513988610648720291068939984598262749281683");
                byte recoveryId = 1;

                byte[] ecdsa_r_bytes = BigIntegerConverter.GetBytes(ecdsa_r);
                byte[] ecdsa_s_bytes = BigIntegerConverter.GetBytes(ecdsa_s);
                signature = ecdsa_r_bytes.Concat(ecdsa_s_bytes).ToArray();

                // Allocate memory for the signature and create a serialized-format signature to deserialize into our native format (platform dependent, hence why we do this).
                Span<byte> serializedSignature = ecdsa_r_bytes.Concat(ecdsa_s_bytes).ToArray();
                signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
                result = secp256k1.RecoverableSignatureParseCompact(signature, serializedSignature, recoveryId);
                if (!result)
                    throw new Exception("Unmanaged EC library failed to parse serialized signature.");

                // Recover the public key
                publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
                result = secp256k1.Recover(publicKeyOutput, signature, messageHash);
                Assert.True(result);

                // Serialize the public key
                serializedKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
                result = secp256k1.PublicKeySerialize(serializedKey, publicKeyOutput);
                Assert.True(result);

                // Slice off any prefix.
                serializedKey = serializedKey.Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

                // Assert our key
                Assert.Equal("0x3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", serializedKey.ToHexString(), true);
            }
        }
    }

    public static class Extensions
    {
        public static string ToHexString(this Span<byte> span)
        {
            return "0x" + BitConverter.ToString(span.ToArray()).Replace("-", "").ToLowerInvariant();
        }

        public static byte[] HexToBytes(this string hexString)
        {
            int chars = hexString.Length;
            byte[] bytes = new byte[chars / 2];
            for (int i = 0; i < chars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return bytes;
        }
    }

    public abstract class BigIntegerConverter
    {
        /// <summary>
        /// Obtains the bytes that represent the BigInteger as if it was a big endian 256-bit integer.
        /// </summary>
        /// <param name="bigInteger">The BigInteger to obtain the byte representation of.</param>
        /// <returns>Returns the bytes that represent BigInteger as if it was a 256-bit integer.</returns>
        public static byte[] GetBytes(BigInteger bigInteger, int byteCount = 32)
        {
            // Obtain the bytes which represent this BigInteger.
            byte[] result = bigInteger.ToByteArray();

            // We'll operate on the data in little endian (since we'll extend the array anyways and we'd have to copy the data over anyways).
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(result);

            // Store the original size of the data, then resize it to the size of a word.
            int originalSize = result.Length;
            Array.Resize(ref result, byteCount);

            // BigInteger uses the most significant bit as sign and optimizes to return values like -1 as 0xFF instead of as 0xFFFF or larger (since there is no bound size, and negative values have all leading bits set)
            // Instead if we wanted to represent 256 (0xFF), we would add a leading zero byte so the sign bit comes from it, and will be zero (positive) (0x00FF), this way, BigInteger knows to represent this as a positive value.
            // Because we resized the array already, it would have added leading zero bytes which works for positive numbers, but if it's negative, all extended bits should be set, so we check for that case.

            // If the integer is negative, any extended bits should all be set.
            if (bigInteger.Sign < 0)
                for (int i = originalSize; i < result.Length; i++)
                    result[i] = 0xFF;

            // Flip the array so it is in big endian form.
            Array.Reverse(result);

            return result;
        }
    }
}
