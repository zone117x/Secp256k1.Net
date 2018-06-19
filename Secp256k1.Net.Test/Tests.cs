using HoshoEthUtil;
using System;
using System.Linq;
using System.Numerics;
using Xunit;

namespace Secp256k1.Net.Test
{
    public class Tests
    {
        [Fact]
        public void SigningTest()
        {
            Span<byte> signature = new byte[65];
            Span<byte> messageHash = new byte[] { 0xc9, 0xf1, 0xc7, 0x66, 0x85, 0x84, 0x5e, 0xa8, 0x1c, 0xac, 0x99, 0x25, 0xa7, 0x56, 0x58, 0x87, 0xb7, 0x77, 0x1b, 0x34, 0xb3, 0x5e, 0x64, 0x1c, 0xca, 0x85, 0xdb, 0x9f, 0xef, 0xd0, 0xe7, 0x1f };
            Span<byte> secretKey = "e815acba8fcf085a0b4141060c13b8017a08da37f2eb1d6a5416adbb621560ef".HexToBytes();

            bool result = Secp256k1.EcdsaSignRecoverable(signature, messageHash, secretKey);
            Assert.True(result);

            // Recover the public key
            Span<byte> publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            result = Secp256k1.EcdsaRecover(publicKeyOutput, signature, messageHash);
            Assert.True(result);

            // Serialize the public key
            Span<byte> serializedKey = new byte[Secp256k1.SERIALIZED_PUBKEY_LENGTH];
            result = Secp256k1.EcdsaPublicKeySerialize(serializedKey, publicKeyOutput);
            Assert.True(result);

            // Slice off any prefix.
            serializedKey = serializedKey.Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

            Assert.Equal("0x3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", serializedKey.ToHexString(true), true);

            // Verify we could obtain the correct sender from the signature.
            Span<byte> senderAddress = Keccak.ComputeHash(serializedKey).Slice(Keccak.HASH_SIZE - 20);
            Assert.Equal("0x75c8aa4b12bc52c1f1860bc4e8af981d6542cccd", senderAddress.ToArray().ToHexString(true), true);

            // Verify it works with variables generated from our managed code.
            BigInteger ecdsa_r = BigInteger.Parse("68932463183462156574914988273446447389145511361487771160486080715355143414637");
            BigInteger ecdsa_s = BigInteger.Parse("47416572686988136438359045243120473513988610648720291068939984598262749281683");
            byte recoveryId = 1;

            byte[] ecdsa_r_bytes = BigIntegerConverter.GetBytes(ecdsa_r);
            byte[] ecdsa_s_bytes = BigIntegerConverter.GetBytes(ecdsa_s);
            signature = ecdsa_r_bytes.Concat(ecdsa_s_bytes).Concat(new byte[] { recoveryId }).ToArray();

            // Recover the public key
            publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            result = Secp256k1.EcdsaRecover(publicKeyOutput, signature, messageHash);
            Assert.True(result);


            // Serialize the public key
            serializedKey = new byte[Secp256k1.SERIALIZED_PUBKEY_LENGTH];
            result = Secp256k1.EcdsaPublicKeySerialize(serializedKey, publicKeyOutput);
            Assert.True(result);

            // Slice off any prefix.
            serializedKey = serializedKey.Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

            // Assert our key
            Assert.Equal("0x3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", serializedKey.ToHexString(true), true);

            //senderAddress = EthereumECDSA.Recover(messageHash.ToArray(), recoveryId, ecdsa_r, ecdsa_s).GetPublicKeyHash();
            //senderAddress = senderAddress.Slice(Keccak.HASH_SIZE - Address.ADDRESS_SIZE);
            //Assert.Equal("0x75c8aa4b12bc52c1f1860bc4e8af981d6542cccd", senderAddress.ToArray().ToHexString(true), true);
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
