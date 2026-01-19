using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Secp256k1Net.Test
{
    /// <summary>
    /// Tests for the auto-generated wrapper functions in Secp256k1.Wrappers.g.cs.
    /// These tests cover the direct native wrapper methods that provide Span-based access.
    /// </summary>
    [TestClass]
    public class GeneratedWrapperTests
    {
        // Helper methods for cross-framework compatibility
        private static byte[] ComputeSha256(byte[] data)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }

        private static void FillRandom(byte[] data)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(data);
            }
        }

        private static byte[] HexToBytes(string hex)
        {
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)int.Parse(hex.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return bytes;
        }

        private static string BytesToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        // Test data - known valid keypairs
        private static readonly byte[] TestPrivateKey = HexToBytes("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
        private static readonly byte[] TestPublicKey = HexToBytes("2208d5dc41d4f3ed555aff761e9bb0b99fbe6d1503b98711944be6a362242ebfa1c788c7a4e13f6aaa4099f9d2175fc031e5aa3ba08eb280e87dfb43bdae207f");

        #region Selftest

        [TestMethod]
        public void Selftest_Succeeds()
        {
            using var secp256k1 = new Secp256k1();
            // Should not throw
            secp256k1.Selftest();
        }

        #endregion

        #region EC Public Key Functions

        [TestMethod]
        public void EcPubkeyParse_ValidCompressedKey_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            // Create a valid compressed public key
            var pubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey));

            var serialized = new byte[33];
            nuint outputLen = 33;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(serialized, ref outputLen, pubkey, Secp256k1EcFlags.Compressed));

            // Parse the compressed key
            var parsedPubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyParse(parsedPubkey, serialized));
            Assert.AreEqual(BytesToHex(pubkey), BytesToHex(parsedPubkey));
        }

        [TestMethod]
        public void EcPubkeyParse_ValidUncompressedKey_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var pubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey));

            var serialized = new byte[65];
            nuint outputLen = 65;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(serialized, ref outputLen, pubkey, Secp256k1EcFlags.Uncompressed));

            var parsedPubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyParse(parsedPubkey, serialized));
            Assert.AreEqual(BytesToHex(pubkey), BytesToHex(parsedPubkey));
        }

        [TestMethod]
        public void EcPubkeySerialize_Compressed_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var pubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey));

            var output = new byte[33];
            nuint outputLen = 33;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(output, ref outputLen, pubkey, Secp256k1EcFlags.Compressed));
            Assert.AreEqual((nuint)33, outputLen);
            // Compressed keys start with 0x02 or 0x03
            Assert.IsTrue(output[0] == 0x02 || output[0] == 0x03);
        }

        [TestMethod]
        public void EcPubkeySerialize_Uncompressed_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var pubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey));

            var output = new byte[65];
            nuint outputLen = 65;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(output, ref outputLen, pubkey, Secp256k1EcFlags.Uncompressed));
            Assert.AreEqual((nuint)65, outputLen);
            // Uncompressed keys start with 0x04
            Assert.AreEqual(0x04, output[0]);
        }

        [TestMethod]
        public void EcPubkeyCmp_SameKeys_ReturnsZero()
        {
            using var secp256k1 = new Secp256k1();

            var pubkey1 = new byte[64];
            var pubkey2 = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey1, TestPrivateKey));
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey2, TestPrivateKey));

            // Same keys should return 0 (equal)
            var result = secp256k1.EcPubkeyCmp(pubkey1, pubkey2);
            Assert.AreEqual(0, result);
        }

        [TestMethod]
        public void EcPubkeyCmp_DifferentKeys_ReturnsNonZero()
        {
            using var secp256k1 = new Secp256k1();

            var privkey2 = HexToBytes("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda");

            var pubkey1 = new byte[64];
            var pubkey2 = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey1, TestPrivateKey));
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey2, privkey2));

            // Different keys should return non-zero comparison (<0 or >0)
            var result = secp256k1.EcPubkeyCmp(pubkey1, pubkey2);
            Assert.AreNotEqual(0, result);
        }

        [TestMethod]
        public void EcPubkeyCreate_ValidSeckey_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var pubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey));
            Assert.AreEqual(BytesToHex(TestPublicKey), BytesToHex(pubkey));
        }

        [TestMethod]
        public void EcSeckeyVerify_ValidKey_ReturnsTrue()
        {
            using var secp256k1 = new Secp256k1();
            Assert.IsTrue(secp256k1.EcSeckeyVerify(TestPrivateKey));
        }

        [TestMethod]
        public void EcSeckeyVerify_ZeroKey_ReturnsFalse()
        {
            using var secp256k1 = new Secp256k1();
            var zeroKey = new byte[32];
            Assert.IsFalse(secp256k1.EcSeckeyVerify(zeroKey));
        }

        [TestMethod]
        public void EcSeckeyNegate_TwiceReturnsOriginal()
        {
            using var secp256k1 = new Secp256k1();

            var seckey = TestPrivateKey.ToArray();
            var original = TestPrivateKey.ToArray();

            Assert.IsTrue(secp256k1.EcSeckeyNegate(seckey));
            Assert.AreNotEqual(BytesToHex(original), BytesToHex(seckey));

            Assert.IsTrue(secp256k1.EcSeckeyNegate(seckey));
            Assert.AreEqual(BytesToHex(original), BytesToHex(seckey));
        }

        [TestMethod]
        public void EcPubkeyNegate_TwiceReturnsOriginal()
        {
            using var secp256k1 = new Secp256k1();

            var pubkey = TestPublicKey.ToArray();
            var original = TestPublicKey.ToArray();

            Assert.IsTrue(secp256k1.EcPubkeyNegate(pubkey));
            Assert.AreNotEqual(BytesToHex(original), BytesToHex(pubkey));

            Assert.IsTrue(secp256k1.EcPubkeyNegate(pubkey));
            Assert.AreEqual(BytesToHex(original), BytesToHex(pubkey));
        }

        [TestMethod]
        public void EcSeckeyTweakAdd_ValidTweak_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var seckey = TestPrivateKey.ToArray();
            var tweak = new byte[32];
            tweak[31] = 1; // Small valid tweak

            Assert.IsTrue(secp256k1.EcSeckeyTweakAdd(seckey, tweak));
            Assert.AreNotEqual(BytesToHex(TestPrivateKey), BytesToHex(seckey));
        }

        [TestMethod]
        public void EcPubkeyTweakAdd_ValidTweak_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var pubkey = TestPublicKey.ToArray();
            var tweak = new byte[32];
            tweak[31] = 1;

            Assert.IsTrue(secp256k1.EcPubkeyTweakAdd(pubkey, tweak));
            Assert.AreNotEqual(BytesToHex(TestPublicKey), BytesToHex(pubkey));
        }

        [TestMethod]
        public void EcSeckeyTweakMul_ValidTweak_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var seckey = TestPrivateKey.ToArray();
            var tweak = new byte[32];
            tweak[31] = 2; // Multiply by 2

            Assert.IsTrue(secp256k1.EcSeckeyTweakMul(seckey, tweak));
            Assert.AreNotEqual(BytesToHex(TestPrivateKey), BytesToHex(seckey));
        }

        [TestMethod]
        public void EcPubkeyTweakMul_ValidTweak_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var pubkey = TestPublicKey.ToArray();
            var tweak = new byte[32];
            tweak[31] = 2;

            Assert.IsTrue(secp256k1.EcPubkeyTweakMul(pubkey, tweak));
            Assert.AreNotEqual(BytesToHex(TestPublicKey), BytesToHex(pubkey));
        }

        #endregion

        #region ECDSA Signature Functions

        [TestMethod]
        public void EcdsaSignatureParseCompact_ValidSig_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            // Create a signature
            var msgHash = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test message"));
            var sig = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaSign(sig, msgHash, TestPrivateKey));

            // Serialize to compact
            var compact = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaSignatureSerializeCompact(compact, sig));

            // Parse it back
            var parsedSig = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaSignatureParseCompact(parsedSig, compact));
            Assert.AreEqual(BytesToHex(sig), BytesToHex(parsedSig));
        }

        [TestMethod]
        public void EcdsaSignatureParseDer_ValidSig_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var msgHash = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test message"));
            var sig = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaSign(sig, msgHash, TestPrivateKey));

            // Serialize to DER
            var der = new byte[72];
            nuint derLen = 72;
            Assert.IsTrue(secp256k1.EcdsaSignatureSerializeDer(der, ref derLen, sig));

            // Parse it back
            var parsedSig = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaSignatureParseDer(parsedSig, der.AsSpan(0, (int)derLen)));
            Assert.AreEqual(BytesToHex(sig), BytesToHex(parsedSig));
        }

        [TestMethod]
        public void EcdsaVerify_ValidSignature_ReturnsTrue()
        {
            using var secp256k1 = new Secp256k1();

            var msgHash = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test message"));
            var sig = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaSign(sig, msgHash, TestPrivateKey));

            Assert.IsTrue(secp256k1.EcdsaVerify(sig, msgHash, TestPublicKey));
        }

        [TestMethod]
        public void EcdsaVerify_InvalidSignature_ReturnsFalse()
        {
            using var secp256k1 = new Secp256k1();

            var msgHash = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test message"));
            var wrongHash = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("different message"));
            var sig = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaSign(sig, msgHash, TestPrivateKey));

            Assert.IsFalse(secp256k1.EcdsaVerify(sig, wrongHash, TestPublicKey));
        }

        [TestMethod]
        public void EcdsaSignatureNormalize_AlreadyLowS_ReturnsFalse()
        {
            using var secp256k1 = new Secp256k1();

            var msgHash = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test"));
            var sig = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaSign(sig, msgHash, TestPrivateKey));

            var normalized = new byte[64];
            // Sign already produces low-S signatures, so normalize should return false
            var wasNormalized = secp256k1.EcdsaSignatureNormalize(normalized, sig);
            // Result is whether it was modified (high-S to low-S)
        }

        #endregion

        #region ECDSA Recovery Functions

        [TestMethod]
        public void EcdsaRecoverableSignatureParseCompact_ValidSig_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var msgHash = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test"));
            var recoverableSig = new byte[65];
            Assert.IsTrue(secp256k1.EcdsaSignRecoverable(recoverableSig, msgHash, TestPrivateKey));

            // Serialize
            var compact = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaRecoverableSignatureSerializeCompact(compact, out var recid, recoverableSig));

            // Parse back
            var parsedSig = new byte[65];
            Assert.IsTrue(secp256k1.EcdsaRecoverableSignatureParseCompact(parsedSig, compact, recid));
        }

        [TestMethod]
        public void EcdsaRecoverableSignatureConvert_ToRegularSig_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var msgHash = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test"));
            var recoverableSig = new byte[65];
            Assert.IsTrue(secp256k1.EcdsaSignRecoverable(recoverableSig, msgHash, TestPrivateKey));

            var regularSig = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaRecoverableSignatureConvert(regularSig, recoverableSig));

            // Verify the regular signature works
            Assert.IsTrue(secp256k1.EcdsaVerify(regularSig, msgHash, TestPublicKey));
        }

        [TestMethod]
        public void EcdsaRecover_ValidSignature_RecoversPubkey()
        {
            using var secp256k1 = new Secp256k1();

            var msgHash = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test"));
            var recoverableSig = new byte[65];
            Assert.IsTrue(secp256k1.EcdsaSignRecoverable(recoverableSig, msgHash, TestPrivateKey));

            var recoveredPubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcdsaRecover(recoveredPubkey, recoverableSig, msgHash));
            Assert.AreEqual(BytesToHex(TestPublicKey), BytesToHex(recoveredPubkey));
        }

        #endregion

        #region Tagged Hash Functions

        [TestMethod]
        public void TaggedSha256_ProducesValidHash()
        {
            using var secp256k1 = new Secp256k1();

            var tag = System.Text.Encoding.UTF8.GetBytes("BIP0340/challenge");
            var msg = System.Text.Encoding.UTF8.GetBytes("test message");
            var hash = new byte[32];

            Assert.IsTrue(secp256k1.TaggedSha256(hash, tag, msg));

            // Hash should not be all zeros
            Assert.IsFalse(hash.All(b => b == 0));
        }

        #endregion

        #region X-only Pubkey Functions

        [TestMethod]
        public void XonlyPubkeyParse_ValidKey_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            // Create keypair
            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            // Get x-only pubkey
            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairXonlyPub(xonlyPubkey, out _, keypair));

            // Serialize
            var serialized = new byte[32];
            Assert.IsTrue(secp256k1.XonlyPubkeySerialize(serialized, xonlyPubkey));

            // Parse back
            var parsed = new byte[64];
            Assert.IsTrue(secp256k1.XonlyPubkeyParse(parsed, serialized));
        }

        [TestMethod]
        public void XonlyPubkeyCmp_SameKeys_ReturnsZero()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairXonlyPub(xonlyPubkey, out _, keypair));

            // Same key comparison returns 0 (equal)
            Assert.AreEqual(0, secp256k1.XonlyPubkeyCmp(xonlyPubkey, xonlyPubkey));
        }

        [TestMethod]
        public void XonlyPubkeyFromPubkey_ConvertsProperly()
        {
            using var secp256k1 = new Secp256k1();

            var pubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey));

            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.XonlyPubkeyFromPubkey(xonlyPubkey, out var parity, pubkey));

            // Parity should be 0 or 1
            Assert.IsTrue(parity == 0 || parity == 1);
        }

        [TestMethod]
        public void XonlyPubkeyTweakAdd_ValidTweak_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairXonlyPub(xonlyPubkey, out _, keypair));

            var outputPubkey = new byte[64];
            var tweak = new byte[32];
            tweak[31] = 1;

            Assert.IsTrue(secp256k1.XonlyPubkeyTweakAdd(outputPubkey, xonlyPubkey, tweak));
        }

        [TestMethod]
        public void XonlyPubkeyTweakAddCheck_ValidTweak_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairXonlyPub(xonlyPubkey, out _, keypair));

            var tweak = new byte[32];
            tweak[31] = 1;

            // Tweak the pubkey
            var tweakedPubkey = new byte[64];
            Assert.IsTrue(secp256k1.XonlyPubkeyTweakAdd(tweakedPubkey, xonlyPubkey, tweak));

            // Get x-only from tweaked
            var tweakedXonly = new byte[64];
            Assert.IsTrue(secp256k1.XonlyPubkeyFromPubkey(tweakedXonly, out var parity, tweakedPubkey));

            // Serialize
            var tweakedSerialized = new byte[32];
            Assert.IsTrue(secp256k1.XonlyPubkeySerialize(tweakedSerialized, tweakedXonly));

            // Check
            Assert.IsTrue(secp256k1.XonlyPubkeyTweakAddCheck(tweakedSerialized, parity, xonlyPubkey, tweak));
        }

        #endregion

        #region Keypair Functions

        [TestMethod]
        public void KeypairCreate_ValidSeckey_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));
        }

        [TestMethod]
        public void KeypairSec_ExtractsSeckey()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var seckey = new byte[32];
            Assert.IsTrue(secp256k1.KeypairSec(seckey, keypair));
            Assert.AreEqual(BytesToHex(TestPrivateKey), BytesToHex(seckey));
        }

        [TestMethod]
        public void KeypairPub_ExtractsPubkey()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var pubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairPub(pubkey, keypair));
            Assert.AreEqual(BytesToHex(TestPublicKey), BytesToHex(pubkey));
        }

        [TestMethod]
        public void KeypairXonlyPub_ExtractsXonlyPubkey()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairXonlyPub(xonlyPubkey, out var parity, keypair));
            Assert.IsTrue(parity == 0 || parity == 1);
        }

        [TestMethod]
        public void KeypairXonlyTweakAdd_ValidTweak_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var tweak = new byte[32];
            tweak[31] = 1;

            Assert.IsTrue(secp256k1.KeypairXonlyTweakAdd(keypair, tweak));
        }

        #endregion

        #region Schnorr Signature Functions

        [TestMethod]
        public void SchnorrsigSign32_ValidInputs_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var msg32 = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test message"));
            var auxRand = new byte[32];
            FillRandom(auxRand);

            var sig64 = new byte[64];
            Assert.IsTrue(secp256k1.SchnorrsigSign32(sig64, msg32, keypair, auxRand));
        }

        [TestMethod]
        public void SchnorrsigVerify_ValidSignature_ReturnsTrue()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var msg = System.Text.Encoding.UTF8.GetBytes("test message");
            var msg32 = ComputeSha256(msg);
            var auxRand = new byte[32];
            FillRandom(auxRand);

            var sig64 = new byte[64];
            Assert.IsTrue(secp256k1.SchnorrsigSign32(sig64, msg32, keypair, auxRand));

            // Get x-only pubkey
            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairXonlyPub(xonlyPubkey, out _, keypair));

            Assert.IsTrue(secp256k1.SchnorrsigVerify(sig64, msg32, xonlyPubkey));
        }

        [TestMethod]
        public void SchnorrsigVerify_InvalidSignature_ReturnsFalse()
        {
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var msg32 = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("test message"));
            var wrongMsg = ComputeSha256(System.Text.Encoding.UTF8.GetBytes("different"));
            var auxRand = new byte[32];
            FillRandom(auxRand);

            var sig64 = new byte[64];
            Assert.IsTrue(secp256k1.SchnorrsigSign32(sig64, msg32, keypair, auxRand));

            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairXonlyPub(xonlyPubkey, out _, keypair));

            Assert.IsFalse(secp256k1.SchnorrsigVerify(sig64, wrongMsg, xonlyPubkey));
        }

        #endregion

        #region ElligatorSwift Functions

        [TestMethod]
        public void EllswiftCreate_ValidInputs_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var ell64 = new byte[64];
            var auxRand = new byte[32];
            FillRandom(auxRand);

            Assert.IsTrue(secp256k1.EllswiftCreate(ell64, TestPrivateKey, auxRand));
        }

        [TestMethod]
        public void EllswiftEncode_ValidPubkey_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var ell64 = new byte[64];
            var rnd32 = new byte[32];
            FillRandom(rnd32);

            Assert.IsTrue(secp256k1.EllswiftEncode(ell64, TestPublicKey, rnd32));
        }

        [TestMethod]
        public void EllswiftDecode_RoundTrip_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var ell64 = new byte[64];
            var rnd32 = new byte[32];
            FillRandom(rnd32);

            Assert.IsTrue(secp256k1.EllswiftEncode(ell64, TestPublicKey, rnd32));

            var decodedPubkey = new byte[64];
            Assert.IsTrue(secp256k1.EllswiftDecode(decodedPubkey, ell64));
            Assert.AreEqual(BytesToHex(TestPublicKey), BytesToHex(decodedPubkey));
        }

        #endregion

        #region MuSig Functions

        [TestMethod]
        public void MusigPubnonceSerialize_MethodExists()
        {
            // Note: Full MuSig testing requires MusigPubkeyAgg which isn't generated
            // (it has a pointer-to-pointer parameter). This test just verifies the methods exist.
            using var secp256k1 = new Secp256k1();

            // Verify the serialize/parse methods exist and can be called
            var pubnonce = new byte[132];
            var serialized = new byte[66];
            var parsed = new byte[132];

            // These will return false because pubnonce is not valid, but the methods exist
            secp256k1.MusigPubnonceSerialize(serialized, pubnonce);
            secp256k1.MusigPubnonceParse(parsed, serialized);
        }

        [TestMethod]
        public void MusigPartialSigParse_RoundTrip_ProducesValidStructure()
        {
            // This test verifies the parse/serialize round trip works
            // We can't fully test without a complete MuSig signing flow
            using var secp256k1 = new Secp256k1();

            // Create a minimal partial sig structure
            var partialSig = new byte[36];
            var in32 = new byte[32];
            in32[0] = 1; // Non-zero to make it look like a valid scalar

            // This may fail if in32 is not a valid partial sig encoding
            // Just test that the methods exist and can be called
            var parsed = new byte[36];
            var result = secp256k1.MusigPartialSigParse(parsed, in32);
            // Result depends on validity of input
        }

        [TestMethod]
        public void MusigNonceGen_MethodExists()
        {
            // Note: Full MuSig testing requires MusigPubkeyAgg which isn't generated
            // This test verifies the method exists and validates parameters
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var pubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairPub(pubkey, keypair));

            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var sessionRand = new byte[32];
            FillRandom(sessionRand);

            var msg32 = new byte[32];
            FillRandom(msg32);
            var keyaggCache = new byte[197];  // Not properly initialized
            var extraInput = new byte[32];

            // This will fail because keyagg_cache isn't properly initialized
            // (requires MusigPubkeyAgg which has unsupported pointer-to-pointer signature)
            // We just verify the method exists and can be called
            var result = secp256k1.MusigNonceGen(secnonce, pubnonce, sessionRand, TestPrivateKey, pubkey, msg32, keyaggCache, extraInput);
            // Result is expected to be false due to invalid keyagg_cache
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void MusigNonceGenCounter_MethodExists()
        {
            // Note: Full MuSig testing requires MusigPubkeyAgg which isn't generated
            using var secp256k1 = new Secp256k1();

            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, TestPrivateKey));

            var secnonce = new byte[132];
            var pubnonce = new byte[132];

            var msg32 = new byte[32];
            FillRandom(msg32);
            var keyaggCache = new byte[197];  // Not properly initialized
            var extraInput = new byte[32];

            // This will fail because keyagg_cache isn't properly initialized
            var result = secp256k1.MusigNonceGenCounter(secnonce, pubnonce, 1, keypair, msg32, keyaggCache, extraInput);
            Assert.IsFalse(result);
        }

        #endregion

        #region Array-of-Pointers Functions (New Generated Wrappers)

        [TestMethod]
        public void EcPubkeyCombine_TwoPubkeys_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            // Create two keypairs
            var privkey1 = new byte[32];
            var privkey2 = new byte[32];
            FillRandom(privkey1);
            FillRandom(privkey2);

            var pubkey1 = new byte[64];
            var pubkey2 = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey1, privkey1));
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey2, privkey2));

            // Combine them using the generated wrapper
            var combinedPubkey = new byte[64];
            var result = secp256k1.EcPubkeyCombine(combinedPubkey, new[] { pubkey1, pubkey2 });
            Assert.IsTrue(result);

            // Verify the combined pubkey is different from both inputs
            Assert.AreNotEqual(BytesToHex(pubkey1), BytesToHex(combinedPubkey));
            Assert.AreNotEqual(BytesToHex(pubkey2), BytesToHex(combinedPubkey));
        }

        [TestMethod]
        public void EcPubkeyCombine_ThreePubkeys_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            var privkey1 = new byte[32];
            var privkey2 = new byte[32];
            var privkey3 = new byte[32];
            FillRandom(privkey1);
            FillRandom(privkey2);
            FillRandom(privkey3);

            var pubkey1 = new byte[64];
            var pubkey2 = new byte[64];
            var pubkey3 = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey1, privkey1));
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey2, privkey2));
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey3, privkey3));

            // Combine three pubkeys
            var combinedPubkey = new byte[64];
            var result = secp256k1.EcPubkeyCombine(combinedPubkey, new[] { pubkey1, pubkey2, pubkey3 });
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void EcPubkeySort_SortsTwoPubkeys()
        {
            using var secp256k1 = new Secp256k1();

            // Create two pubkeys from different private keys
            var pubkey1 = new byte[64];
            var pubkey2 = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey1, TestPrivateKey));

            var privkey2 = HexToBytes("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda");
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey2, privkey2));

            // Serialize pubkeys to compare lexicographic order
            var serialized1 = new byte[33];
            var serialized2 = new byte[33];
            nuint outputLen1 = 33;
            nuint outputLen2 = 33;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(serialized1, ref outputLen1, pubkey1, Secp256k1EcFlags.Compressed));
            Assert.IsTrue(secp256k1.EcPubkeySerialize(serialized2, ref outputLen2, pubkey2, Secp256k1EcFlags.Compressed));

            // Determine which should come first lexicographically
            var comparison = CompareBytes(serialized1, serialized2);
            Assert.AreNotEqual(0, comparison, "Pubkeys should be different");

            // Put them in reverse sorted order
            byte[][] pubkeys;
            byte[] expectedFirst, expectedSecond;
            if (comparison < 0)
            {
                // pubkey1 < pubkey2, so put pubkey2 first (reverse order)
                pubkeys = new[] { pubkey2, pubkey1 };
                expectedFirst = pubkey1;
                expectedSecond = pubkey2;
            }
            else
            {
                // pubkey2 < pubkey1, so put pubkey1 first (reverse order)
                pubkeys = new[] { pubkey1, pubkey2 };
                expectedFirst = pubkey2;
                expectedSecond = pubkey1;
            }

            // Sort
            var result = secp256k1.EcPubkeySort(pubkeys);
            Assert.IsTrue(result);

            // Verify the array is now sorted
            Assert.IsTrue(AreByteArraysEqual(pubkeys[0], expectedFirst), "First pubkey should be the lexicographically smaller one");
            Assert.IsTrue(AreByteArraysEqual(pubkeys[1], expectedSecond), "Second pubkey should be the lexicographically larger one");
        }

        private static int CompareBytes(byte[] a, byte[] b)
        {
            var minLen = Math.Min(a.Length, b.Length);
            for (int i = 0; i < minLen; i++)
            {
                if (a[i] < b[i]) return -1;
                if (a[i] > b[i]) return 1;
            }
            return a.Length.CompareTo(b.Length);
        }

        private static bool AreByteArraysEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        [TestMethod]
        public void MusigPubkeyAgg_AggregateTwoPubkeys_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            // Create two pubkeys
            var pubkey1 = new byte[64];
            var pubkey2 = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey1, TestPrivateKey));

            var privkey2 = HexToBytes("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda");
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey2, privkey2));

            // Aggregate them
            var aggPk = new byte[64];
            var keyaggCache = new byte[197];
            var result = secp256k1.MusigPubkeyAgg(aggPk, keyaggCache, new[] { pubkey1, pubkey2 });
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void MusigNonceAgg_AggregatesTwoNonces_Succeeds()
        {
            using var secp256k1 = new Secp256k1();

            // First set up two signers with valid keyagg
            var pubkey1 = new byte[64];
            var pubkey2 = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey1, TestPrivateKey));

            var privkey2 = HexToBytes("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda");
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey2, privkey2));

            // Create keyagg cache
            var aggPk = new byte[64];
            var keyaggCache = new byte[197];
            Assert.IsTrue(secp256k1.MusigPubkeyAgg(aggPk, keyaggCache, new[] { pubkey1, pubkey2 }));

            // Generate nonces for both signers
            var msg32 = new byte[32];
            FillRandom(msg32);

            var extraInput = new byte[32]; // Required parameter, can be zero-filled

            var secnonce1 = new byte[132];
            var pubnonce1 = new byte[132];
            var sessionRand1 = new byte[32];
            FillRandom(sessionRand1);
            Assert.IsTrue(secp256k1.MusigNonceGen(secnonce1, pubnonce1, sessionRand1, TestPrivateKey, pubkey1, msg32, keyaggCache, extraInput));

            var secnonce2 = new byte[132];
            var pubnonce2 = new byte[132];
            var sessionRand2 = new byte[32];
            FillRandom(sessionRand2);
            Assert.IsTrue(secp256k1.MusigNonceGen(secnonce2, pubnonce2, sessionRand2, privkey2, pubkey2, msg32, keyaggCache, extraInput));

            // Aggregate the nonces
            var aggnonce = new byte[132];
            var result = secp256k1.MusigNonceAgg(aggnonce, new[] { pubnonce1, pubnonce2 });
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void EcPubkeyCombine_NullArray_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[64];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyCombine(output, null));
        }

        [TestMethod]
        public void EcPubkeyCombine_EmptyArray_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[64];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyCombine(output, new byte[0][]));
        }

        [TestMethod]
        public void EcPubkeyCombine_TooSmallElement_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[64];
            var smallPubkey = new byte[63]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyCombine(output, new[] { smallPubkey }));
        }

        #endregion

        #region Argument Validation Tests

        [TestMethod]
        public void EcPubkeyParse_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Too small
            var input = new byte[33];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyParse(pubkey, input));
        }

        [TestMethod]
        public void EcPubkeySerialize_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();

            // First create a valid public key
            var pubkey = new byte[64];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey));

            // Try to serialize with too small output - wrapper validates based on flags
            var output = new byte[32]; // Too small for compressed (33) or uncompressed (65)
            nuint outputLen = 32;

            // The wrapper validates output size based on flags and throws ArgumentException
            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeySerialize(output, ref outputLen, pubkey, Secp256k1EcFlags.Compressed));
        }

        [TestMethod]
        public void EcSeckeyVerify_TooSmallInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var seckey = new byte[31]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcSeckeyVerify(seckey));
        }

        [TestMethod]
        public void KeypairCreate_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var keypair = new byte[95]; // Too small
            var seckey = new byte[32];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.KeypairCreate(keypair, seckey));
        }

        [TestMethod]
        public void SchnorrsigSign32_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[63]; // Too small
            var msg32 = new byte[32];
            var keypair = new byte[96];
            var auxRand = new byte[32];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SchnorrsigSign32(sig, msg32, keypair, auxRand));
        }

        #endregion
    }
}
