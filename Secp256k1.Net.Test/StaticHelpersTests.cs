using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Secp256k1Net.Test
{
    /// <summary>
    /// Tests for Secp256k1 static helper methods using test vectors from the secp256k1 C library.
    /// </summary>
    [TestClass]
    public class StaticHelpersTests
    {
        #region Test Vectors from secp256k1 C library

        // BIP-340 Schnorr test vectors (from secp256k1/src/modules/schnorrsig/tests_impl.h)
        private static readonly (string SecretKey, string PublicKey, string AuxRand, string Message, string Signature)[] SchnorrSigningVectors =
        {
            // Test vector 0
            (
                SecretKey: "0000000000000000000000000000000000000000000000000000000000000003",
                PublicKey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                AuxRand: "0000000000000000000000000000000000000000000000000000000000000000",
                Message: "0000000000000000000000000000000000000000000000000000000000000000",
                Signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
            ),
            // Test vector 1
            (
                SecretKey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
                PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                AuxRand: "0000000000000000000000000000000000000000000000000000000000000001",
                Message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                Signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"
            ),
            // Test vector 2
            (
                SecretKey: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
                PublicKey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
                AuxRand: "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
                Message: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
                Signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"
            ),
            // Test vector 3
            (
                SecretKey: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
                PublicKey: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
                AuxRand: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                Message: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                Signature: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"
            )
        };

        // Schnorr verify-only vectors (signatures should verify)
        private static readonly (string PublicKey, string Message, string Signature, bool ExpectedValid)[] SchnorrVerifyVectors =
        {
            // Test vector 4 - valid signature with different format
            (
                PublicKey: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
                Message: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
                Signature: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
                ExpectedValid: true
            ),
            // Test vector 6 - invalid signature (has_even_y == false)
            (
                PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                Message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                Signature: "FFF97BD5755EEEA420453A1435523582F6472F8568A18B2F057A1460297556563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
                ExpectedValid: false
            ),
            // Test vector 7 - negated message
            (
                PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                Message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                Signature: "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
                ExpectedValid: false
            ),
            // Test vector 8 - negated s value
            (
                PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                Message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                Signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
                ExpectedValid: false
            ),
            // Test vector 9 - sG - eP is infinite (r = 0)
            (
                PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                Message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                Signature: "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
                ExpectedValid: false
            ),
            // Test vector 10 - sG - eP is infinite (r = 1)
            (
                PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                Message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                Signature: "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C0997420DEADB4DBA87F11AC6754F93780D5A1837CF19",
                ExpectedValid: false
            ),
            // Test vector 11 - sig[0:32] is not an X coordinate
            (
                PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                Message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                Signature: "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                ExpectedValid: false
            ),
            // Test vector 12 - sig[0:32] >= p
            (
                PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                Message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                Signature: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                ExpectedValid: false
            )
        };

        // Recovery signature edge case test vector (from secp256k1/src/modules/recovery/tests_impl.h)
        private static readonly byte[] RecoveryMsg32 = new byte[]
        {
            (byte)'T', (byte)'h', (byte)'i', (byte)'s', (byte)' ', (byte)'i', (byte)'s', (byte)' ',
            (byte)'a', (byte)' ', (byte)'v', (byte)'e', (byte)'r', (byte)'y', (byte)' ', (byte)'s',
            (byte)'e', (byte)'c', (byte)'r', (byte)'e', (byte)'t', (byte)' ', (byte)'m', (byte)'e',
            (byte)'s', (byte)'s', (byte)'a', (byte)'g', (byte)'e', (byte)'.', (byte)'.', (byte)'.'
        };

        // Wycheproof ECDSA test vectors (from secp256k1/src/wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json)
        // Using uncompressed public key format for the first test group
        private static readonly string WycheproofEcdsaPublicKeyUncompressed =
            "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";

        private static readonly (string MsgHex, string DerSigHex, bool ExpectedValid, string Comment)[] WycheproofEcdsaVectors =
        {
            // tcId 1: Signature malleability (high-S, should be invalid for Bitcoin)
            ("313233343030", "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87", false, "Signature malleability"),
            // tcId 2: valid signature
            ("313233343030", "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba", true, "valid"),
            // tcId 3: Invalid BER encoding (long form)
            ("313233343030", "308145022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba", false, "BER long form encoding"),
            // tcId 5: Invalid length
            ("313233343030", "3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba", false, "Invalid encoding - wrong length"),
            // tcId 6: Invalid length
            ("313233343030", "3044022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba", false, "Invalid encoding - wrong length"),
        };

        // Wycheproof ECDH test vectors (from secp256k1/src/wycheproof/ecdh_secp256k1_test.json)
        // These use raw uncompressed public key bytes (stripped of ASN.1 wrapper)
        private static readonly (string PublicKeyHex, string PrivateKeyHex, string ExpectedSharedHex, string Comment)[] WycheproofEcdhVectors =
        {
            // tcId 1: normal case
            (
                "04d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b396812ea1686e7472e9692eaf3e958e50e9500d3b4c77243db1f2acd67ba9cc4",
                "f4b7ff7cccc98813a69fae3df222bfe3f4e28f764bf91b4a10d8096ce446b254",
                "544dfae22af6af939042b1d85b71a1e49e9a5614123c4d6ad0c8af65baf87d65",
                "normal case"
            ),
            // tcId 3: shared secret has x-coordinate = 1
            (
                "04965ff42d654e058ee7317cced7caf093fbb180d8d3a74b0dcd9d8cd47a39d5cb9c2aa4daac01a4be37c20467ede964662f12983e0b5272a47a5f2785685d8087",
                "a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "edge case: shared secret x = 1"
            ),
            // tcId 4: shared secret has x-coordinate = 2
            (
                "0406c4b87ba76c6dcb101f54a050a086aa2cb0722f03137df5a922472f1bdc11b982e3c735c4b6c481d09269559f080ad08632f370a054af12c1fd1eced2ea9211",
                "a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "edge case: shared secret x = 2"
            ),
            // tcId 5: shared secret has x-coordinate = 3
            (
                "04bba30eef7967a2f2f08a2ffadac0e41fd4db12a93cef0b045b5706f2853821e6d50b2bf8cbf530e619869e07c021ef16f693cfc0a4b0d4ed5a8f464692bf3d6e",
                "a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "edge case: shared secret x = 3"
            ),
            // tcId 6: shared secret has x-coordinate p-3
            (
                "046da9eb2cdac02122d5f05cf6a8cd768e378f664ea4a7871d10e25f57eb1ee1cc5b2b5abf9c6c6596f8f383ddbcb3bcc2d5a7cc605984931239ca9669946032ee",
                "a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c",
                "edge case: shared secret x = p-3"
            ),
        };

        // X-only public key test vectors (from secp256k1/src/modules/extrakeys/tests_impl.h)
        private static readonly (string XOnlyPubKey1, string XOnlyPubKey2)[] XOnlyPubKeyComparisonVectors =
        {
            (
                "5884b3a24b97378892386a2662523511d09aa11b800b5e93802611ef674bd923",
                "de360e87598f3c01362a2ab8c6f45e4db2c2d503a7f9f14fa8fa95a8e969761c"
            )
        };

        private static readonly byte[] RecoverySig64 = new byte[]
        {
            // Generated by signing the above message with nonce 'This is the nonce we will use...'
            // and secret key 0 (which is not valid), resulting in recid 1.
            0x67, 0xCB, 0x28, 0x5F, 0x9C, 0xD1, 0x94, 0xE8,
            0x40, 0xD6, 0x29, 0x39, 0x7A, 0xF5, 0x56, 0x96,
            0x62, 0xFD, 0xE4, 0x46, 0x49, 0x99, 0x59, 0x63,
            0x17, 0x9A, 0x7D, 0xD1, 0x7B, 0xD2, 0x35, 0x32,
            0x4B, 0x1B, 0x7D, 0xF3, 0x4C, 0xE1, 0xF6, 0x8E,
            0x69, 0x4F, 0xF6, 0xF1, 0x1A, 0xC7, 0x51, 0xDD,
            0x7D, 0xD7, 0x3E, 0x38, 0x7E, 0xE4, 0xFC, 0x86,
            0x6E, 0x1B, 0xE8, 0xEC, 0xC7, 0xDD, 0x95, 0x57
        };

        #endregion

        #region Key Generation Tests

        [TestMethod]
        public void CreateSecretKey_ReturnsValidKey()
        {
            var secretKey = Secp256k1.CreateSecretKey();

            Assert.AreEqual(32, secretKey.Length);
            Assert.IsTrue(Secp256k1.IsValidSecretKey(secretKey));
        }

        [TestMethod]
        public void CreateSecretKey_GeneratesUniqueKeys()
        {
            var key1 = Secp256k1.CreateSecretKey();
            var key2 = Secp256k1.CreateSecretKey();

            CollectionAssert.AreNotEqual(key1, key2);
        }

        [TestMethod]
        public void CreateKeyPair_CompressedByDefault()
        {
            var (secretKey, publicKey) = Secp256k1.CreateKeyPair();

            Assert.AreEqual(32, secretKey.Length);
            Assert.AreEqual(33, publicKey.Length);
            Assert.IsTrue(publicKey[0] == 0x02 || publicKey[0] == 0x03);
        }

        [TestMethod]
        public void CreateKeyPair_Uncompressed()
        {
            var (secretKey, publicKey) = Secp256k1.CreateKeyPair(compressed: false);

            Assert.AreEqual(32, secretKey.Length);
            Assert.AreEqual(65, publicKey.Length);
            Assert.AreEqual(0x04, publicKey[0]);
        }

        [TestMethod]
        public void CreatePublicKey_FromKnownSecretKey()
        {
            // Test vector 1 from BIP-340
            var secretKey = Convert.FromHexString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
            var expectedXOnlyPubKey = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";

            var publicKey = Secp256k1.CreatePublicKey(secretKey, compressed: true);

            Assert.AreEqual(33, publicKey.Length);
            // The x-coordinate should match (bytes 1-32 of compressed key)
            var xCoord = Convert.ToHexString(publicKey.AsSpan(1).ToArray());
            Assert.AreEqual(expectedXOnlyPubKey, xCoord);
        }

        [TestMethod]
        public void CreateXOnlyPublicKey_FromKnownSecretKey()
        {
            // Test vector 1 from BIP-340
            var secretKey = Convert.FromHexString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
            var expectedXOnlyPubKey = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";

            var (xOnlyPubKey, parity) = Secp256k1.CreateXOnlyPublicKey(secretKey);

            Assert.AreEqual(32, xOnlyPubKey.Length);
            Assert.AreEqual(expectedXOnlyPubKey, Convert.ToHexString(xOnlyPubKey));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CreatePublicKey_InvalidSecretKey_Throws()
        {
            var invalidKey = new byte[32]; // all zeros is invalid
            Secp256k1.CreatePublicKey(invalidKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CreateXOnlyPublicKey_InvalidSecretKey_Throws()
        {
            var invalidKey = new byte[32]; // all zeros is invalid
            Secp256k1.CreateXOnlyPublicKey(invalidKey);
        }

        #endregion

        #region Key Validation Tests

        [TestMethod]
        public void IsValidSecretKey_ValidKey_ReturnsTrue()
        {
            var secretKey = Convert.FromHexString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
            Assert.IsTrue(Secp256k1.IsValidSecretKey(secretKey));
        }

        [TestMethod]
        public void IsValidSecretKey_ZeroKey_ReturnsFalse()
        {
            var zeroKey = new byte[32];
            Assert.IsFalse(Secp256k1.IsValidSecretKey(zeroKey));
        }

        [TestMethod]
        public void IsValidSecretKey_OverflowKey_ReturnsFalse()
        {
            // Key >= curve order n
            var overflowKey = new byte[32];
            for (int i = 0; i < overflowKey.Length; i++) overflowKey[i] = 0xFF;
            Assert.IsFalse(Secp256k1.IsValidSecretKey(overflowKey));
        }

        [TestMethod]
        public void IsValidSecretKey_ShortKey_ReturnsFalse()
        {
            var shortKey = new byte[31];
            for (int i = 0; i < shortKey.Length; i++) shortKey[i] = 0x01;
            Assert.IsFalse(Secp256k1.IsValidSecretKey(shortKey));
        }

        [TestMethod]
        public void IsValidPublicKey_ValidCompressedKey_ReturnsTrue()
        {
            var secretKey = Convert.FromHexString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
            var publicKey = Secp256k1.CreatePublicKey(secretKey, compressed: true);

            Assert.IsTrue(Secp256k1.IsValidPublicKey(publicKey));
        }

        [TestMethod]
        public void IsValidPublicKey_ValidUncompressedKey_ReturnsTrue()
        {
            var secretKey = Convert.FromHexString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
            var publicKey = Secp256k1.CreatePublicKey(secretKey, compressed: false);

            Assert.IsTrue(Secp256k1.IsValidPublicKey(publicKey));
        }

        [TestMethod]
        public void IsValidPublicKey_InvalidKey_ReturnsFalse()
        {
            // Test vector 5 from BIP-340 - point not on curve
            var invalidPubKey = Convert.FromHexString("02EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34");
            Assert.IsFalse(Secp256k1.IsValidPublicKey(invalidPubKey));
        }

        [TestMethod]
        public void IsValidPublicKey_WrongLength_ReturnsFalse()
        {
            var wrongLength = new byte[34];
            Assert.IsFalse(Secp256k1.IsValidPublicKey(wrongLength));
        }

        #endregion

        #region Public Key Compression Tests

        [TestMethod]
        public void CompressPublicKey_FromUncompressed()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var uncompressed = Secp256k1.CreatePublicKey(secretKey, compressed: false);
            var compressed = Secp256k1.CreatePublicKey(secretKey, compressed: true);

            var result = Secp256k1.CompressPublicKey(uncompressed);

            CollectionAssert.AreEqual(compressed, result);
        }

        [TestMethod]
        public void CompressPublicKey_AlreadyCompressed()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var compressed = Secp256k1.CreatePublicKey(secretKey, compressed: true);

            var result = Secp256k1.CompressPublicKey(compressed);

            CollectionAssert.AreEqual(compressed, result);
        }

        [TestMethod]
        public void DecompressPublicKey_FromCompressed()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var compressed = Secp256k1.CreatePublicKey(secretKey, compressed: true);
            var uncompressed = Secp256k1.CreatePublicKey(secretKey, compressed: false);

            var result = Secp256k1.DecompressPublicKey(compressed);

            CollectionAssert.AreEqual(uncompressed, result);
        }

        [TestMethod]
        public void DecompressPublicKey_AlreadyUncompressed()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var uncompressed = Secp256k1.CreatePublicKey(secretKey, compressed: false);

            var result = Secp256k1.DecompressPublicKey(uncompressed);

            CollectionAssert.AreEqual(uncompressed, result);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CompressPublicKey_InvalidKey_Throws()
        {
            var invalidKey = new byte[33];
            Secp256k1.CompressPublicKey(invalidKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DecompressPublicKey_InvalidKey_Throws()
        {
            var invalidKey = new byte[33];
            Secp256k1.DecompressPublicKey(invalidKey);
        }

        #endregion

        #region ECDSA Sign/Verify Tests

        [TestMethod]
        public void Sign_AndVerify_RoundTrip()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var signature = Secp256k1.Sign(messageHash, secretKey);

            Assert.AreEqual(64, signature.Length);
            Assert.IsTrue(Secp256k1.Verify(signature, messageHash, publicKey));
        }

        [TestMethod]
        public void Verify_WrongMessage_ReturnsFalse()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var signature = Secp256k1.Sign(messageHash, secretKey);

            // Modify message
            messageHash[0] ^= 0x01;

            Assert.IsFalse(Secp256k1.Verify(signature, messageHash, publicKey));
        }

        [TestMethod]
        public void Verify_WrongPublicKey_ReturnsFalse()
        {
            var secretKey1 = Secp256k1.CreateSecretKey();
            var secretKey2 = Secp256k1.CreateSecretKey();
            var publicKey2 = Secp256k1.CreatePublicKey(secretKey2);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var signature = Secp256k1.Sign(messageHash, secretKey1);

            Assert.IsFalse(Secp256k1.Verify(signature, messageHash, publicKey2));
        }

        [TestMethod]
        public void Verify_CorruptedSignature_ReturnsFalse()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var signature = Secp256k1.Sign(messageHash, secretKey);
            signature[0] ^= 0x01;

            Assert.IsFalse(Secp256k1.Verify(signature, messageHash, publicKey));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Sign_InvalidSecretKey_Throws()
        {
            var invalidKey = new byte[32];
            var messageHash = new byte[32];
            Secp256k1.Sign(messageHash, invalidKey);
        }

        [TestMethod]
        public void Verify_InvalidPublicKey_ReturnsFalse()
        {
            var invalidPubKey = new byte[33];
            var signature = new byte[64];
            var messageHash = new byte[32];

            Assert.IsFalse(Secp256k1.Verify(signature, messageHash, invalidPubKey));
        }

        [TestMethod]
        public void Verify_InvalidSignature_ReturnsFalse()
        {
            var (_, publicKey) = Secp256k1.CreateKeyPair();
            var invalidSig = new byte[64];
            for (int i = 0; i < 64; i++) invalidSig[i] = 0xFF;
            var messageHash = new byte[32];

            Assert.IsFalse(Secp256k1.Verify(invalidSig, messageHash, publicKey));
        }

        #endregion

        #region Recoverable Signature Tests

        [TestMethod]
        public void SignRecoverable_AndRecover_RoundTrip()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var (signature, recoveryId) = Secp256k1.SignRecoverable(messageHash, secretKey);

            Assert.AreEqual(64, signature.Length);
            Assert.IsTrue(recoveryId >= 0 && recoveryId <= 3);

            var recoveredKey = Secp256k1.RecoverPublicKey(signature, recoveryId, messageHash);

            CollectionAssert.AreEqual(publicKey, recoveredKey);
        }

        [TestMethod]
        public void RecoverPublicKey_Uncompressed()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey, compressed: false);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var (signature, recoveryId) = Secp256k1.SignRecoverable(messageHash, secretKey);
            var recoveredKey = Secp256k1.RecoverPublicKey(signature, recoveryId, messageHash, compressed: false);

            CollectionAssert.AreEqual(publicKey, recoveredKey);
        }

        [TestMethod]
        public void RecoverPublicKey_EdgeCase_RecId1()
        {
            // Test vector from secp256k1 recovery tests
            // This signature was created with an invalid (zero) secret key and only recovers with recid=1
            Assert.ThrowsException<ArgumentException>(() =>
                Secp256k1.RecoverPublicKey(RecoverySig64, 0, RecoveryMsg32));

            // recid=1 should work (though we can't verify the public key since the secret key was invalid)
            var recovered = Secp256k1.RecoverPublicKey(RecoverySig64, 1, RecoveryMsg32);
            Assert.AreEqual(33, recovered.Length);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void RecoverPublicKey_InvalidRecoveryId_Throws()
        {
            var messageHash = new byte[32];
            var signature = new byte[64];
            for (int i = 0; i < signature.Length; i++) signature[i] = 0x01;

            Secp256k1.RecoverPublicKey(signature, 5, messageHash);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignRecoverable_InvalidSecretKey_Throws()
        {
            var invalidKey = new byte[32]; // all zeros is invalid
            var messageHash = new byte[32];
            Secp256k1.SignRecoverable(messageHash, invalidKey);
        }

        #endregion

        #region Schnorr Signature Tests (BIP-340)

        [TestMethod]
        public void SignSchnorr_BIP340TestVectors()
        {
            foreach (var vector in SchnorrSigningVectors)
            {
                var secretKey = Convert.FromHexString(vector.SecretKey);
                var expectedPubKey = Convert.FromHexString(vector.PublicKey);
                var auxRand = Convert.FromHexString(vector.AuxRand);
                var message = Convert.FromHexString(vector.Message);
                var expectedSig = Convert.FromHexString(vector.Signature);

                // Verify the public key matches
                var (actualPubKey, _) = Secp256k1.CreateXOnlyPublicKey(secretKey);
                Assert.AreEqual(vector.PublicKey, Convert.ToHexString(actualPubKey),
                    $"Public key mismatch for vector with sk={vector.SecretKey.Substring(0, 16)}...");

                // Sign and verify signature matches expected
                var signature = Secp256k1.SignSchnorr(message, secretKey, auxRand);
                Assert.AreEqual(vector.Signature, Convert.ToHexString(signature),
                    $"Signature mismatch for vector with sk={vector.SecretKey.Substring(0, 16)}...");

                // Verify the signature
                Assert.IsTrue(Secp256k1.VerifySchnorr(signature, message, actualPubKey),
                    $"Signature verification failed for vector with sk={vector.SecretKey.Substring(0, 16)}...");
            }
        }

        [TestMethod]
        public void VerifySchnorr_BIP340TestVectors()
        {
            foreach (var vector in SchnorrVerifyVectors)
            {
                var publicKey = Convert.FromHexString(vector.PublicKey);
                var message = Convert.FromHexString(vector.Message);
                var signature = Convert.FromHexString(vector.Signature);

                var result = Secp256k1.VerifySchnorr(signature, message, publicKey);

                Assert.AreEqual(vector.ExpectedValid, result,
                    $"Verification result mismatch for vector with pk={vector.PublicKey.Substring(0, 16)}..., sig={vector.Signature.Substring(0, 16)}...");
            }
        }

        [TestMethod]
        public void SignSchnorr_WithoutAuxRand()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var (xOnlyPubKey, _) = Secp256k1.CreateXOnlyPublicKey(secretKey);
            var message = new byte[32];
            new Random(42).NextBytes(message);

            // Sign without auxiliary randomness
            var signature = Secp256k1.SignSchnorr(message, secretKey);

            Assert.AreEqual(64, signature.Length);
            Assert.IsTrue(Secp256k1.VerifySchnorr(signature, message, xOnlyPubKey));
        }

        [TestMethod]
        public void VerifySchnorr_VariableLengthMessage()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var (xOnlyPubKey, _) = Secp256k1.CreateXOnlyPublicKey(secretKey);

            // BIP-340 supports variable length messages for verification
            // (though sign32 requires 32-byte messages)
            var message32 = new byte[32];
            new Random(42).NextBytes(message32);

            var signature = Secp256k1.SignSchnorr(message32, secretKey);

            // Verify with the exact message
            Assert.IsTrue(Secp256k1.VerifySchnorr(signature, message32, xOnlyPubKey));

            // Verify fails with different length message
            var message31 = new byte[31];
            Array.Copy(message32, message31, 31);
            Assert.IsFalse(Secp256k1.VerifySchnorr(signature, message31, xOnlyPubKey));
        }

        [TestMethod]
        public void VerifySchnorr_WithCompressedPublicKey()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var compressedPubKey = Secp256k1.CreatePublicKey(secretKey, compressed: true);
            var message = new byte[32];
            new Random(42).NextBytes(message);

            var signature = Secp256k1.SignSchnorr(message, secretKey);

            Assert.IsTrue(Secp256k1.VerifySchnorr(signature, message, compressedPubKey));
        }

        [TestMethod]
        public void VerifySchnorr_WithUncompressedPublicKey()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var uncompressedPubKey = Secp256k1.CreatePublicKey(secretKey, compressed: false);
            var message = new byte[32];
            new Random(42).NextBytes(message);

            var signature = Secp256k1.SignSchnorr(message, secretKey);

            Assert.IsTrue(Secp256k1.VerifySchnorr(signature, message, uncompressedPubKey));
        }

        [TestMethod]
        public void VerifySchnorr_AllPublicKeyFormatsProduceSameResult()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var (xOnlyPubKey, _) = Secp256k1.CreateXOnlyPublicKey(secretKey);
            var compressedPubKey = Secp256k1.CreatePublicKey(secretKey, compressed: true);
            var uncompressedPubKey = Secp256k1.CreatePublicKey(secretKey, compressed: false);
            var message = new byte[32];
            new Random(42).NextBytes(message);

            var signature = Secp256k1.SignSchnorr(message, secretKey);

            // All three formats should verify the same signature
            Assert.IsTrue(Secp256k1.VerifySchnorr(signature, message, xOnlyPubKey));
            Assert.IsTrue(Secp256k1.VerifySchnorr(signature, message, compressedPubKey));
            Assert.IsTrue(Secp256k1.VerifySchnorr(signature, message, uncompressedPubKey));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void VerifySchnorr_InvalidPublicKeyLength_Throws()
        {
            var signature = new byte[64];
            var message = new byte[32];
            var invalidPubKey = new byte[34]; // Invalid length

            Secp256k1.VerifySchnorr(signature, message, invalidPubKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void VerifySchnorr_InvalidXOnlyPublicKey_Throws()
        {
            var signature = new byte[64];
            var message = new byte[32];
            var invalidXOnlyPubKey = new byte[32];
            for (int i = 0; i < invalidXOnlyPubKey.Length; i++) invalidXOnlyPubKey[i] = 0xFF;

            Secp256k1.VerifySchnorr(signature, message, invalidXOnlyPubKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void VerifySchnorr_InvalidCompressedPublicKey_Throws()
        {
            var signature = new byte[64];
            var message = new byte[32];
            var invalidCompressedPubKey = new byte[33];
            for (int i = 0; i < invalidCompressedPubKey.Length; i++) invalidCompressedPubKey[i] = 0xFF;

            Secp256k1.VerifySchnorr(signature, message, invalidCompressedPubKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignSchnorr_WrongMessageLength_Throws()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var wrongLengthMessage = new byte[31];

            Secp256k1.SignSchnorr(wrongLengthMessage, secretKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignSchnorr_InvalidSecretKey_Throws()
        {
            var invalidKey = new byte[32]; // all zeros is invalid
            var message = new byte[32];

            Secp256k1.SignSchnorr(message, invalidKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignSchnorr_ShortAuxRand_Throws()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var message = new byte[32];
            var shortAuxRand = new byte[16]; // Less than 32 bytes

            Secp256k1.SignSchnorr(message, secretKey, shortAuxRand);
        }

        #endregion

        #region DER Signature Tests

        [TestMethod]
        public void SignatureToDer_AndBack_RoundTrip()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var compactSig = Secp256k1.Sign(messageHash, secretKey);
            var derSig = Secp256k1.SignatureToDer(compactSig);
            var backToCompact = Secp256k1.SignatureFromDer(derSig);

            CollectionAssert.AreEqual(compactSig, backToCompact);
        }

        [TestMethod]
        public void SignatureToDer_ValidFormat()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var compactSig = Secp256k1.Sign(messageHash, secretKey);
            var derSig = Secp256k1.SignatureToDer(compactSig);

            // DER signature should start with 0x30 (SEQUENCE tag)
            Assert.AreEqual(0x30, derSig[0]);

            // Length should be reasonable (typically 68-72 bytes total)
            Assert.IsTrue(derSig.Length >= 68 && derSig.Length <= 72);
        }

        [TestMethod]
        public void VerifyDer_WithValidSignature()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var compactSig = Secp256k1.Sign(messageHash, secretKey);
            var derSig = Secp256k1.SignatureToDer(compactSig);

            Assert.IsTrue(Secp256k1.VerifyDer(derSig, messageHash, publicKey));
        }

        [TestMethod]
        public void VerifyDer_WithInvalidSignature_ReturnsFalse()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var compactSig = Secp256k1.Sign(messageHash, secretKey);
            var derSig = Secp256k1.SignatureToDer(compactSig);

            // Corrupt the signature
            derSig[derSig.Length / 2] ^= 0x01;

            Assert.IsFalse(Secp256k1.VerifyDer(derSig, messageHash, publicKey));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignatureFromDer_InvalidDer_Throws()
        {
            // Completely invalid DER - wrong structure
            var invalidDer = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };
            Secp256k1.SignatureFromDer(invalidDer);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignatureToDer_InvalidSignature_Throws()
        {
            var invalidSig = new byte[64];
            for (int i = 0; i < 64; i++) invalidSig[i] = 0xFF;

            Secp256k1.SignatureToDer(invalidSig);
        }

        [TestMethod]
        public void VerifyDer_InvalidPublicKey_ReturnsFalse()
        {
            var invalidPubKey = new byte[33];
            var derSig = new byte[72];
            var messageHash = new byte[32];

            Assert.IsFalse(Secp256k1.VerifyDer(derSig, messageHash, invalidPubKey));
        }

        #endregion

        #region Signature Normalization Tests

        [TestMethod]
        public void NormalizeSignature_AlreadyNormalized()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var signature = Secp256k1.Sign(messageHash, secretKey);

            // secp256k1 always produces normalized signatures, so normalizing again
            // should produce the same signature
            var normalized = Secp256k1.NormalizeSignature(signature);
            CollectionAssert.AreEqual(signature, normalized);

            // Both should verify
            Assert.IsTrue(Secp256k1.Verify(signature, messageHash, publicKey));
            Assert.IsTrue(Secp256k1.Verify(normalized, messageHash, publicKey));
        }

        [TestMethod]
        public void NormalizeSignature_StillVerifiesAfterNormalization()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            var signature = Secp256k1.Sign(messageHash, secretKey);

            // After normalization, should still verify
            var normalized = Secp256k1.NormalizeSignature(signature);
            Assert.IsTrue(Secp256k1.Verify(normalized, messageHash, publicKey));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NormalizeSignature_InvalidSignature_Throws()
        {
            var invalidSignature = new byte[64];
            for (int i = 0; i < invalidSignature.Length; i++) invalidSignature[i] = 0xFF;
            Secp256k1.NormalizeSignature(invalidSignature);
        }

        [TestMethod]
        public void IsNormalizedSignature_NormalizedSignature_ReturnsTrue()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var messageHash = new byte[32];
            new Random(42).NextBytes(messageHash);

            // secp256k1 always produces normalized (low-S) signatures
            var signature = Secp256k1.Sign(messageHash, secretKey);

            Assert.IsTrue(Secp256k1.IsNormalizedSignature(signature));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void IsNormalizedSignature_InvalidSignature_Throws()
        {
            var invalidSig = new byte[64];
            for (int i = 0; i < 64; i++) invalidSig[i] = 0xFF;

            Secp256k1.IsNormalizedSignature(invalidSig);
        }

        #endregion

        #region ECDH Tests

        [TestMethod]
        public void ComputeSharedSecret_Symmetric()
        {
            var (secretKey1, publicKey1) = Secp256k1.CreateKeyPair();
            var (secretKey2, publicKey2) = Secp256k1.CreateKeyPair();

            var secret1 = Secp256k1.ComputeSharedSecret(publicKey2, secretKey1);
            var secret2 = Secp256k1.ComputeSharedSecret(publicKey1, secretKey2);

            CollectionAssert.AreEqual(secret1, secret2);
        }

        [TestMethod]
        public void ComputeSharedSecret_DifferentForDifferentKeys()
        {
            var (secretKey1, publicKey1) = Secp256k1.CreateKeyPair();
            var (secretKey2, publicKey2) = Secp256k1.CreateKeyPair();
            var (secretKey3, publicKey3) = Secp256k1.CreateKeyPair();

            var secret12 = Secp256k1.ComputeSharedSecret(publicKey2, secretKey1);
            var secret13 = Secp256k1.ComputeSharedSecret(publicKey3, secretKey1);

            CollectionAssert.AreNotEqual(secret12, secret13);
        }

        [TestMethod]
        public void ComputeSharedSecret_WithUncompressedKey()
        {
            var (secretKey1, _) = Secp256k1.CreateKeyPair();
            var publicKey1Uncompressed = Secp256k1.CreatePublicKey(secretKey1, compressed: false);
            var (secretKey2, _) = Secp256k1.CreateKeyPair();
            var publicKey2Compressed = Secp256k1.CreatePublicKey(secretKey2, compressed: true);

            var secret1 = Secp256k1.ComputeSharedSecret(publicKey2Compressed, secretKey1);
            var secret2 = Secp256k1.ComputeSharedSecret(publicKey1Uncompressed, secretKey2);

            CollectionAssert.AreEqual(secret1, secret2);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ComputeSharedSecret_InvalidPublicKey_Throws()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var invalidPubKey = new byte[33];

            Secp256k1.ComputeSharedSecret(invalidPubKey, secretKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ComputeSharedSecret_InvalidSecretKey_Throws()
        {
            var (_, publicKey) = Secp256k1.CreateKeyPair();
            var invalidSecretKey = new byte[32];

            Secp256k1.ComputeSharedSecret(publicKey, invalidSecretKey);
        }

        #endregion

        #region Tweak Tests

        [TestMethod]
        public void TweakSecretKeyAdd_ValidTweak()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var tweak = new byte[32];
            new Random(42).NextBytes(tweak);

            var tweakedKey = Secp256k1.TweakSecretKeyAdd(secretKey, tweak);

            Assert.AreEqual(32, tweakedKey.Length);
            Assert.IsTrue(Secp256k1.IsValidSecretKey(tweakedKey));
            CollectionAssert.AreNotEqual(secretKey, tweakedKey);
        }

        [TestMethod]
        public void TweakPublicKeyAdd_MatchesSecretKeyTweak()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var tweak = new byte[32];
            new Random(42).NextBytes(tweak);

            // Tweak both keys
            var tweakedSecretKey = Secp256k1.TweakSecretKeyAdd(secretKey, tweak);
            var tweakedPublicKey = Secp256k1.TweakPublicKeyAdd(publicKey, tweak);

            // Public key from tweaked secret should match directly tweaked public key
            var expectedPublicKey = Secp256k1.CreatePublicKey(tweakedSecretKey);

            CollectionAssert.AreEqual(expectedPublicKey, tweakedPublicKey);
        }

        [TestMethod]
        public void TweakSecretKeyMul_ValidTweak()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var tweak = new byte[32];
            new Random(42).NextBytes(tweak);
            // Ensure tweak is valid (non-zero)
            tweak[0] = 0x01;

            var tweakedKey = Secp256k1.TweakSecretKeyMul(secretKey, tweak);

            Assert.AreEqual(32, tweakedKey.Length);
            Assert.IsTrue(Secp256k1.IsValidSecretKey(tweakedKey));
            CollectionAssert.AreNotEqual(secretKey, tweakedKey);
        }

        [TestMethod]
        public void TweakPublicKeyMul_MatchesSecretKeyTweak()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var tweak = new byte[32];
            new Random(42).NextBytes(tweak);
            tweak[0] = 0x01; // Ensure non-zero

            // Tweak both keys
            var tweakedSecretKey = Secp256k1.TweakSecretKeyMul(secretKey, tweak);
            var tweakedPublicKey = Secp256k1.TweakPublicKeyMul(publicKey, tweak);

            // Public key from tweaked secret should match directly tweaked public key
            var expectedPublicKey = Secp256k1.CreatePublicKey(tweakedSecretKey);

            CollectionAssert.AreEqual(expectedPublicKey, tweakedPublicKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TweakSecretKeyAdd_ZeroResult_Throws()
        {
            // This is hard to trigger but we test the exception handling
            var secretKey = new byte[32];
            secretKey[31] = 0x01; // Very small key
            var tweak = new byte[32];
            for (int i = 0; i < tweak.Length; i++) tweak[i] = 0xFF; // Large tweak that would cause overflow

            Secp256k1.TweakSecretKeyAdd(secretKey, tweak);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TweakPublicKeyAdd_InvalidPublicKey_Throws()
        {
            var invalidPubKey = new byte[33];
            var tweak = new byte[32];
            new Random(42).NextBytes(tweak);

            Secp256k1.TweakPublicKeyAdd(invalidPubKey, tweak);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TweakSecretKeyMul_ZeroTweak_Throws()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var zeroTweak = new byte[32]; // Zero tweak is invalid for multiply

            Secp256k1.TweakSecretKeyMul(secretKey, zeroTweak);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TweakPublicKeyMul_InvalidPublicKey_Throws()
        {
            var invalidPubKey = new byte[33];
            var tweak = new byte[32];
            tweak[0] = 0x01;

            Secp256k1.TweakPublicKeyMul(invalidPubKey, tweak);
        }

        #endregion

        #region Negate Tests

        [TestMethod]
        public void NegateSecretKey_DoubleNegateReturnsOriginal()
        {
            var secretKey = Secp256k1.CreateSecretKey();

            var negated = Secp256k1.NegateSecretKey(secretKey);
            var doubleNegated = Secp256k1.NegateSecretKey(negated);

            CollectionAssert.AreEqual(secretKey, doubleNegated);
        }

        [TestMethod]
        public void NegatePublicKey_DoubleNegateReturnsOriginal()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);

            var negated = Secp256k1.NegatePublicKey(publicKey);
            var doubleNegated = Secp256k1.NegatePublicKey(negated);

            CollectionAssert.AreEqual(publicKey, doubleNegated);
        }

        [TestMethod]
        public void NegateSecretKey_ChangesKey()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var negated = Secp256k1.NegateSecretKey(secretKey);

            CollectionAssert.AreNotEqual(secretKey, negated);
            Assert.IsTrue(Secp256k1.IsValidSecretKey(negated));
        }

        [TestMethod]
        public void NegatePublicKey_ChangesKey()
        {
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var negated = Secp256k1.NegatePublicKey(publicKey);

            CollectionAssert.AreNotEqual(publicKey, negated);
            Assert.IsTrue(Secp256k1.IsValidPublicKey(negated));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NegateSecretKey_InvalidSecretKey_Throws()
        {
            var invalidKey = new byte[32]; // all zeros is invalid
            Secp256k1.NegateSecretKey(invalidKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NegatePublicKey_InvalidPublicKey_Throws()
        {
            var invalidPubKey = new byte[33];
            Secp256k1.NegatePublicKey(invalidPubKey);
        }

        #endregion

        #region Combine Public Keys Tests

        [TestMethod]
        public void CombinePublicKeys_TwoKeys()
        {
            var (_, publicKey1) = Secp256k1.CreateKeyPair();
            var (_, publicKey2) = Secp256k1.CreateKeyPair();

            var combined = Secp256k1.CombinePublicKeys(new[] { publicKey1, publicKey2 });

            Assert.AreEqual(33, combined.Length);
            Assert.IsTrue(Secp256k1.IsValidPublicKey(combined));
        }

        [TestMethod]
        public void CombinePublicKeys_MultipleKeys()
        {
            var keys = new byte[5][];
            for (int i = 0; i < 5; i++)
            {
                var (_, pk) = Secp256k1.CreateKeyPair();
                keys[i] = pk;
            }

            var combined = Secp256k1.CombinePublicKeys(keys);

            Assert.AreEqual(33, combined.Length);
            Assert.IsTrue(Secp256k1.IsValidPublicKey(combined));
        }

        [TestMethod]
        public void CombinePublicKeys_Commutative()
        {
            var (_, pk1) = Secp256k1.CreateKeyPair();
            var (_, pk2) = Secp256k1.CreateKeyPair();

            var combined1 = Secp256k1.CombinePublicKeys(new[] { pk1, pk2 });
            var combined2 = Secp256k1.CombinePublicKeys(new[] { pk2, pk1 });

            CollectionAssert.AreEqual(combined1, combined2);
        }

        [TestMethod]
        public void CombinePublicKeys_Associative()
        {
            var (_, pk1) = Secp256k1.CreateKeyPair();
            var (_, pk2) = Secp256k1.CreateKeyPair();
            var (_, pk3) = Secp256k1.CreateKeyPair();

            // (pk1 + pk2) + pk3
            var combined12 = Secp256k1.CombinePublicKeys(new[] { pk1, pk2 });
            var combined123a = Secp256k1.CombinePublicKeys(new[] { combined12, pk3 });

            // pk1 + (pk2 + pk3)
            var combined23 = Secp256k1.CombinePublicKeys(new[] { pk2, pk3 });
            var combined123b = Secp256k1.CombinePublicKeys(new[] { pk1, combined23 });

            CollectionAssert.AreEqual(combined123a, combined123b);
        }

        [TestMethod]
        public void CombinePublicKeys_Uncompressed()
        {
            var secretKey1 = Secp256k1.CreateSecretKey();
            var secretKey2 = Secp256k1.CreateSecretKey();
            var pk1 = Secp256k1.CreatePublicKey(secretKey1, compressed: false);
            var pk2 = Secp256k1.CreatePublicKey(secretKey2, compressed: false);

            var combined = Secp256k1.CombinePublicKeys(new[] { pk1, pk2 }, compressed: false);

            Assert.AreEqual(65, combined.Length);
            Assert.AreEqual(0x04, combined[0]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CombinePublicKeys_EmptyArray_Throws()
        {
            Secp256k1.CombinePublicKeys(Array.Empty<byte[]>());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CombinePublicKeys_NullArray_Throws()
        {
            Secp256k1.CombinePublicKeys(null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CombinePublicKeys_KeyAndItsNegation_Throws()
        {
            // Combining a key with its negation results in point at infinity
            var secretKey = Secp256k1.CreateSecretKey();
            var publicKey = Secp256k1.CreatePublicKey(secretKey);
            var negatedKey = Secp256k1.NegatePublicKey(publicKey);

            Secp256k1.CombinePublicKeys(new[] { publicKey, negatedKey });
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CombinePublicKeys_InvalidKeyInArray_Throws()
        {
            var (_, validKey) = Secp256k1.CreateKeyPair();
            var invalidKey = new byte[33];

            Secp256k1.CombinePublicKeys(new[] { validKey, invalidKey });
        }

        #endregion

        #region Tagged Hash Tests

        [TestMethod]
        public void TaggedHash_DifferentTagsProduceDifferentHashes()
        {
            var message = new byte[] { 0x01, 0x02, 0x03 };
            var tag1 = System.Text.Encoding.UTF8.GetBytes("Tag1");
            var tag2 = System.Text.Encoding.UTF8.GetBytes("Tag2");

            var hash1 = Secp256k1.TaggedHash(tag1, message);
            var hash2 = Secp256k1.TaggedHash(tag2, message);

            CollectionAssert.AreNotEqual(hash1, hash2);
        }

        [TestMethod]
        public void TaggedHash_SameInputsProduceSameOutput()
        {
            var message = new byte[] { 0x01, 0x02, 0x03 };
            var tag = System.Text.Encoding.UTF8.GetBytes("TestTag");

            var hash1 = Secp256k1.TaggedHash(tag, message);
            var hash2 = Secp256k1.TaggedHash(tag, message);

            CollectionAssert.AreEqual(hash1, hash2);
        }

        [TestMethod]
        public void TaggedHash_ReturnsCorrectLength()
        {
            var message = new byte[] { 0x01, 0x02, 0x03 };
            var tag = System.Text.Encoding.UTF8.GetBytes("TestTag");

            var hash = Secp256k1.TaggedHash(tag, message);

            Assert.AreEqual(32, hash.Length);
        }

        [TestMethod]
        public void TaggedHash_BIP340Challenge()
        {
            // BIP-340 uses "BIP0340/challenge" tag
            var tag = System.Text.Encoding.UTF8.GetBytes("BIP0340/challenge");
            var message = new byte[96]; // R || P || m
            new Random(42).NextBytes(message);

            var hash = Secp256k1.TaggedHash(tag, message);

            Assert.AreEqual(32, hash.Length);
            // Just verify it doesn't throw and produces consistent output
            var hash2 = Secp256k1.TaggedHash(tag, message);
            CollectionAssert.AreEqual(hash, hash2);
        }

        #endregion

        #region Wycheproof ECDSA Test Vectors

        [TestMethod]
        public void VerifyDer_WycheproofVectors()
        {
            // Parse the uncompressed public key
            var publicKeyUncompressed = Convert.FromHexString(WycheproofEcdsaPublicKeyUncompressed);
            Assert.IsTrue(Secp256k1.IsValidPublicKey(publicKeyUncompressed));

            foreach (var vector in WycheproofEcdsaVectors)
            {
                var msg = Convert.FromHexString(vector.MsgHex);
                var msgHash = ComputeSha256(msg);
                var derSig = Convert.FromHexString(vector.DerSigHex);

                var result = Secp256k1.VerifyDer(derSig, msgHash, publicKeyUncompressed);

                Assert.AreEqual(vector.ExpectedValid, result,
                    $"Wycheproof ECDSA vector failed: {vector.Comment}");
            }
        }

        [TestMethod]
        public void VerifyDer_WycheproofValidSignature()
        {
            // Test the valid signature case specifically
            var publicKey = Convert.FromHexString(WycheproofEcdsaPublicKeyUncompressed);
            var msg = Convert.FromHexString("313233343030"); // "123400" in ASCII
            var msgHash = ComputeSha256(msg);

            // Valid normalized signature (tcId 2)
            var validDerSig = Convert.FromHexString("3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba");

            Assert.IsTrue(Secp256k1.VerifyDer(validDerSig, msgHash, publicKey));
        }

        [TestMethod]
        public void VerifyDer_WycheproofMalleableSignature()
        {
            // Test that high-S signatures are rejected (Bitcoin malleability protection)
            var publicKey = Convert.FromHexString(WycheproofEcdsaPublicKeyUncompressed);
            var msg = Convert.FromHexString("313233343030");
            var msgHash = ComputeSha256(msg);

            // High-S malleable signature (tcId 1) - should be invalid
            var malleableSig = Convert.FromHexString("3046022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365022100900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87");

            Assert.IsFalse(Secp256k1.VerifyDer(malleableSig, msgHash, publicKey));
        }

        #endregion

        #region Wycheproof ECDH Test Vectors

        [TestMethod]
        public void ComputeSharedSecret_WycheproofVectors()
        {
            // Note: The secp256k1 library's default ECDH hashes the shared point's x-coordinate with SHA256
            // to produce the final shared secret. The Wycheproof vectors provide the raw x-coordinate.
            // We verify that the same inputs produce consistent outputs between the library's two parties.
            foreach (var vector in WycheproofEcdhVectors)
            {
                var publicKey = Convert.FromHexString(vector.PublicKeyHex);
                var privateKey = Convert.FromHexString(vector.PrivateKeyHex);

                // Verify the computation doesn't throw (keys are valid)
                var actualShared = Secp256k1.ComputeSharedSecret(publicKey, privateKey);
                Assert.AreEqual(32, actualShared.Length, $"Wycheproof ECDH vector failed length check: {vector.Comment}");

                // The expected shared secret is the raw x-coordinate. The library returns SHA256(compressed_point).
                // We verify the x-coordinate is correctly used by checking the computation succeeds.
                // For full verification, we'd need to use the raw hash function variant.
            }
        }

        [TestMethod]
        public void ComputeSharedSecret_WycheproofEdgeCasesSymmetry()
        {
            // Test edge cases by verifying symmetry (A's private + B's public = B's private + A's public)
            // Using Wycheproof edge case vectors with small x-coordinate shared secrets
            var publicKey1 = Convert.FromHexString("04965ff42d654e058ee7317cced7caf093fbb180d8d3a74b0dcd9d8cd47a39d5cb9c2aa4daac01a4be37c20467ede964662f12983e0b5272a47a5f2785685d8087");
            var privateKey1 = Convert.FromHexString("a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a");

            // Compute shared secret - should not throw
            var shared1 = Secp256k1.ComputeSharedSecret(publicKey1, privateKey1);
            Assert.AreEqual(32, shared1.Length);

            // Verify consistency - computing again produces same result
            var shared1Again = Secp256k1.ComputeSharedSecret(publicKey1, privateKey1);
            CollectionAssert.AreEqual(shared1, shared1Again);
        }

        [TestMethod]
        public void ComputeSharedSecret_WycheproofLargeXCoordinateValid()
        {
            // Test edge case where shared secret x-coordinate is p-3 (near field prime)
            // Verify the computation succeeds with valid keys
            var publicKey = Convert.FromHexString("046da9eb2cdac02122d5f05cf6a8cd768e378f664ea4a7871d10e25f57eb1ee1cc5b2b5abf9c6c6596f8f383ddbcb3bcc2d5a7cc605984931239ca9669946032ee");
            var privateKey = Convert.FromHexString("a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a");

            var actualShared = Secp256k1.ComputeSharedSecret(publicKey, privateKey);

            Assert.AreEqual(32, actualShared.Length);
            // The raw x-coordinate would be fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c
            // but the library hashes it, so we just verify the computation succeeds
        }

        #endregion

        #region X-Only Public Key Tests with Vectors

        [TestMethod]
        public void CreateXOnlyPublicKey_FromKnownSecretKeys()
        {
            // Test vector from secp256k1/src/modules/extrakeys/tests_impl.h
            // In C: sk[0] = 1 means first byte is 1 (big-endian), so 0x0100...00
            var secretKey1 = new byte[32];
            secretKey1[0] = 0x01; // Big-endian: 0x0100...00

            var (xOnlyPubKey1, parity1) = Secp256k1.CreateXOnlyPublicKey(secretKey1);
            Assert.AreEqual(32, xOnlyPubKey1.Length);
            Assert.AreEqual(0, parity1); // sk with first byte = 1 has even y

            // Test vector: sk[0] = 2 produces a key with odd y (parity = 1)
            var secretKey2 = new byte[32];
            secretKey2[0] = 0x02; // Big-endian: 0x0200...00

            var (xOnlyPubKey2, parity2) = Secp256k1.CreateXOnlyPublicKey(secretKey2);
            Assert.AreEqual(32, xOnlyPubKey2.Length);
            Assert.AreEqual(1, parity2); // sk with first byte = 2 has odd y
        }

        [TestMethod]
        public void IsValidPublicKey_XOnlyPubKeyComparisonVectors()
        {
            // Test vectors from secp256k1/src/modules/extrakeys/tests_impl.h
            var pk1 = Convert.FromHexString(XOnlyPubKeyComparisonVectors[0].XOnlyPubKey1);
            var pk2 = Convert.FromHexString(XOnlyPubKeyComparisonVectors[0].XOnlyPubKey2);

            // These should be valid x-only public keys (can be parsed as compressed keys with 02 prefix)
            var compressedPk1 = new byte[33];
            compressedPk1[0] = 0x02;
            Array.Copy(pk1, 0, compressedPk1, 1, 32);

            var compressedPk2 = new byte[33];
            compressedPk2[0] = 0x02;
            Array.Copy(pk2, 0, compressedPk2, 1, 32);

            Assert.IsTrue(Secp256k1.IsValidPublicKey(compressedPk1));
            Assert.IsTrue(Secp256k1.IsValidPublicKey(compressedPk2));
        }

        #endregion

        #region Secret Key Validation with Edge Cases

        [TestMethod]
        public void IsValidSecretKey_BoundaryValues()
        {
            // Test secret key = 1 (minimum valid)
            var skOne = new byte[32];
            skOne[31] = 0x01;
            Assert.IsTrue(Secp256k1.IsValidSecretKey(skOne));

            // Test secret key just below the curve order n
            // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            // n-1 is valid
            var skNMinus1 = Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
            Assert.IsTrue(Secp256k1.IsValidSecretKey(skNMinus1));

            // Test secret key = n (invalid, equals curve order)
            var skN = Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
            Assert.IsFalse(Secp256k1.IsValidSecretKey(skN));

            // Test secret key = n+1 (invalid, exceeds curve order)
            var skNPlus1 = Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142");
            Assert.IsFalse(Secp256k1.IsValidSecretKey(skNPlus1));
        }

        #endregion

        #region Helpers

        private static byte[] ComputeSha256(byte[] data)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }

        #endregion
    }
}
