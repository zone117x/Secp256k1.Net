using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Secp256k1Net.Test
{
    [TestClass]
    public class Tests
    {
        [TestMethod]
        public void ReadmeExample()
        {
            // Create a secp256k1 context (ensure disposal to prevent unmanaged memory leaks)
            using var secp256k1 = new Secp256k1();

            // Generate a private key
            var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH];
            var rnd = System.Security.Cryptography.RandomNumberGenerator.Create();
            do { rnd.GetBytes(privateKey); }
            while (!secp256k1.SecretKeyVerify(privateKey));

            // Create public key from private key
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeyCreate(publicKey, privateKey));

            // Serialize the public key to compressed format
            var serializedKey = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeySerialize(serializedKey, publicKey, Flags.SECP256K1_EC_COMPRESSED));

            // Sign a message hash
            var messageBytes = System.Text.Encoding.UTF8.GetBytes("Hello world.");
            var messageHash = System.Security.Cryptography.SHA256.Create().ComputeHash(messageBytes);
            var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
            Assert.IsTrue(secp256k1.Sign(signature, messageHash, privateKey));

            // Verify message hash
            Assert.IsTrue(secp256k1.Verify(signature, messageHash, publicKey));
        }

        [TestMethod]
        public void EcdhTest()
        {
            using var secp256k1 = new Secp256k1();

            var aliceKeyPair = new
            {
                PrivateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe"),
                PublicKey = Convert.FromHexString("2208d5dc41d4f3ed555aff761e9bb0b99fbe6d1503b98711944be6a362242ebfa1c788c7a4e13f6aaa4099f9d2175fc031e5aa3ba08eb280e87dfb43bdae207f")
            };
            var bobKeyPair = new
            {
                PrivateKey = Convert.FromHexString("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda"),
                PublicKey = Convert.FromHexString("62127c4563f711169b1d3e56a34f218302a2587c3725bd418b9388933373e095d45ec4d74ca734599598c89d7719bda5fb799afeec89c6940d569e05bd5a1bba")
            };

            // Create secret using Alice's public key and Bob's private key
            var secret1 = new byte[Secp256k1.SECRET_LENGTH];
            Assert.IsTrue(secp256k1.Ecdh(secret1, aliceKeyPair.PublicKey, bobKeyPair.PrivateKey));

            // Create secret using Bob's public key and Alice's private key
            var secret2 = new byte[Secp256k1.SECRET_LENGTH];
            Assert.IsTrue(secp256k1.Ecdh(secret2, bobKeyPair.PublicKey, aliceKeyPair.PrivateKey));

            // Validate secrets match
            Assert.AreEqual(Convert.ToHexString(secret1), Convert.ToHexString(secret2));

            // Create (useless/invalid) secret using only Alice's key pair
            var secret3 = new byte[Secp256k1.SECRET_LENGTH];
            Assert.IsTrue(secp256k1.Ecdh(secret3, aliceKeyPair.PublicKey, aliceKeyPair.PrivateKey));

            // Validate invalid secret does not match
            Assert.AreNotEqual(Convert.ToHexString(secret3), Convert.ToHexString(secret2));
        }

        [TestMethod]
        public void EcdhTestCustomHash()
        {
            using var secp256k1 = new Secp256k1();
            var keypair1 = new
            {
                PrivateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe"),
                PublicKey = Convert.FromHexString("2208d5dc41d4f3ed555aff761e9bb0b99fbe6d1503b98711944be6a362242ebfa1c788c7a4e13f6aaa4099f9d2175fc031e5aa3ba08eb280e87dfb43bdae207f")
            };
            var keypair2 = new
            {
                PrivateKey = Convert.FromHexString("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda"),
                PublicKey = Convert.FromHexString("62127c4563f711169b1d3e56a34f218302a2587c3725bd418b9388933373e095d45ec4d74ca734599598c89d7719bda5fb799afeec89c6940d569e05bd5a1bba")
            };

            EcdhHashFunction hashFunc = (Span<byte> output, Span<byte> x, Span<byte> y, IntPtr data) =>
            {
                // XOR points together (dumb)
                for (var i = 0; i < Secp256k1.HASH_LENGTH; i++)
                {
                    output[i] = (byte)(x[i] ^ y[i]);
                }
                return 1;
            };

            var sec1 = new byte[Secp256k1.SECRET_LENGTH];
            Assert.IsTrue(secp256k1.Ecdh(sec1, keypair1.PublicKey, keypair2.PrivateKey, hashFunc, IntPtr.Zero));

            var sec2 = new byte[Secp256k1.SECRET_LENGTH];
            Assert.IsTrue(secp256k1.Ecdh(sec2, keypair2.PublicKey, keypair1.PrivateKey, hashFunc, IntPtr.Zero));

            var sec3 = new byte[Secp256k1.SECRET_LENGTH];
            Assert.IsTrue(secp256k1.Ecdh(sec3, keypair1.PublicKey, keypair1.PrivateKey, hashFunc, IntPtr.Zero));

            Assert.AreEqual(Convert.ToHexString(sec1), Convert.ToHexString(sec2));
            Assert.AreNotEqual(Convert.ToHexString(sec3), Convert.ToHexString(sec2));
        }

        [TestMethod]
        public void KeyPairGeneration()
        {
            using var secp256k1 = new Secp256k1();

            // Generate a private key
            var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH];
            var rnd = System.Security.Cryptography.RandomNumberGenerator.Create();
            do { rnd.GetBytes(privateKey); }
            while (!secp256k1.SecretKeyVerify(privateKey));

            // Derive public key bytes
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeyCreate(publicKey, privateKey), "Public key creation failed");

            // Serialize the public key to compressed format
            var serializedCompressedPublicKey = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeySerialize(serializedCompressedPublicKey, publicKey, Flags.SECP256K1_EC_COMPRESSED));

            // Serialize the public key to uncompressed format
            var serializedUncompressedPublicKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeySerialize(serializedUncompressedPublicKey, publicKey, Flags.SECP256K1_EC_UNCOMPRESSED));

            // Parse public key from serialized compressed public key
            var parsedPublicKey1 = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeyParse(parsedPublicKey1, serializedCompressedPublicKey));
            Assert.AreEqual(Convert.ToHexString(publicKey), Convert.ToHexString(parsedPublicKey1));

            // Parse public key from serialied uncompressed public key
            var parsedPublicKey2 = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeyParse(parsedPublicKey2, serializedUncompressedPublicKey));
            Assert.AreEqual(Convert.ToHexString(publicKey), Convert.ToHexString(parsedPublicKey2));
        }

        [TestMethod]
        public void SignAndVerify()
        {
            using var secp256k1 = new Secp256k1();
            var keypair = new
            {
                PrivateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe"),
                PublicKey = Convert.FromHexString("2208d5dc41d4f3ed555aff761e9bb0b99fbe6d1503b98711944be6a362242ebfa1c788c7a4e13f6aaa4099f9d2175fc031e5aa3ba08eb280e87dfb43bdae207f")
            };

            var msgBytes = System.Text.Encoding.UTF8.GetBytes("Hello!!");
            var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);
            Assert.AreEqual(Secp256k1.HASH_LENGTH, msgHash.Length);

            var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
            Assert.IsTrue(secp256k1.Sign(signature, msgHash, keypair.PrivateKey));
            Assert.IsTrue(secp256k1.Verify(signature, msgHash, keypair.PublicKey));
        }

        [TestMethod]
        public void SerializeSignature()
        {
            using var secp256k1 = new Secp256k1();
            var keypair = new
            {
                PrivateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe"),
                PublicKey = Convert.FromHexString("2208d5dc41d4f3ed555aff761e9bb0b99fbe6d1503b98711944be6a362242ebfa1c788c7a4e13f6aaa4099f9d2175fc031e5aa3ba08eb280e87dfb43bdae207f")
            };

            var msgBytes = System.Text.Encoding.UTF8.GetBytes("Hello!!");
            var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);
            Assert.AreEqual(Secp256k1.HASH_LENGTH, msgHash.Length);

            var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
            Assert.IsTrue(secp256k1.Sign(signature, msgHash, keypair.PrivateKey));

            var serialiedSignature = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            Assert.IsTrue(secp256k1.SignatureSerializeCompact(serialiedSignature, signature));

            var expectedSerializedSig = "A480EA494EB5648A3D034444A5D79E9DB53CFF6F8E55E9231B80D3C09EC6B6C4551D740AB96DE6B74A9BCDCD6C40CB6E5312A9CFD896C12D46BB1C945EA6A5C7";
            Assert.AreEqual(expectedSerializedSig, Convert.ToHexString(serialiedSignature));

            var parsedSig = new byte[Secp256k1.SIGNATURE_LENGTH];
            Assert.IsTrue(secp256k1.SignatureParseCompact(parsedSig, serialiedSignature));
            Assert.AreEqual(Convert.ToHexString(signature), Convert.ToHexString(parsedSig));
        }

        [TestMethod]
        public void DerSignatureTest()
        {
            using var secp256k1 = new Secp256k1();

            // Parse DER signature
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var derSignature = Convert.FromHexString("30440220484ECE2B365D2B2C2EAD34B518328BBFEF0F4409349EEEC9CB19837B5795A5F5022040C4F6901FE489F923C49D4104554FD08595EAF864137F87DADDD0E3619B0605");
            Assert.IsTrue(secp256k1.SignatureParseDer(signatureOutput, derSignature));

            // Serialize DER signature
            Span<byte> derSignatureOutput = new byte[Secp256k1.SERIALIZED_DER_SIGNATURE_MAX_SIZE];
            Assert.IsTrue(secp256k1.SignatureSerializeDer(derSignatureOutput, signatureOutput, out int signatureOutputLength));
            derSignatureOutput = derSignatureOutput.Slice(0, signatureOutputLength);

            // Validate signature is the same after round trip parse and serialize
            Assert.AreEqual(Convert.ToHexString(derSignature), Convert.ToHexString(derSignatureOutput));

            // Ensure invalid signature does not parse
            var invalidSignatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var invalidDerSignature = Convert.FromHexString("00");
            Assert.IsFalse(secp256k1.SignatureParseDer(invalidSignatureOutput, invalidDerSignature));
        }

        [TestMethod]
        public void SignatureNormalizeAlreadyLowerS()
        {
            using var secp256k1 = new Secp256k1();
            var sigInput = Convert.FromHexString("6d23167e4ef7df78cc9798de17a2b7aeeff8d312cc06ac655077a8383c646698933defe2dd8ca3d9849f471336a28a4d03245a071423ce6b0d220a8d3ed4d468");
            var sigOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var normalized = secp256k1.SignatureNormalize(sigOutput, sigInput);
            Assert.IsFalse(normalized);
            Assert.AreEqual(Convert.ToHexString(sigInput), Convert.ToHexString(sigOutput));
        }

        [TestMethod]
        public void SignatureNormalizeNotLowerS()
        {
            using var secp256k1 = new Secp256k1();
            var sigInput = Convert.FromHexString("376254344f1a2cfea28440d4d9af56331c1b9e7f5d0f9540a667b48a962605c83536193faed4fa6c58aafd19fe18b4d67d07303cb4c909bc5aa93788a8a0fdf9");
            var sigOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var normalized = secp256k1.SignatureNormalize(sigOutput, sigInput);
            Assert.IsTrue(normalized);
            Assert.AreNotEqual(Convert.ToHexString(sigInput), Convert.ToHexString(sigOutput));
        }

        [TestMethod]
        public void SignatureRecoveryTest()
        {
            using var secp256k1 = new Secp256k1();

            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var messageHash = Convert.FromHexString("c9f1c76685845ea81cac9925a7565887b7771b34b35e641cca85db9fefd0e71f");
            var secretKey = Convert.FromHexString("e815acba8fcf085a0b4141060c13b8017a08da37f2eb1d6a5416adbb621560ef");

            Assert.IsTrue(secp256k1.SignRecoverable(signature, messageHash, secretKey));

            // Recover the public key
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.Recover(publicKeyOutput, signature, messageHash));

            // Serialize the public key
            Span<byte> serializedKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeySerialize(serializedKey, publicKeyOutput));

            // Slice off any prefix.
            serializedKey = serializedKey.Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

            Assert.AreEqual("3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", Convert.ToHexString(serializedKey), true);

            // Verify it works with variables generated from our managed code.
            byte[] ecdsa_r = Convert.FromHexString("9866643c38a8775065ac06cc12d3f8efaeb7a217de9897cc78dff74e7e16236d");
            byte[] ecdsa_s = Convert.FromHexString("68d4d43e8d0a220d6bce2314075a24034d8aa23613479f84d9a38cdde2ef3d93");
            byte recoveryId = 1;

            // Allocate memory for the signature and create a serialized-format signature to deserialize into our native format (platform dependent, hence why we do this).
            var serializedSignature = ecdsa_r.Concat(ecdsa_s).ToArray();
            signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            Assert.IsTrue(secp256k1.RecoverableSignatureParseCompact(signature, serializedSignature, recoveryId));

            // Create a serialized signature in compact format (64 bytes + recovery ID)
            var serializedSignatureOutput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            Assert.IsTrue(secp256k1.RecoverableSignatureSerializeCompact(serializedSignatureOutput, out var recoveryIdOutput, signature));
            Assert.AreEqual(recoveryId, (byte)recoveryIdOutput);
            Assert.AreEqual(Convert.ToHexString(serializedSignature), Convert.ToHexString(serializedSignatureOutput));

            // Recover the public key
            publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.Recover(publicKeyOutput, signature, messageHash));

            // Serialize the public key
            serializedKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeySerialize(serializedKey, publicKeyOutput));

            // Slice off any prefix.
            serializedKey = serializedKey.Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

            // Assert our key
            Assert.AreEqual("3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", Convert.ToHexString(serializedKey), true);
        }

        [TestMethod]
        public void SigAbortTest()
        {
            using var secp256k1 = new Secp256k1();

            byte[] ecdsa_r = Convert.FromHexString("9866643c38a8775065ac06cc12d3f8efaeb7a217de9897cc78dff74e7e16236d");
            byte[] ecdsa_s = Convert.FromHexString("68d4d43e8d0a220d6bce2314075a24034d8aa23613479f84d9a38cdde2ef3d93");

            var signature = ecdsa_r.Concat(ecdsa_s).ToArray();

            // Allocate memory for the signature and create a serialized-format signature to deserialize into our native format (platform dependent, hence why we do this).
            var serializedSignature = ecdsa_r.Concat(ecdsa_s).ToArray();
            signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            byte recoveryId = 9; // incorrect recoveryId,  it should be >=0 and <=3
            // We get SIGABORT here with default error callback  
            var result = secp256k1.RecoverableSignatureParseCompact(signature, serializedSignature, recoveryId);
            Assert.IsFalse(result);
        }

        [TestMethod]
        public unsafe void SigAbortCtorCustomErrorHandlerTest()
        {
            string errorMsg = null;
            var errorCallback = new ErrorCallbackDelegate((msg, data) =>
            {
                errorMsg = "Error message test: " + msg;
            });
            using var secp256k1 = new Secp256k1(errorCallback);

            byte[] ecdsa_r = Convert.FromHexString("9866643c38a8775065ac06cc12d3f8efaeb7a217de9897cc78dff74e7e16236d");
            byte[] ecdsa_s = Convert.FromHexString("68d4d43e8d0a220d6bce2314075a24034d8aa23613479f84d9a38cdde2ef3d93");

            var signature = ecdsa_r.Concat(ecdsa_s).ToArray();

            // Allocate memory for the signature and create a serialized-format signature to deserialize into our native format (platform dependent, hence why we do this).
            var serializedSignature = ecdsa_r.Concat(ecdsa_s).ToArray();
            signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            byte recoveryId = 9; // incorrect recoveryId,  it should be >=0 and <=3
            // We get SIGABORT here with default error callback  
            var result = secp256k1.RecoverableSignatureParseCompact(signature, serializedSignature, recoveryId);
            Assert.IsFalse(result);

            Assert.AreEqual("Error message test: recid >= 0 && recid <= 3", errorMsg);
        }

        [TestMethod]
        public unsafe void SigAbortSetCustomErrorHandlerTest()
        {
            string errorMsg = null;
            var errorCallback = new ErrorCallbackDelegate((msg, data) =>
            {
                errorMsg = "Error message test: " + msg;
            });
            using var secp256k1 = new Secp256k1();

            secp256k1.SetErrorCallback(errorCallback);
            byte[] ecdsa_r = Convert.FromHexString("9866643c38a8775065ac06cc12d3f8efaeb7a217de9897cc78dff74e7e16236d");
            byte[] ecdsa_s = Convert.FromHexString("68d4d43e8d0a220d6bce2314075a24034d8aa23613479f84d9a38cdde2ef3d93");

            var signature = ecdsa_r.Concat(ecdsa_s).ToArray();

            // Allocate memory for the signature and create a serialized-format signature to deserialize into our native format (platform dependent, hence why we do this).
            var serializedSignature = ecdsa_r.Concat(ecdsa_s).ToArray();
            signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            byte recoveryId = 9; // incorrect recoveryId,  it should be >=0 and <=3
            // We get SIGABORT here with default error callback  
            var result = secp256k1.RecoverableSignatureParseCompact(signature, serializedSignature, recoveryId);
            Assert.IsFalse(result);
            Assert.AreEqual("Error message test: recid >= 0 && recid <= 3", errorMsg);
        }

        [TestMethod]
        public void LibPathProperty_ReturnsValidPath()
        {
            // Access the static LibPath property to ensure it's covered
            var libPath = Secp256k1.LibPath;
            Assert.IsNotNull(libPath);
            Assert.IsTrue(File.Exists(libPath), $"LibPath should point to an existing file: {libPath}");
        }

        [TestMethod]
        public void NativeLibResolveLoadClose()
        {
            var origLibPath = LibPathResolver.Resolve(Secp256k1.LIB);
            var tempLibPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            try
            {
                File.Copy(origLibPath, tempLibPath, overwrite: true);
                var libPtr = LoadLibNative.LoadLib(tempLibPath);
                LoadLibNative.CloseLibrary(libPtr);
            }
            finally
            {
                File.Delete(tempLibPath);
            }
        }

        [TestMethod]
        public void NativeLibResolveFailure()
        {
            var exception = Assert.ThrowsException<Exception>(() =>
            {
                LibPathResolver.Resolve("invalid_lib_test_123456");
            });
            StringAssert.Contains(exception.Message, "lib not found");
        }

        [TestMethod]
        public void NativeLibResolveWithExtraSearchPaths()
        {
            // Copy the native library to a temp directory with a unique name
            var origLibPath = LibPathResolver.Resolve(Secp256k1.LIB);
            var tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(tempDir);

            // Create a unique library name and copy with platform-appropriate naming
            var uniqueLibName = "testlib_" + Guid.NewGuid().ToString("N").Substring(0, 8);
            var origFileName = Path.GetFileName(origLibPath);
            var newFileName = origFileName.Replace(Secp256k1.LIB, uniqueLibName);
            var tempLibPath = Path.Combine(tempDir, newFileName);

            try
            {
                File.Copy(origLibPath, tempLibPath, overwrite: true);

                // Add the temp directory to extra search paths
                LibPathResolver.ExtraNativeLibSearchPaths.Add(tempDir);

                // Resolve the unique library name - should find it in our extra path
                var resolvedPath = LibPathResolver.Resolve(uniqueLibName);

                // Verify the resolved path matches our temp file
                Assert.AreEqual(tempLibPath, resolvedPath, "Library should be resolved from ExtraNativeLibSearchPaths");

                // Actually load the library to prove it works
                var libPtr = LoadLibNative.LoadLib(resolvedPath);
                Assert.AreNotEqual(IntPtr.Zero, libPtr, "Library should load successfully");
                LoadLibNative.CloseLibrary(libPtr);
            }
            finally
            {
                LibPathResolver.ExtraNativeLibSearchPaths.Remove(tempDir);
                if (File.Exists(tempLibPath))
                    File.Delete(tempLibPath);
                if (Directory.Exists(tempDir))
                    Directory.Delete(tempDir);
            }
        }

        [TestMethod]
        public void NativeLibLoadFailure()
        {
            var exception = Assert.ThrowsException<Exception>(() =>
            {
                LoadLibNative.LoadLib("invalid_lib_test_123456");
            });
            StringAssert.Contains(exception.Message, "loading failed");
        }

        [TestMethod]
        [Ignore]
        public void NativeLibCloseFailure()
        {
            var exception = Assert.ThrowsException<Exception>(() =>
            {
                LoadLibNative.CloseLibrary(new IntPtr(int.MaxValue));
            });
            StringAssert.Contains(exception.Message, "closing failed");
        }

        [TestMethod]
        public void NativeLibSymbolLoadFailure()
        {
            var libPath = LibPathResolver.Resolve(Secp256k1.LIB);
            var libPtr = LoadLibNative.LoadLib(libPath);
            var exception = Assert.ThrowsException<Exception>(() =>
            {
                LoadLibNative.GetDelegate<Action>(libPtr, "invalid_symbol_name_test_123456");
            });
            StringAssert.Contains(exception.Message, "symbol failed");
        }

        [TestMethod]
        public void PublicKeyNegateTest()
        {
            using var secp256k1 = new Secp256k1();
            var publicKeyOriginal =
                Convert.FromHexString(
                    "2208D5DC41D4F3ED555AFF761E9BB0B99FBE6D1503B98711944BE6A362242EBFA1C788C7A4E13F6AAA4099F9D2175FC031E5AA3BA08EB280E87DFB43BDAE207F");
            var publicKeyOutput =
                Convert.FromHexString(
                    "2208D5DC41D4F3ED555AFF761E9BB0B99FBE6D1503B98711944BE6A362242EBF8E3477385A1EC09555BF66062DE8A03FCE1A55C45F714D7F178204BC4251DF80");

            var publicKey = new byte[publicKeyOriginal.Length];
            Buffer.BlockCopy(publicKeyOriginal, 0, publicKey, 0, publicKeyOriginal.Length);
            Assert.IsTrue(secp256k1.PublicKeyNegate(publicKey));
            Assert.IsTrue(publicKeyOutput.SequenceEqual(publicKey));
        }
        
        [TestMethod]
        public void PublicKeysCombineTest()
        {
            using var secp256k1 = new Secp256k1();
            var publicKey1 =
                Convert.FromHexString(
                    "2208D5DC41D4F3ED555AFF761E9BB0B99FBE6D1503B98711944BE6A362242EBFA1C788C7A4E13F6AAA4099F9D2175FC031E5AA3BA08EB280E87DFB43BDAE207F");
            var publicKey2 =
                Convert.FromHexString(
                    "62127C4563F711169B1D3E56A34F218302A2587C3725BD418B9388933373E095D45EC4D74CA734599598C89D7719BDA5FB799AFEEC89C6940D569E05BD5A1BBA");
            var expectedPublicKeyOutput =
                Convert.FromHexString(
                    "75B39FA41258C450F987CB50CC151AA8FADC7BBFFA2B059C50A74A8434DE00726B635A12A12EEDB61E7736AB39740A5B78D2259EC9DF0692A321043D88156DB5");
                
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.PublicKeysCombine(publicKeyOutput, publicKey1, publicKey2));
            Assert.IsTrue(publicKeyOutput.SequenceEqual(expectedPublicKeyOutput));
        }
        
        [TestMethod]
        public void PublicKeyMultiplyTest()
        {
            using var secp256k1 = new Secp256k1();
            var publicKey =
                Convert.FromHexString(
                    "2208D5DC41D4F3ED555AFF761E9BB0B99FBE6D1503B98711944BE6A362242EBFA1C788C7A4E13F6AAA4099F9D2175FC031E5AA3BA08EB280E87DFB43BDAE207F");
            var publicKeyOutput =
                Convert.FromHexString(
                    "F626FF3EF22B127F75374BCD3202229E5AE12B3FB405E6687AFA6527ED300EA31269CC0E59E0D1E37B8FA56B0EA1435FF7F66EA3391EB94BA31E70C99FD70C38");
            var tweak = Convert.FromHexString("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda");
            Assert.IsTrue(secp256k1.PublicKeyMultiply(publicKey, tweak));
            Assert.IsTrue(publicKeyOutput.SequenceEqual(publicKey));

        }

        [TestMethod]
        public void Rfc6979NonceTest()
        {
            // Reference test cases in https://github.com/decred/dcrd/blob/113758cab3304375cbfb7bfbc8e5d75406315d8b/dcrec/secp256k1/nonce_test.go#L40-L143
            using var secp256k1 = new Secp256k1();
            var nonce = Convert.FromHexString("154E92760F77AD9AF6B547EDD6F14AD0FAE023EB2221BC8BE2911675D8A686A3");
            var hash = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000001");
            var secretKey = Convert.FromHexString("0011111111111111111111111111111111111111111111111111111111111111");
            var nonceOutput = new byte[Secp256k1.NONCE_LENGTH];
            var s = Convert.ToHexString(nonceOutput);
            Assert.IsTrue(secp256k1.Rfc6979Nonce(nonceOutput, hash, secretKey, null, null, 0));
            Assert.IsTrue(nonceOutput.SequenceEqual(nonce));
        }

        [TestMethod]
        public void ConcurrentInstanceCreation()
        {
            // Test that creating Secp256k1 instances from multiple threads concurrently
            // does not cause threading issues with Lazy<T> initialization
            const int threadCount = 10;
            const int iterationsPerThread = 100;
            var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();
            var barrier = new System.Threading.Barrier(threadCount);

            var tasks = Enumerable.Range(0, threadCount)
                .Select(_ => Task.Run(() =>
                {
                    try
                    {
                        // Synchronize all threads to start at the same time
                        barrier.SignalAndWait();

                        for (int i = 0; i < iterationsPerThread; i++)
                        {
                            using var secp256k1 = new Secp256k1();

                            // Do some basic operation to ensure the instance works
                            var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH];
                            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
                            new Random().NextBytes(privateKey);
                            secp256k1.PublicKeyCreate(publicKey, privateKey);
                        }
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                }))
                .ToArray();

            Task.WaitAll(tasks);

            Assert.AreEqual(0, exceptions.Count, 
                $"Concurrent instance creation failed with {exceptions.Count} exception(s): " +
                $"{string.Join("; ", exceptions.Select(e => e.Message))}");
        }
    }

    [TestClass]
    public class ArgumentValidationTests
    {

        [TestMethod]
        public void Recover_InvalidPublicKeyOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var message = new byte[32];
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Recover(publicKeyOutput, signature, message));
        }

        [TestMethod]
        public void Recover_InvalidSignature_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE - 1]; // Too small
            var message = new byte[32];
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Recover(publicKeyOutput, signature, message));
        }

        [TestMethod]
        public void Recover_InvalidMessage_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var message = new byte[31]; // Too small
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Recover(publicKeyOutput, signature, message));
        }

        [TestMethod]
        public void SecretKeyVerify_InvalidSecretKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SecretKeyVerify(secretKey));
        }

        [TestMethod]
        public void PublicKeyCreate_InvalidPublicKeyOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small
            var privateKeyInput = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeyCreate(publicKeyOutput, privateKeyInput));
        }

        [TestMethod]
        public void PublicKeyCreate_InvalidPrivateKeyInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            var privateKeyInput = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeyCreate(publicKeyOutput, privateKeyInput));
        }

        [TestMethod]
        public void RecoverableSignatureParseCompact_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE - 1]; // Too small
            var compactSignature = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.RecoverableSignatureParseCompact(signatureOutput, compactSignature, 0));
        }

        [TestMethod]
        public void RecoverableSignatureParseCompact_InvalidCompactSignature_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var compactSignature = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.RecoverableSignatureParseCompact(signatureOutput, compactSignature, 0));
        }

        [TestMethod]
        public void SignRecoverable_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE - 1]; // Too small
            var messageHash = new byte[32];
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignRecoverable(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void SignRecoverable_InvalidMessageHash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var messageHash = new byte[31]; // Too small
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignRecoverable(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void SignRecoverable_InvalidSecretKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var messageHash = new byte[32];
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignRecoverable(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void RecoverableSignatureSerializeCompact_InvalidCompactSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var compactSignatureOutput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE - 1]; // Too small
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.RecoverableSignatureSerializeCompact(compactSignatureOutput, out _, signature));
        }

        [TestMethod]
        public void RecoverableSignatureSerializeCompact_InvalidSignature_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var compactSignatureOutput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.RecoverableSignatureSerializeCompact(compactSignatureOutput, out _, signature));
        }

        [TestMethod]
        public void PublicKeySerialize_InvalidSerializedPublicKeyOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var serializedPublicKeyOutput = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH - 1]; // Too small
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeySerialize(serializedPublicKeyOutput, publicKey));
        }

        [TestMethod]
        public void PublicKeySerialize_InvalidSerializedPublicKeyOutputCompressed_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var serializedPublicKeyOutput = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH - 1]; // Too small
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeySerialize(serializedPublicKeyOutput, publicKey, Flags.SECP256K1_EC_COMPRESSED));
        }

        [TestMethod]
        public void PublicKeySerialize_InvalidPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var serializedPublicKeyOutput = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeySerialize(serializedPublicKeyOutput, publicKey));
        }

        [TestMethod]
        public void PublicKeyParse_InvalidSerializedPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            var serializedPublicKey = new byte[32]; // Wrong size (not 33 or 65)

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeyParse(publicKeyOutput, serializedPublicKey));
        }

        [TestMethod]
        public void PublicKeyParse_InvalidPublicKeyOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small
            var serializedPublicKey = new byte[33]; // Valid size

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeyParse(publicKeyOutput, serializedPublicKey));
        }

        [TestMethod]
        public void SignatureNormalize_InvalidNormalizedSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var normalizedSignatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small
            var signatureInput = new byte[Secp256k1.SIGNATURE_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignatureNormalize(normalizedSignatureOutput, signatureInput));
        }

        [TestMethod]
        public void SignatureNormalize_InvalidSignatureInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var normalizedSignatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var signatureInput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignatureNormalize(normalizedSignatureOutput, signatureInput));
        }

        [TestMethod]
        public void SignatureParseDer_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small
            var derSignature = new byte[72];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignatureParseDer(signatureOutput, derSignature));
        }

        [TestMethod]
        public void SignatureSerializeDer_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SERIALIZED_DER_SIGNATURE_MAX_SIZE - 1]; // Too small
            var signatureInput = new byte[Secp256k1.SIGNATURE_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignatureSerializeDer(signatureOutput, signatureInput, out _));
        }

        [TestMethod]
        public void SignatureSerializeCompact_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE - 1]; // Too small
            var signatureInput = new byte[Secp256k1.SIGNATURE_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignatureSerializeCompact(signatureOutput, signatureInput));
        }

        [TestMethod]
        public void SignatureSerializeCompact_InvalidSignatureInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            var signatureInput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignatureSerializeCompact(signatureOutput, signatureInput));
        }

        [TestMethod]
        public void SignatureParseCompact_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small
            var signatureInput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignatureParseCompact(signatureOutput, signatureInput));
        }

        [TestMethod]
        public void SignatureParseCompact_InvalidSignatureInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var signatureInput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.SignatureParseCompact(signatureOutput, signatureInput));
        }

        [TestMethod]
        public void Verify_InvalidSignature_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small
            var messageHash = new byte[Secp256k1.HASH_LENGTH];
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Verify(signature, messageHash, publicKey));
        }

        [TestMethod]
        public void Verify_InvalidMessageHash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
            var messageHash = new byte[Secp256k1.HASH_LENGTH - 1]; // Too small
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Verify(signature, messageHash, publicKey));
        }

        [TestMethod]
        public void Verify_InvalidPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
            var messageHash = new byte[Secp256k1.HASH_LENGTH];
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Verify(signature, messageHash, publicKey));
        }

        [TestMethod]
        public void Sign_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small
            var messageHash = new byte[Secp256k1.HASH_LENGTH];
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Sign(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void Sign_InvalidMessageHash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var messageHash = new byte[Secp256k1.HASH_LENGTH - 1]; // Too small
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Sign(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void Sign_InvalidSecretKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var messageHash = new byte[Secp256k1.HASH_LENGTH];
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Sign(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void Ecdh_InvalidResultOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var resultOutput = new byte[Secp256k1.SECRET_LENGTH - 1]; // Too small
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Ecdh(resultOutput, publicKey, privateKey));
        }

        [TestMethod]
        public void Ecdh_InvalidPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var resultOutput = new byte[Secp256k1.SECRET_LENGTH];
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small
            var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Ecdh(resultOutput, publicKey, privateKey));
        }

        [TestMethod]
        public void Ecdh_InvalidPrivateKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var resultOutput = new byte[Secp256k1.SECRET_LENGTH];
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Ecdh(resultOutput, publicKey, privateKey));
        }

        [TestMethod]
        public void EcdhWithHashFunction_InvalidResultOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var resultOutput = new byte[Secp256k1.SECRET_LENGTH - 1]; // Too small
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH];
            EcdhHashFunction hashFunc = (Span<byte> o, Span<byte> x, Span<byte> y, IntPtr d) => 1;

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Ecdh(resultOutput, publicKey, privateKey, hashFunc, IntPtr.Zero));
        }

        [TestMethod]
        public void EcdhWithHashFunction_InvalidPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var resultOutput = new byte[Secp256k1.SECRET_LENGTH];
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small
            var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH];
            EcdhHashFunction hashFunc = (Span<byte> o, Span<byte> x, Span<byte> y, IntPtr d) => 1;

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Ecdh(resultOutput, publicKey, privateKey, hashFunc, IntPtr.Zero));
        }

        [TestMethod]
        public void EcdhWithHashFunction_InvalidPrivateKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var resultOutput = new byte[Secp256k1.SECRET_LENGTH];
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            var privateKey = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small
            EcdhHashFunction hashFunc = (Span<byte> o, Span<byte> x, Span<byte> y, IntPtr d) => 1;

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Ecdh(resultOutput, publicKey, privateKey, hashFunc, IntPtr.Zero));
        }

        [TestMethod]
        public void PublicKeysCombine_InvalidOutputPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var outputPublicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small
            var publicKey1 = new byte[Secp256k1.PUBKEY_LENGTH];
            var publicKey2 = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeysCombine(outputPublicKey, publicKey1, publicKey2));
        }

        [TestMethod]
        public void PublicKeysCombine_InvalidPublicKey1_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var outputPublicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            var publicKey1 = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small
            var publicKey2 = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeysCombine(outputPublicKey, publicKey1, publicKey2));
        }

        [TestMethod]
        public void PublicKeysCombine_InvalidPublicKey2_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var outputPublicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            var publicKey1 = new byte[Secp256k1.PUBKEY_LENGTH];
            var publicKey2 = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeysCombine(outputPublicKey, publicKey1, publicKey2));
        }

        [TestMethod]
        public void PublicKeyNegate_InvalidPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeyNegate(publicKey));
        }

        [TestMethod]
        public void PublicKeyMultiply_InvalidPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small
            var tweak = new byte[Secp256k1.SECRET_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeyMultiply(publicKey, tweak));
        }

        [TestMethod]
        public void PublicKeyMultiply_InvalidTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            var tweak = new byte[Secp256k1.SECRET_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.PublicKeyMultiply(publicKey, tweak));
        }

        [TestMethod]
        public void Rfc6979Nonce_InvalidNonceOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonceOutput = new byte[Secp256k1.NONCE_LENGTH - 1]; // Too small
            var hash = new byte[Secp256k1.HASH_LENGTH];
            var secretKey = new byte[Secp256k1.SECRET_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Rfc6979Nonce(nonceOutput, hash, secretKey, null, null, 0));
        }

        [TestMethod]
        public void Rfc6979Nonce_InvalidHash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonceOutput = new byte[Secp256k1.NONCE_LENGTH];
            var hash = new byte[Secp256k1.HASH_LENGTH - 1]; // Too small
            var secretKey = new byte[Secp256k1.SECRET_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Rfc6979Nonce(nonceOutput, hash, secretKey, null, null, 0));
        }

        [TestMethod]
        public void Rfc6979Nonce_InvalidSecretKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonceOutput = new byte[Secp256k1.NONCE_LENGTH];
            var hash = new byte[Secp256k1.HASH_LENGTH];
            var secretKey = new byte[Secp256k1.SECRET_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Rfc6979Nonce(nonceOutput, hash, secretKey, null, null, 0));
        }
    }

#if !NET5_0_OR_GREATER
    static class Convert
    {
        public static byte[] FromHexString(string s)
        {
            return Enumerable.Range(0, s.Length / 2).Select(x => System.Convert.ToByte(s.Substring(x * 2, 2), 16)).ToArray();
        }

        public static string ToHexString(ReadOnlySpan<byte> bytes)
        {
            return BitConverter.ToString(bytes.ToArray()).Replace("-", "");
        }
    }
#endif

}