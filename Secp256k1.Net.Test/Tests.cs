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
            while (!secp256k1.EcSeckeyVerify(privateKey));

            // Create public key from private key
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(publicKey, privateKey));

            // Serialize the public key to compressed format
            var serializedKey = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
            nuint outputLen = (nuint)serializedKey.Length;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(serializedKey, ref outputLen, publicKey, Secp256k1EcFlags.Compressed));

            // Sign a message hash
            var messageBytes = System.Text.Encoding.UTF8.GetBytes("Hello world.");
            var messageHash = System.Security.Cryptography.SHA256.Create().ComputeHash(messageBytes);
            var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
            Assert.IsTrue(secp256k1.EcdsaSign(signature, messageHash, privateKey));

            // Verify message hash
            Assert.IsTrue(secp256k1.EcdsaVerify(signature, messageHash, publicKey));
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

            EcdhHashFunction hashFunc = (Span<byte> output, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, IntPtr data) =>
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
            while (!secp256k1.EcSeckeyVerify(privateKey));

            // Derive public key bytes
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(publicKey, privateKey), "Public key creation failed");

            // Serialize the public key to compressed format
            var serializedCompressedPublicKey = new byte[Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH];
            nuint compressedLen = (nuint)serializedCompressedPublicKey.Length;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(serializedCompressedPublicKey, ref compressedLen, publicKey, Secp256k1EcFlags.Compressed));

            // Serialize the public key to uncompressed format
            var serializedUncompressedPublicKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            nuint uncompressedLen = (nuint)serializedUncompressedPublicKey.Length;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(serializedUncompressedPublicKey, ref uncompressedLen, publicKey, Secp256k1EcFlags.Uncompressed));

            // Parse public key from serialized compressed public key
            var parsedPublicKey1 = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyParse(parsedPublicKey1, serializedCompressedPublicKey));
            Assert.AreEqual(Convert.ToHexString(publicKey), Convert.ToHexString(parsedPublicKey1));

            // Parse public key from serialied uncompressed public key
            var parsedPublicKey2 = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyParse(parsedPublicKey2, serializedUncompressedPublicKey));
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
            Assert.IsTrue(secp256k1.EcdsaSign(signature, msgHash, keypair.PrivateKey));
            Assert.IsTrue(secp256k1.EcdsaVerify(signature, msgHash, keypair.PublicKey));
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
            Assert.IsTrue(secp256k1.EcdsaSign(signature, msgHash, keypair.PrivateKey));

            var serialiedSignature = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            Assert.IsTrue(secp256k1.EcdsaSignatureSerializeCompact(serialiedSignature, signature));

            var expectedSerializedSig = "A480EA494EB5648A3D034444A5D79E9DB53CFF6F8E55E9231B80D3C09EC6B6C4551D740AB96DE6B74A9BCDCD6C40CB6E5312A9CFD896C12D46BB1C945EA6A5C7";
            Assert.AreEqual(expectedSerializedSig, Convert.ToHexString(serialiedSignature));

            var parsedSig = new byte[Secp256k1.SIGNATURE_LENGTH];
            Assert.IsTrue(secp256k1.EcdsaSignatureParseCompact(parsedSig, serialiedSignature));
            Assert.AreEqual(Convert.ToHexString(signature), Convert.ToHexString(parsedSig));
        }

        [TestMethod]
        public void DerSignatureTest()
        {
            using var secp256k1 = new Secp256k1();

            // Parse DER signature
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var derSignature = Convert.FromHexString("30440220484ECE2B365D2B2C2EAD34B518328BBFEF0F4409349EEEC9CB19837B5795A5F5022040C4F6901FE489F923C49D4104554FD08595EAF864137F87DADDD0E3619B0605");
            Assert.IsTrue(secp256k1.EcdsaSignatureParseDer(signatureOutput, derSignature));

            // Serialize DER signature
            var derSignatureOutput = new byte[Secp256k1.SERIALIZED_DER_SIGNATURE_MAX_SIZE];
            nuint derOutputLen = (nuint)derSignatureOutput.Length;
            Assert.IsTrue(secp256k1.EcdsaSignatureSerializeDer(derSignatureOutput, ref derOutputLen, signatureOutput));
            var derSignatureOutputSlice = derSignatureOutput.AsSpan(0, (int)derOutputLen);

            // Validate signature is the same after round trip parse and serialize
            Assert.AreEqual(Convert.ToHexString(derSignature), Convert.ToHexString(derSignatureOutputSlice));

            // Ensure invalid signature does not parse
            var invalidSignatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var invalidDerSignature = Convert.FromHexString("00");
            Assert.IsFalse(secp256k1.EcdsaSignatureParseDer(invalidSignatureOutput, invalidDerSignature));
        }

        [TestMethod]
        public void SignatureNormalizeAlreadyLowerS()
        {
            using var secp256k1 = new Secp256k1();
            var sigInput = Convert.FromHexString("6d23167e4ef7df78cc9798de17a2b7aeeff8d312cc06ac655077a8383c646698933defe2dd8ca3d9849f471336a28a4d03245a071423ce6b0d220a8d3ed4d468");
            var sigOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var normalized = secp256k1.EcdsaSignatureNormalize(sigOutput, sigInput);
            Assert.IsFalse(normalized);
            Assert.AreEqual(Convert.ToHexString(sigInput), Convert.ToHexString(sigOutput));
        }

        [TestMethod]
        public void SignatureNormalizeNotLowerS()
        {
            using var secp256k1 = new Secp256k1();
            var sigInput = Convert.FromHexString("376254344f1a2cfea28440d4d9af56331c1b9e7f5d0f9540a667b48a962605c83536193faed4fa6c58aafd19fe18b4d67d07303cb4c909bc5aa93788a8a0fdf9");
            var sigOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var normalized = secp256k1.EcdsaSignatureNormalize(sigOutput, sigInput);
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

            Assert.IsTrue(secp256k1.EcdsaSignRecoverable(signature, messageHash, secretKey));

            // Recover the public key
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcdsaRecover(publicKeyOutput, signature, messageHash));

            // Serialize the public key
            var serializedKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            nuint outputLen = (nuint)serializedKey.Length;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(serializedKey, ref outputLen, publicKeyOutput, Secp256k1EcFlags.Uncompressed));

            // Slice off any prefix.
            var serializedKeySlice = serializedKey.AsSpan().Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

            Assert.AreEqual("3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", Convert.ToHexString(serializedKeySlice), true);

            // Verify it works with variables generated from our managed code.
            byte[] ecdsa_r = Convert.FromHexString("9866643c38a8775065ac06cc12d3f8efaeb7a217de9897cc78dff74e7e16236d");
            byte[] ecdsa_s = Convert.FromHexString("68d4d43e8d0a220d6bce2314075a24034d8aa23613479f84d9a38cdde2ef3d93");
            byte recoveryId = 1;

            // Allocate memory for the signature and create a serialized-format signature to deserialize into our native format (platform dependent, hence why we do this).
            var serializedSignature = ecdsa_r.Concat(ecdsa_s).ToArray();
            signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            Assert.IsTrue(secp256k1.EcdsaRecoverableSignatureParseCompact(signature, serializedSignature, recoveryId));

            // Create a serialized signature in compact format (64 bytes + recovery ID)
            var serializedSignatureOutput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            Assert.IsTrue(secp256k1.EcdsaRecoverableSignatureSerializeCompact(serializedSignatureOutput, out var recoveryIdOutput, signature));
            Assert.AreEqual(recoveryId, (byte)recoveryIdOutput);
            Assert.AreEqual(Convert.ToHexString(serializedSignature), Convert.ToHexString(serializedSignatureOutput));

            // Recover the public key
            publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcdsaRecover(publicKeyOutput, signature, messageHash));

            // Serialize the public key
            serializedKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            outputLen = (nuint)serializedKey.Length;
            Assert.IsTrue(secp256k1.EcPubkeySerialize(serializedKey, ref outputLen, publicKeyOutput, Secp256k1EcFlags.Uncompressed));

            // Slice off any prefix.
            serializedKeySlice = serializedKey.AsSpan().Slice(serializedKey.Length - Secp256k1.PUBKEY_LENGTH);

            // Assert our key
            Assert.AreEqual("3a2361270fb1bdd220a2fa0f187cc6f85079043a56fb6a968dfad7d7032b07b01213e80ecd4fb41f1500f94698b1117bc9f3335bde5efbb1330271afc6e85e92", Convert.ToHexString(serializedKeySlice), true);
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
            var result = secp256k1.EcdsaRecoverableSignatureParseCompact(signature, serializedSignature, recoveryId);
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
            var result = secp256k1.EcdsaRecoverableSignatureParseCompact(signature, serializedSignature, recoveryId);
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
            var result = secp256k1.EcdsaRecoverableSignatureParseCompact(signature, serializedSignature, recoveryId);
            Assert.IsFalse(result);
            Assert.AreEqual("Error message test: recid >= 0 && recid <= 3", errorMsg);
        }

        [TestMethod]
        public void LibPathProperty_ReturnsValidValue()
        {
            // Access the static LibPath property to ensure it's covered
            var libPath = Secp256k1.LibPath;
            Assert.IsNotNull(libPath);
            // LibPath is either a library name (standard resolution via NativeLibrary.TryLoad)
            // or a full file path (fallback via LibPathResolver)
            var isLibraryName = libPath == "secp256k1" || libPath == "libsecp256k1";
            var isFilePath = File.Exists(libPath);
            Assert.IsTrue(isLibraryName || isFilePath,
                $"LibPath should be either a library name or an existing file path: {libPath}");
        }

        [TestMethod]
        public void NativeLibResolveLoadClose()
        {
            var origLibPath = LibPathResolver.Resolve(Secp256k1.LIB);
            var tempLibPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            try
            {
                File.Copy(origLibPath, tempLibPath, overwrite: true);
                var libPtr = LoadLibNative.LoadLibrary(tempLibPath, out var _);
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
                var libPtr = LoadLibNative.LoadLibrary(resolvedPath, out var _);
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
                LoadLibNative.LoadLibrary("invalid_lib_test_123456", out var _);
            });
        }

        [TestMethod]
        [Ignore]
        public void NativeLibCloseFailure()
        {
            var exception = Assert.ThrowsException<Exception>(() =>
            {
                LoadLibNative.CloseLibrary(new IntPtr(int.MaxValue));
            });
        }

        [TestMethod]
        public void NativeLibSymbolLoadFailure()
        {
            var libPath = LibPathResolver.Resolve(Secp256k1.LIB);
            var libPtr = LoadLibNative.LoadLibrary(libPath, out var _);
            try
            {
                LoadLibNative.GetSymbolPointer(libPtr, "invalid_symbol_name_test_123456");
                Assert.Fail("Expected an exception");
            }
            catch (Exception ex) when (ex is not AssertFailedException)
            {
                // success - any exception was thrown
            }
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
            Assert.IsTrue(secp256k1.EcPubkeyNegate(publicKey));
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
            Assert.IsTrue(secp256k1.EcPubkeyCombine(publicKeyOutput, new[] { publicKey1, publicKey2 }));
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
            Assert.IsTrue(secp256k1.EcPubkeyTweakMul(publicKey, tweak));
            Assert.IsTrue(publicKeyOutput.SequenceEqual(publicKey));

        }

        [TestMethod]
        public void NonceFunctionRfc6979Test()
        {
            // Reference test cases in https://github.com/decred/dcrd/blob/113758cab3304375cbfb7bfbc8e5d75406315d8b/dcrec/secp256k1/nonce_test.go#L40-L143
            using var secp256k1 = new Secp256k1();
            var nonce = Convert.FromHexString("154E92760F77AD9AF6B547EDD6F14AD0FAE023EB2221BC8BE2911675D8A686A3");
            var hash = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000001");
            var secretKey = Convert.FromHexString("0011111111111111111111111111111111111111111111111111111111111111");
            var nonceOutput = new byte[Secp256k1.NONCE_LENGTH];
            Assert.IsTrue(secp256k1.NonceFunctionRfc6979(nonceOutput, hash, secretKey, default, default, 0));
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
                            secp256k1.EcPubkeyCreate(publicKey, privateKey);
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
        public void EcdsaRecover_InvalidPublicKeyOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var message = new byte[32];
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaRecover(publicKeyOutput, signature, message));
        }

        [TestMethod]
        public void EcdsaRecover_InvalidSignature_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE - 1]; // Too small
            var message = new byte[32];
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaRecover(publicKeyOutput, signature, message));
        }

        [TestMethod]
        public void EcdsaRecover_InvalidMessage_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var message = new byte[31]; // Too small
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaRecover(publicKeyOutput, signature, message));
        }

        [TestMethod]
        public void EcSeckeyVerify_InvalidSecretKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcSeckeyVerify(secretKey));
        }

        [TestMethod]
        public void EcPubkeyCreate_InvalidPublicKeyOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small
            var privateKeyInput = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyCreate(publicKeyOutput, privateKeyInput));
        }

        [TestMethod]
        public void EcPubkeyCreate_InvalidPrivateKeyInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            var privateKeyInput = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyCreate(publicKeyOutput, privateKeyInput));
        }

        [TestMethod]
        public void EcdsaRecoverableSignatureParseCompact_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE - 1]; // Too small
            var compactSignature = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaRecoverableSignatureParseCompact(signatureOutput, compactSignature, 0));
        }

        [TestMethod]
        public void EcdsaSignRecoverable_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE - 1]; // Too small
            var messageHash = new byte[32];
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSignRecoverable(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void EcdsaSignRecoverable_InvalidMessageHash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var messageHash = new byte[31]; // Too small
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSignRecoverable(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void EcdsaSignRecoverable_InvalidSecretKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            var messageHash = new byte[32];
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSignRecoverable(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void EcdsaRecoverableSignatureSerializeCompact_InvalidSignature_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var compactSignatureOutput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaRecoverableSignatureSerializeCompact(compactSignatureOutput, out _, signature));
        }

        [TestMethod]
        public void EcdsaSignatureNormalize_InvalidSignatureInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var normalizedSignatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var signatureInput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSignatureNormalize(normalizedSignatureOutput, signatureInput));
        }

        [TestMethod]
        public void EcdsaSignatureParseDer_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small
            var derSignature = new byte[72];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSignatureParseDer(signatureOutput, derSignature));
        }

        [TestMethod]
        public void EcdsaSignatureSerializeCompact_InvalidSignatureInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];
            var signatureInput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSignatureSerializeCompact(signatureOutput, signatureInput));
        }

        [TestMethod]
        public void EcdsaSignatureParseCompact_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small
            var signatureInput = new byte[Secp256k1.SERIALIZED_SIGNATURE_SIZE];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSignatureParseCompact(signatureOutput, signatureInput));
        }

        [TestMethod]
        public void EcdsaVerify_InvalidSignature_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small
            var messageHash = new byte[Secp256k1.HASH_LENGTH];
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaVerify(signature, messageHash, publicKey));
        }

        [TestMethod]
        public void EcdsaVerify_InvalidMessageHash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
            var messageHash = new byte[Secp256k1.HASH_LENGTH - 1]; // Too small
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaVerify(signature, messageHash, publicKey));
        }

        [TestMethod]
        public void EcdsaVerify_InvalidPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
            var messageHash = new byte[Secp256k1.HASH_LENGTH];
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaVerify(signature, messageHash, publicKey));
        }

        [TestMethod]
        public void EcdsaSign_InvalidSignatureOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH - 1]; // Too small
            var messageHash = new byte[Secp256k1.HASH_LENGTH];
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSign(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void EcdsaSign_InvalidMessageHash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var messageHash = new byte[Secp256k1.HASH_LENGTH - 1]; // Too small
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSign(signatureOutput, messageHash, secretKey));
        }

        [TestMethod]
        public void EcdsaSign_InvalidSecretKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var signatureOutput = new byte[Secp256k1.SIGNATURE_LENGTH];
            var messageHash = new byte[Secp256k1.HASH_LENGTH];
            var secretKey = new byte[Secp256k1.PRIVKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcdsaSign(signatureOutput, messageHash, secretKey));
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
            EcdhHashFunction hashFunc = (Span<byte> o, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, IntPtr d) => 1;

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
            EcdhHashFunction hashFunc = (Span<byte> o, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, IntPtr d) => 1;

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
            EcdhHashFunction hashFunc = (Span<byte> o, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, IntPtr d) => 1;

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.Ecdh(resultOutput, publicKey, privateKey, hashFunc, IntPtr.Zero));
        }

        [TestMethod]
        public void EcPubkeyCombine_NullArray_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var outputPublicKey = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyCombine(outputPublicKey, null));
        }

        [TestMethod]
        public void EcPubkeyCombine_EmptyArray_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var outputPublicKey = new byte[Secp256k1.PUBKEY_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyCombine(outputPublicKey, new byte[0][]));
        }

        [TestMethod]
        public void EcPubkeyCombine_TooSmallElement_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var outputPublicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            var smallPubkey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyCombine(outputPublicKey, new[] { smallPubkey }));
        }

        [TestMethod]
        public void EcPubkeyNegate_InvalidPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyNegate(publicKey));
        }

        [TestMethod]
        public void EcPubkeyTweakMul_InvalidPublicKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH - 1]; // Too small
            var tweak = new byte[Secp256k1.SECRET_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyTweakMul(publicKey, tweak));
        }

        [TestMethod]
        public void EcPubkeyTweakMul_InvalidTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            var tweak = new byte[Secp256k1.SECRET_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.EcPubkeyTweakMul(publicKey, tweak));
        }

        [TestMethod]
        public void NonceFunctionRfc6979_InvalidNonceOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonceOutput = new byte[Secp256k1.NONCE_LENGTH - 1]; // Too small
            var hash = new byte[Secp256k1.HASH_LENGTH];
            var secretKey = new byte[Secp256k1.SECRET_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.NonceFunctionRfc6979(nonceOutput, hash, secretKey, default, default, 0));
        }

        [TestMethod]
        public void NonceFunctionRfc6979_InvalidHash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonceOutput = new byte[Secp256k1.NONCE_LENGTH];
            var hash = new byte[Secp256k1.HASH_LENGTH - 1]; // Too small
            var secretKey = new byte[Secp256k1.SECRET_LENGTH];

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.NonceFunctionRfc6979(nonceOutput, hash, secretKey, default, default, 0));
        }

        [TestMethod]
        public void NonceFunctionRfc6979_InvalidSecretKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonceOutput = new byte[Secp256k1.NONCE_LENGTH];
            var hash = new byte[Secp256k1.HASH_LENGTH];
            var secretKey = new byte[Secp256k1.SECRET_LENGTH - 1]; // Too small

            Assert.ThrowsException<ArgumentException>(() =>
                secp256k1.NonceFunctionRfc6979(nonceOutput, hash, secretKey, default, default, 0));
        }
    }

    [TestClass]
    public class CustomNonceFunctionTests
    {
        [TestMethod]
        public void EcdsaSign_WithCustomNonceFunction()
        {
            using var secp256k1 = new Secp256k1();
            var keypair = new
            {
                PrivateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe"),
                PublicKey = Convert.FromHexString("2208d5dc41d4f3ed555aff761e9bb0b99fbe6d1503b98711944be6a362242ebfa1c788c7a4e13f6aaa4099f9d2175fc031e5aa3ba08eb280e87dfb43bdae207f")
            };

            var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes("Test message"));

            bool nonceFunctionCalled = false;
            NonceFunction customNonce = (Span<byte> nonce, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> key,
                ReadOnlySpan<byte> algo, IntPtr data, uint attempt) =>
            {
                nonceFunctionCalled = true;
                // Use RFC6979 deterministic nonce generation
                var tempNonce = new byte[32];
                secp256k1.NonceFunctionRfc6979(tempNonce, msg.ToArray(), key.ToArray(), default, default, attempt);
                tempNonce.CopyTo(nonce);
                return 1;
            };

            var signature = new byte[Secp256k1.SIGNATURE_LENGTH];
            Assert.IsTrue(secp256k1.EcdsaSign(signature, msgHash, keypair.PrivateKey, customNonce, IntPtr.Zero));
            Assert.IsTrue(nonceFunctionCalled, "Custom nonce function should have been called");
            Assert.IsTrue(secp256k1.EcdsaVerify(signature, msgHash, keypair.PublicKey));
        }

        [TestMethod]
        public void EcdsaSignRecoverable_WithCustomNonceFunction()
        {
            using var secp256k1 = new Secp256k1();
            var secretKey = Convert.FromHexString("e815acba8fcf085a0b4141060c13b8017a08da37f2eb1d6a5416adbb621560ef");
            var msgHash = Convert.FromHexString("c9f1c76685845ea81cac9925a7565887b7771b34b35e641cca85db9fefd0e71f");

            bool nonceFunctionCalled = false;
            NonceFunction customNonce = (Span<byte> nonce, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> key,
                ReadOnlySpan<byte> algo, IntPtr data, uint attempt) =>
            {
                nonceFunctionCalled = true;
                var tempNonce = new byte[32];
                secp256k1.NonceFunctionRfc6979(tempNonce, msg.ToArray(), key.ToArray(), default, default, attempt);
                tempNonce.CopyTo(nonce);
                return 1;
            };

            var signature = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            Assert.IsTrue(secp256k1.EcdsaSignRecoverable(signature, msgHash, secretKey, customNonce, IntPtr.Zero));
            Assert.IsTrue(nonceFunctionCalled, "Custom nonce function should have been called");

            // Verify we can recover the public key
            var publicKeyOutput = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcdsaRecover(publicKeyOutput, signature, msgHash));
        }
    }

    [TestClass]
    public class SchnorrTests
    {
        [TestMethod]
        public void SchnorrSign32AndVerify()
        {
            using var secp256k1 = new Secp256k1();

            // Generate a keypair
            var privateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var keypair = new byte[96]; // secp256k1_keypair size
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, privateKey));

            // Get the xonly public key
            var xonlyPubkey = new byte[64]; // secp256k1_xonly_pubkey size
            Assert.IsTrue(secp256k1.KeypairXonlyPub(xonlyPubkey, out _, keypair));

            // Sign a message
            var msg32 = System.Security.Cryptography.SHA256.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes("Test message for Schnorr"));
            var auxRand = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(auxRand);

            var sig64 = new byte[64];
            Assert.IsTrue(secp256k1.SchnorrsigSign32(sig64, msg32, keypair, auxRand));

            // Verify the signature
            Assert.IsTrue(secp256k1.SchnorrsigVerify(sig64, msg32, xonlyPubkey));
        }

        [TestMethod]
        public void SchnorrSignCustom()
        {
            using var secp256k1 = new Secp256k1();

            var privateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, privateKey));

            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.KeypairXonlyPub(xonlyPubkey, out _, keypair));

            // Use a variable-length message
            var msg = System.Text.Encoding.UTF8.GetBytes("Variable length message for Schnorr signing");

            // extraparams is a struct with magic bytes and optional nonce function
            // struct secp256k1_schnorrsig_extraparams { unsigned char magic[4]; secp256k1_nonce_function_hardened noncefp; void *ndata; }
            // magic = { 0xDA, 0x6F, 0xB3, 0x8C }
            var extraparams = new byte[64]; // enough space for the struct
            extraparams[0] = 0xDA;
            extraparams[1] = 0x6F;
            extraparams[2] = 0xB3;
            extraparams[3] = 0x8C;

            var sig64 = new byte[64];
            Assert.IsTrue(secp256k1.SchnorrsigSignCustom(sig64, msg, keypair, extraparams));

            // Verify the signature
            Assert.IsTrue(secp256k1.SchnorrsigVerify(sig64, msg, xonlyPubkey));
        }
    }

    [TestClass]
    public class EllswiftTests
    {
        [TestMethod]
        public void EllswiftEncodeAndDecode()
        {
            using var secp256k1 = new Secp256k1();

            // Generate a key pair
            var privateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(publicKey, privateKey));

            // Encode to ellswift format
            var rnd32 = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(rnd32);
            var ell64 = new byte[64];
            Assert.IsTrue(secp256k1.EllswiftEncode(ell64, publicKey, rnd32));

            // Decode back to public key
            var decodedPubkey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EllswiftDecode(decodedPubkey, ell64));

            // The decoded pubkey should match the original
            Assert.AreEqual(Convert.ToHexString(publicKey), Convert.ToHexString(decodedPubkey));
        }

        [TestMethod]
        public void EllswiftCreate()
        {
            using var secp256k1 = new Secp256k1();

            var privateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var auxRand = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(auxRand);

            var ell64 = new byte[64];
            Assert.IsTrue(secp256k1.EllswiftCreate(ell64, privateKey, auxRand));

            // Verify we can decode it and get the correct public key
            var decodedPubkey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EllswiftDecode(decodedPubkey, ell64));

            // Compare with public key derived from private key
            var expectedPubkey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(expectedPubkey, privateKey));
            Assert.AreEqual(Convert.ToHexString(expectedPubkey), Convert.ToHexString(decodedPubkey));
        }

        [TestMethod]
        public void EllswiftXdhKeyExchange()
        {
            using var secp256k1 = new Secp256k1();

            // Alice's keys
            var alicePrivate = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var aliceAuxRand = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(aliceAuxRand);
            var aliceEll64 = new byte[64];
            Assert.IsTrue(secp256k1.EllswiftCreate(aliceEll64, alicePrivate, aliceAuxRand));

            // Bob's keys
            var bobPrivate = Convert.FromHexString("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda");
            var bobAuxRand = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(bobAuxRand);
            var bobEll64 = new byte[64];
            Assert.IsTrue(secp256k1.EllswiftCreate(bobEll64, bobPrivate, bobAuxRand));

            // Custom hash function for XDH
            bool hashFunctionCalled = false;
            EllswiftXdhHashFunction hashFunc = (Span<byte> output, ReadOnlySpan<byte> x32,
                ReadOnlySpan<byte> ell_a64, ReadOnlySpan<byte> ell_b64, IntPtr data) =>
            {
                hashFunctionCalled = true;
                // Simple hash: SHA256 of x32
                var hash = System.Security.Cryptography.SHA256.Create().ComputeHash(x32.ToArray());
                hash.CopyTo(output);
                return 1;
            };

            // Alice computes shared secret (party = 0, Alice is initiator)
            var aliceSecret = new byte[32];
            Assert.IsTrue(secp256k1.EllswiftXdh(aliceSecret, aliceEll64, bobEll64, alicePrivate, 0, hashFunc, IntPtr.Zero));
            Assert.IsTrue(hashFunctionCalled);

            // Bob computes shared secret (party = 1, Bob is responder)
            hashFunctionCalled = false;
            var bobSecret = new byte[32];
            Assert.IsTrue(secp256k1.EllswiftXdh(bobSecret, aliceEll64, bobEll64, bobPrivate, 1, hashFunc, IntPtr.Zero));
            Assert.IsTrue(hashFunctionCalled);

            // Secrets should match
            Assert.AreEqual(Convert.ToHexString(aliceSecret), Convert.ToHexString(bobSecret));
        }

        [TestMethod]
        public void EllswiftXdhHashFunctionPrefixTest()
        {
            using var secp256k1 = new Secp256k1();

            var x32 = new byte[32];
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[64];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(x32);
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(ell_a64);
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(ell_b64);

            var output = new byte[32];
            var data = new byte[1]; // Must be non-empty to avoid pinning empty span
            Assert.IsTrue(secp256k1.EllswiftXdhHashFunctionPrefix(output, x32, ell_a64, ell_b64, data));
            Assert.IsFalse(output.All(b => b == 0), "Output should not be all zeros");
        }

        [TestMethod]
        public void EllswiftXdhHashFunctionBip324Test()
        {
            using var secp256k1 = new Secp256k1();

            var x32 = new byte[32];
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[64];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(x32);
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(ell_a64);
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(ell_b64);

            var output = new byte[32];
            var data = new byte[1]; // Must be non-empty to avoid pinning empty span
            Assert.IsTrue(secp256k1.EllswiftXdhHashFunctionBip324(output, x32, ell_a64, ell_b64, data));
            Assert.IsFalse(output.All(b => b == 0), "Output should not be all zeros");
        }
    }

    [TestClass]
    public class MuSigTests
    {
        [TestMethod]
        public void MusigFullSigningFlow()
        {
            using var secp256k1 = new Secp256k1();

            // Two signers
            var signer1Key = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var signer2Key = Convert.FromHexString("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda");

            // Create keypairs
            var keypair1 = new byte[96];
            var keypair2 = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair1, signer1Key));
            Assert.IsTrue(secp256k1.KeypairCreate(keypair2, signer2Key));

            // Get public keys
            var pubkey1 = new byte[Secp256k1.PUBKEY_LENGTH];
            var pubkey2 = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey1, signer1Key));
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey2, signer2Key));

            // Aggregate public keys
            var aggPubkey = new byte[64]; // secp256k1_xonly_pubkey
            var keyaggCache = new byte[197]; // secp256k1_musig_keyagg_cache
            Assert.IsTrue(secp256k1.MusigPubkeyAgg(aggPubkey, keyaggCache, new[] { pubkey1, pubkey2 }));

            // Test MusigPubkeyGet - returns secp256k1_pubkey (not xonly_pubkey)
            // This is the non-xonly aggregate pubkey, different from aggPubkey which is xonly
            var retrievedAggPubkey = new byte[64]; // secp256k1_pubkey
            Assert.IsTrue(secp256k1.MusigPubkeyGet(retrievedAggPubkey, keyaggCache));
            // Convert the retrieved pubkey to xonly to compare with aggPubkey
            var retrievedXonly = new byte[64];
            Assert.IsTrue(secp256k1.XonlyPubkeyFromPubkey(retrievedXonly, out _, retrievedAggPubkey));
            var retrievedSerialized = new byte[32];
            Assert.IsTrue(secp256k1.XonlyPubkeySerialize(retrievedSerialized, retrievedXonly));
            var aggSerialized = new byte[32];
            Assert.IsTrue(secp256k1.XonlyPubkeySerialize(aggSerialized, aggPubkey));
            Assert.AreEqual(Convert.ToHexString(aggSerialized), Convert.ToHexString(retrievedSerialized));

            // Message to sign
            var msg32 = System.Security.Cryptography.SHA256.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes("MuSig test message"));

            // Generate nonces for both signers
            var secnonce1 = new byte[132]; // secp256k1_musig_secnonce
            var pubnonce1 = new byte[132]; // secp256k1_musig_pubnonce
            var sessionRand1 = new byte[32];
            var extraInput1 = new byte[32]; // extra_input32 must be at least 32 bytes
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(sessionRand1);
            Assert.IsTrue(secp256k1.MusigNonceGen(secnonce1, pubnonce1, sessionRand1, signer1Key, pubkey1, msg32, keyaggCache, extraInput1));

            var secnonce2 = new byte[132];
            var pubnonce2 = new byte[132];
            var sessionRand2 = new byte[32];
            var extraInput2 = new byte[32]; // extra_input32 must be at least 32 bytes
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(sessionRand2);
            Assert.IsTrue(secp256k1.MusigNonceGen(secnonce2, pubnonce2, sessionRand2, signer2Key, pubkey2, msg32, keyaggCache, extraInput2));

            // Serialize and parse pubnonces (test round-trip)
            var pubnonce1Serialized = new byte[66];
            Assert.IsTrue(secp256k1.MusigPubnonceSerialize(pubnonce1Serialized, pubnonce1));
            var pubnonce1Parsed = new byte[132];
            Assert.IsTrue(secp256k1.MusigPubnonceParse(pubnonce1Parsed, pubnonce1Serialized));

            // Aggregate nonces
            var aggnonce = new byte[132]; // secp256k1_musig_aggnonce
            Assert.IsTrue(secp256k1.MusigNonceAgg(aggnonce, new[] { pubnonce1, pubnonce2 }));

            // Serialize and parse aggnonce (test round-trip)
            var aggnonceSerialized = new byte[66];
            Assert.IsTrue(secp256k1.MusigAggnonceSerialize(aggnonceSerialized, aggnonce));
            var aggnonceParsed = new byte[132];
            Assert.IsTrue(secp256k1.MusigAggnonceParse(aggnonceParsed, aggnonceSerialized));

            // Create signing session
            var session = new byte[133]; // secp256k1_musig_session
            Assert.IsTrue(secp256k1.MusigNonceProcess(session, aggnonce, msg32, keyaggCache));

            // Create partial signatures
            var partialSig1 = new byte[36]; // secp256k1_musig_partial_sig
            Assert.IsTrue(secp256k1.MusigPartialSign(partialSig1, secnonce1, keypair1, keyaggCache, session));

            var partialSig2 = new byte[36];
            Assert.IsTrue(secp256k1.MusigPartialSign(partialSig2, secnonce2, keypair2, keyaggCache, session));

            // Verify partial signatures
            Assert.IsTrue(secp256k1.MusigPartialSigVerify(partialSig1, pubnonce1, pubkey1, keyaggCache, session));
            Assert.IsTrue(secp256k1.MusigPartialSigVerify(partialSig2, pubnonce2, pubkey2, keyaggCache, session));

            // Serialize and parse partial sig (test round-trip)
            var partialSig1Serialized = new byte[32];
            Assert.IsTrue(secp256k1.MusigPartialSigSerialize(partialSig1Serialized, partialSig1));
            var partialSig1Parsed = new byte[36];
            Assert.IsTrue(secp256k1.MusigPartialSigParse(partialSig1Parsed, partialSig1Serialized));

            // Aggregate partial signatures into final signature
            var finalSig = new byte[64];
            Assert.IsTrue(secp256k1.MusigPartialSigAgg(finalSig, session, new[] { partialSig1, partialSig2 }));

            // Verify the final Schnorr signature
            Assert.IsTrue(secp256k1.SchnorrsigVerify(finalSig, msg32, aggPubkey));
        }

        [TestMethod]
        public void MusigPubkeyTweakTests()
        {
            using var secp256k1 = new Secp256k1();

            var signer1Key = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var signer2Key = Convert.FromHexString("d8bdb07407bb011137ef7ba6a7f07c6a55c1e3600a6aa138e34ab5c16439ceda");

            var pubkey1 = new byte[Secp256k1.PUBKEY_LENGTH];
            var pubkey2 = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey1, signer1Key));
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey2, signer2Key));

            var aggPubkey = new byte[64];
            var keyaggCache = new byte[197];
            Assert.IsTrue(secp256k1.MusigPubkeyAgg(aggPubkey, keyaggCache, new[] { pubkey1, pubkey2 }));

            var tweak32 = System.Security.Cryptography.SHA256.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes("tweak"));

            // Test EC tweak add
            var tweakedPubkeyEc = new byte[Secp256k1.PUBKEY_LENGTH];
            var keyaggCacheEc = new byte[197];
            Array.Copy(keyaggCache, keyaggCacheEc, keyaggCache.Length);
            Assert.IsTrue(secp256k1.MusigPubkeyEcTweakAdd(tweakedPubkeyEc, keyaggCacheEc, tweak32));

            // Test xonly tweak add
            var tweakedPubkeyXonly = new byte[64];
            var keyaggCacheXonly = new byte[197];
            Array.Copy(keyaggCache, keyaggCacheXonly, keyaggCache.Length);
            Assert.IsTrue(secp256k1.MusigPubkeyXonlyTweakAdd(tweakedPubkeyXonly, keyaggCacheXonly, tweak32));
        }
    }

    [TestClass]
    public class GlobalFunctionWrapperTests
    {
        [TestMethod]
        public void NonceFunctionDefaultTest()
        {
            using var secp256k1 = new Secp256k1();

            var nonce32 = new byte[32];
            var msg32 = System.Security.Cryptography.SHA256.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes("test"));
            var key32 = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");

            Assert.IsTrue(secp256k1.NonceFunctionDefault(nonce32, msg32, key32, default, default, 0));
            Assert.IsFalse(nonce32.All(b => b == 0), "Nonce should not be all zeros");
        }

        [TestMethod]
        public void EcdhHashFunctionDefaultTest()
        {
            using var secp256k1 = new Secp256k1();

            var output = new byte[32];
            var x32 = new byte[32];
            var y32 = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(x32);
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(y32);

            Assert.IsTrue(secp256k1.EcdhHashFunctionDefault(output, x32, y32, default));
            Assert.IsFalse(output.All(b => b == 0), "Output should not be all zeros");
        }

        [TestMethod]
        public void EcdhHashFunctionSha256Test()
        {
            using var secp256k1 = new Secp256k1();

            var output = new byte[32];
            var x32 = new byte[32];
            var y32 = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(x32);
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(y32);

            Assert.IsTrue(secp256k1.EcdhHashFunctionSha256(output, x32, y32, default));
            Assert.IsFalse(output.All(b => b == 0), "Output should not be all zeros");
        }

        [TestMethod]
        public void NonceFunctionBip340Test()
        {
            using var secp256k1 = new Secp256k1();

            var nonce32 = new byte[32];
            var msg = System.Text.Encoding.UTF8.GetBytes("BIP340 test message");
            var key32 = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");

            // Get xonly pubkey
            var pubkey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey, key32));
            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.XonlyPubkeyFromPubkey(xonlyPubkey, out _, pubkey));
            var serializedXonly = new byte[32];
            Assert.IsTrue(secp256k1.XonlyPubkeySerialize(serializedXonly, xonlyPubkey));

            var algo = System.Text.Encoding.UTF8.GetBytes("BIP0340/nonce");

            Assert.IsTrue(secp256k1.NonceFunctionBip340(nonce32, msg, (nuint)msg.Length, key32, serializedXonly, algo, (nuint)algo.Length, default));
            Assert.IsFalse(nonce32.All(b => b == 0), "Nonce should not be all zeros");
        }
    }

    [TestClass]
    public class KeypairAndXonlyTests
    {
        [TestMethod]
        public void KeypairCreateAndExtract()
        {
            using var secp256k1 = new Secp256k1();

            var privateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var keypair = new byte[96];
            Assert.IsTrue(secp256k1.KeypairCreate(keypair, privateKey));

            // Extract public key
            var pubkey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.KeypairPub(pubkey, keypair));

            // Compare with directly created public key
            var expectedPubkey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(expectedPubkey, privateKey));
            Assert.AreEqual(Convert.ToHexString(expectedPubkey), Convert.ToHexString(pubkey));

            // Extract secret key
            var extractedSecret = new byte[32];
            Assert.IsTrue(secp256k1.KeypairSec(extractedSecret, keypair));
            Assert.AreEqual(Convert.ToHexString(privateKey), Convert.ToHexString(extractedSecret));
        }

        [TestMethod]
        public void XonlyPubkeyOperations()
        {
            using var secp256k1 = new Secp256k1();

            var privateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var pubkey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(pubkey, privateKey));

            // Convert to xonly
            var xonlyPubkey = new byte[64];
            Assert.IsTrue(secp256k1.XonlyPubkeyFromPubkey(xonlyPubkey, out int pkParity, pubkey));

            // Serialize xonly pubkey
            var serialized = new byte[32];
            Assert.IsTrue(secp256k1.XonlyPubkeySerialize(serialized, xonlyPubkey));

            // Parse it back
            var parsedXonly = new byte[64];
            Assert.IsTrue(secp256k1.XonlyPubkeyParse(parsedXonly, serialized));
            Assert.AreEqual(Convert.ToHexString(xonlyPubkey), Convert.ToHexString(parsedXonly));

            // Compare xonly pubkeys - returns 0 if equal
            Assert.AreEqual(0, secp256k1.XonlyPubkeyCmp(xonlyPubkey, parsedXonly));

            // Test tweak add
            var tweak = System.Security.Cryptography.SHA256.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes("tweak"));
            var tweakedPubkey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.XonlyPubkeyTweakAdd(tweakedPubkey, xonlyPubkey, tweak));

            // Verify tweak
            var tweakedXonly = new byte[64];
            Assert.IsTrue(secp256k1.XonlyPubkeyFromPubkey(tweakedXonly, out int tweakedParity, tweakedPubkey));
            var tweakedSerialized = new byte[32];
            Assert.IsTrue(secp256k1.XonlyPubkeySerialize(tweakedSerialized, tweakedXonly));
            Assert.IsTrue(secp256k1.XonlyPubkeyTweakAddCheck(tweakedSerialized, tweakedParity, xonlyPubkey, tweak));
        }
    }

    [TestClass]
    public class AdditionalCoverageTests
    {
        [TestMethod]
        public void EcSeckeyTweakAdd()
        {
            using var secp256k1 = new Secp256k1();

            var secretKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var tweak = System.Security.Cryptography.SHA256.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes("tweak"));

            var tweakedKey = new byte[32];
            Array.Copy(secretKey, tweakedKey, 32);
            Assert.IsTrue(secp256k1.EcSeckeyTweakAdd(tweakedKey, tweak));
            Assert.AreNotEqual(Convert.ToHexString(secretKey), Convert.ToHexString(tweakedKey));
        }

        [TestMethod]
        public void EcSeckeyTweakMul()
        {
            using var secp256k1 = new Secp256k1();

            var secretKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var tweak = System.Security.Cryptography.SHA256.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes("tweak"));

            var tweakedKey = new byte[32];
            Array.Copy(secretKey, tweakedKey, 32);
            Assert.IsTrue(secp256k1.EcSeckeyTweakMul(tweakedKey, tweak));
            Assert.AreNotEqual(Convert.ToHexString(secretKey), Convert.ToHexString(tweakedKey));
        }

        [TestMethod]
        public void EcPubkeyTweakAdd()
        {
            using var secp256k1 = new Secp256k1();

            var privateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(publicKey, privateKey));

            var tweak = System.Security.Cryptography.SHA256.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes("tweak"));

            var originalPubkey = Convert.ToHexString(publicKey);
            Assert.IsTrue(secp256k1.EcPubkeyTweakAdd(publicKey, tweak));
            Assert.AreNotEqual(originalPubkey, Convert.ToHexString(publicKey));
        }

        [TestMethod]
        public void EcSeckeyNegate()
        {
            using var secp256k1 = new Secp256k1();

            var secretKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");
            var negatedKey = new byte[32];
            Array.Copy(secretKey, negatedKey, 32);

            Assert.IsTrue(secp256k1.EcSeckeyNegate(negatedKey));
            Assert.AreNotEqual(Convert.ToHexString(secretKey), Convert.ToHexString(negatedKey));

            // Negating twice should give original
            Assert.IsTrue(secp256k1.EcSeckeyNegate(negatedKey));
            Assert.AreEqual(Convert.ToHexString(secretKey), Convert.ToHexString(negatedKey));
        }

        [TestMethod]
        public void EcdsaRecoverableSignatureConvert()
        {
            using var secp256k1 = new Secp256k1();

            var secretKey = Convert.FromHexString("e815acba8fcf085a0b4141060c13b8017a08da37f2eb1d6a5416adbb621560ef");
            var msgHash = Convert.FromHexString("c9f1c76685845ea81cac9925a7565887b7771b34b35e641cca85db9fefd0e71f");

            // Create recoverable signature
            var recoverableSig = new byte[Secp256k1.UNSERIALIZED_SIGNATURE_SIZE];
            Assert.IsTrue(secp256k1.EcdsaSignRecoverable(recoverableSig, msgHash, secretKey));

            // Convert to normal signature
            var normalSig = new byte[Secp256k1.SIGNATURE_LENGTH];
            Assert.IsTrue(secp256k1.EcdsaRecoverableSignatureConvert(normalSig, recoverableSig));

            // Verify the normal signature works
            var publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            Assert.IsTrue(secp256k1.EcPubkeyCreate(publicKey, secretKey));
            Assert.IsTrue(secp256k1.EcdsaVerify(normalSig, msgHash, publicKey));
        }

    }

    /// <summary>
    /// Tests for ArgumentException validation in wrapper methods.
    /// These test the size validation code paths that throw when input buffers are too small.
    /// </summary>
    [TestClass]
    public class ArgumentExceptionTests
    {
        private static readonly byte[] TestPrivateKey = Convert.FromHexString("7ef7543476bf146020cb59f9968a25ec67c3c73dbebad8a0b53a3256170dcdfe");

        // EC Pubkey functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyCreate_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyCreate_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            var seckey = new byte[31]; // Should be 32
            secp256k1.EcPubkeyCreate(pubkey, seckey);
        }

        [TestMethod]
        public void EcPubkeySerialize_TooSmallOutput_ReturnsFalse()
        {
            // Variable-length output buffers are not validated by the wrapper.
            // The native library handles size checking and returns failure.
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey);
            var output = new byte[31]; // Too small for compressed (33 bytes)
            nuint outputLen = (nuint)output.Length;
            var result = secp256k1.EcPubkeySerialize(output, ref outputLen, pubkey, Secp256k1EcFlags.Compressed);
            Assert.IsFalse(result, "Native library should reject too-small buffer");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeySerialize_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            var output = new byte[65];
            nuint outputLen = 65;
            secp256k1.EcPubkeySerialize(output, ref outputLen, pubkey, Secp256k1EcFlags.Uncompressed);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyParse_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            var input = new byte[33];
            secp256k1.EcPubkeyParse(pubkey, input);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyCmp_TooSmallPubkey1_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey1 = new byte[63]; // Should be 64
            var pubkey2 = new byte[64];
            secp256k1.EcPubkeyCmp(pubkey1, pubkey2);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyCmp_TooSmallPubkey2_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey1 = new byte[64];
            var pubkey2 = new byte[63]; // Should be 64
            secp256k1.EcPubkeyCmp(pubkey1, pubkey2);
        }

        // EC Seckey functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcSeckeyVerify_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var seckey = new byte[31]; // Should be 32
            secp256k1.EcSeckeyVerify(seckey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcSeckeyNegate_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var seckey = new byte[31]; // Should be 32
            secp256k1.EcSeckeyNegate(seckey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcSeckeyTweakAdd_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var seckey = new byte[31]; // Should be 32
            var tweak = new byte[32];
            secp256k1.EcSeckeyTweakAdd(seckey, tweak);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcSeckeyTweakAdd_TooSmallTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var seckey = new byte[32];
            var tweak = new byte[31]; // Should be 32
            secp256k1.EcSeckeyTweakAdd(seckey, tweak);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcSeckeyTweakMul_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var seckey = new byte[31]; // Should be 32
            var tweak = new byte[32];
            secp256k1.EcSeckeyTweakMul(seckey, tweak);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcSeckeyTweakMul_TooSmallTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var seckey = new byte[32];
            var tweak = new byte[31]; // Should be 32
            secp256k1.EcSeckeyTweakMul(seckey, tweak);
        }

        // EC Pubkey tweak functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyNegate_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            secp256k1.EcPubkeyNegate(pubkey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyTweakAdd_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            var tweak = new byte[32];
            secp256k1.EcPubkeyTweakAdd(pubkey, tweak);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyTweakAdd_TooSmallTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey);
            var tweak = new byte[31]; // Should be 32
            secp256k1.EcPubkeyTweakAdd(pubkey, tweak);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyTweakMul_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            var tweak = new byte[32];
            secp256k1.EcPubkeyTweakMul(pubkey, tweak);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyTweakMul_TooSmallTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            secp256k1.EcPubkeyCreate(pubkey, TestPrivateKey);
            var tweak = new byte[31]; // Should be 32
            secp256k1.EcPubkeyTweakMul(pubkey, tweak);
        }

        // ECDSA signature functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignatureParseCompact_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[63]; // Should be 64
            var input64 = new byte[64];
            secp256k1.EcdsaSignatureParseCompact(sig, input64);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignatureParseCompact_TooSmallInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64];
            var input64 = new byte[63]; // Should be 64
            secp256k1.EcdsaSignatureParseCompact(sig, input64);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignatureSerializeCompact_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output64 = new byte[63]; // Should be 64
            var sig = new byte[64];
            secp256k1.EcdsaSignatureSerializeCompact(output64, sig);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignatureSerializeCompact_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output64 = new byte[64];
            var sig = new byte[63]; // Should be 64
            secp256k1.EcdsaSignatureSerializeCompact(output64, sig);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignatureNormalize_TooSmallSigout_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sigout = new byte[63]; // Should be 64
            var sigin = new byte[64];
            secp256k1.EcdsaSignatureNormalize(sigout, sigin);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignatureNormalize_TooSmallSigin_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sigout = new byte[64];
            var sigin = new byte[63]; // Should be 64
            secp256k1.EcdsaSignatureNormalize(sigout, sigin);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaVerify_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[63]; // Should be 64
            var msghash32 = new byte[32];
            var pubkey = new byte[64];
            secp256k1.EcdsaVerify(sig, msghash32, pubkey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaVerify_TooSmallMsghash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64];
            var msghash32 = new byte[31]; // Should be 32
            var pubkey = new byte[64];
            secp256k1.EcdsaVerify(sig, msghash32, pubkey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaVerify_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64];
            var msghash32 = new byte[32];
            var pubkey = new byte[63]; // Should be 64
            secp256k1.EcdsaVerify(sig, msghash32, pubkey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSign_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[63]; // Should be 64
            var msghash32 = new byte[32];
            var seckey = new byte[32];
            secp256k1.EcdsaSign(sig, msghash32, seckey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSign_TooSmallMsghash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64];
            var msghash32 = new byte[31]; // Should be 32
            var seckey = new byte[32];
            secp256k1.EcdsaSign(sig, msghash32, seckey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSign_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64];
            var msghash32 = new byte[32];
            var seckey = new byte[31]; // Should be 32
            secp256k1.EcdsaSign(sig, msghash32, seckey);
        }

        // ECDSA recoverable signature functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaRecoverableSignatureParseCompact_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64]; // Should be 65
            var input64 = new byte[64];
            secp256k1.EcdsaRecoverableSignatureParseCompact(sig, input64, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaRecoverableSignatureParseCompact_TooSmallInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[65];
            var input64 = new byte[63]; // Should be 64
            secp256k1.EcdsaRecoverableSignatureParseCompact(sig, input64, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaRecoverableSignatureSerializeCompact_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output64 = new byte[63]; // Should be 64
            var sig = new byte[65];
            secp256k1.EcdsaRecoverableSignatureSerializeCompact(output64, out _, sig);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaRecoverableSignatureSerializeCompact_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output64 = new byte[64];
            var sig = new byte[64]; // Should be 65
            secp256k1.EcdsaRecoverableSignatureSerializeCompact(output64, out _, sig);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaRecoverableSignatureConvert_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[63]; // Should be 64
            var sigin = new byte[65];
            secp256k1.EcdsaRecoverableSignatureConvert(sig, sigin);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaRecoverableSignatureConvert_TooSmallSigin_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64];
            var sigin = new byte[64]; // Should be 65
            secp256k1.EcdsaRecoverableSignatureConvert(sig, sigin);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignRecoverable_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64]; // Should be 65
            var msghash32 = new byte[32];
            var seckey = new byte[32];
            secp256k1.EcdsaSignRecoverable(sig, msghash32, seckey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaRecover_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            var sig = new byte[65];
            var msghash32 = new byte[32];
            secp256k1.EcdsaRecover(pubkey, sig, msghash32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaRecover_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            var sig = new byte[64]; // Should be 65
            var msghash32 = new byte[32];
            secp256k1.EcdsaRecover(pubkey, sig, msghash32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaRecover_TooSmallMsghash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            var sig = new byte[65];
            var msghash32 = new byte[31]; // Should be 32
            secp256k1.EcdsaRecover(pubkey, sig, msghash32);
        }

        // ECDH functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Ecdh_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[31]; // Should be 32
            var pubkey = new byte[64];
            var seckey = new byte[32];
            secp256k1.Ecdh(output, pubkey, seckey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Ecdh_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var pubkey = new byte[63]; // Should be 64
            var seckey = new byte[32];
            secp256k1.Ecdh(output, pubkey, seckey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Ecdh_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var pubkey = new byte[64];
            var seckey = new byte[31]; // Should be 32
            secp256k1.Ecdh(output, pubkey, seckey);
        }

        // Keypair functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairCreate_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var keypair = new byte[95]; // Should be 96
            var seckey = new byte[32];
            secp256k1.KeypairCreate(keypair, seckey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairCreate_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var keypair = new byte[96];
            var seckey = new byte[31]; // Should be 32
            secp256k1.KeypairCreate(keypair, seckey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairSec_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var seckey = new byte[31]; // Should be 32
            var keypair = new byte[96];
            secp256k1.KeypairCreate(keypair, TestPrivateKey);
            secp256k1.KeypairSec(seckey, keypair);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairSec_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var seckey = new byte[32];
            var keypair = new byte[95]; // Should be 96
            secp256k1.KeypairSec(seckey, keypair);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairPub_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            var keypair = new byte[96];
            secp256k1.KeypairCreate(keypair, TestPrivateKey);
            secp256k1.KeypairPub(pubkey, keypair);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairPub_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            var keypair = new byte[95]; // Should be 96
            secp256k1.KeypairPub(pubkey, keypair);
        }

        // Xonly pubkey functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyParse_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            var input32 = new byte[32];
            secp256k1.XonlyPubkeyParse(pubkey, input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyParse_TooSmallInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            var input32 = new byte[31]; // Should be 32
            secp256k1.XonlyPubkeyParse(pubkey, input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeySerialize_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output32 = new byte[31]; // Should be 32
            var pubkey = new byte[64];
            secp256k1.XonlyPubkeySerialize(output32, pubkey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeySerialize_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output32 = new byte[32];
            var pubkey = new byte[63]; // Should be 64
            secp256k1.XonlyPubkeySerialize(output32, pubkey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyCmp_TooSmallPk1_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pk1 = new byte[63]; // Should be 64
            var pk2 = new byte[64];
            secp256k1.XonlyPubkeyCmp(pk1, pk2);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyCmp_TooSmallPk2_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pk1 = new byte[64];
            var pk2 = new byte[63]; // Should be 64
            secp256k1.XonlyPubkeyCmp(pk1, pk2);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyFromPubkey_TooSmallXonlyPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var xonlyPubkey = new byte[63]; // Should be 64
            var pubkey = new byte[64];
            secp256k1.XonlyPubkeyFromPubkey(xonlyPubkey, out _, pubkey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyFromPubkey_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var xonlyPubkey = new byte[64];
            var pubkey = new byte[63]; // Should be 64
            secp256k1.XonlyPubkeyFromPubkey(xonlyPubkey, out _, pubkey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyTweakAdd_TooSmallOutputPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var outputPubkey = new byte[63]; // Should be 64
            var internalPubkey = new byte[64];
            var tweak32 = new byte[32];
            secp256k1.XonlyPubkeyTweakAdd(outputPubkey, internalPubkey, tweak32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyTweakAdd_TooSmallInternalPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var outputPubkey = new byte[64];
            var internalPubkey = new byte[63]; // Should be 64
            var tweak32 = new byte[32];
            secp256k1.XonlyPubkeyTweakAdd(outputPubkey, internalPubkey, tweak32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyTweakAdd_TooSmallTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var outputPubkey = new byte[64];
            var internalPubkey = new byte[64];
            var tweak32 = new byte[31]; // Should be 32
            secp256k1.XonlyPubkeyTweakAdd(outputPubkey, internalPubkey, tweak32);
        }

        // Schnorr signature functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SchnorrsigSign32_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[63]; // Should be 64
            var msghash32 = new byte[32];
            var keypair = new byte[96];
            var aux_rand32 = new byte[32];
            secp256k1.SchnorrsigSign32(sig64, msghash32, keypair, aux_rand32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SchnorrsigSign32_TooSmallMsghash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[64];
            var msghash32 = new byte[31]; // Should be 32
            var keypair = new byte[96];
            var aux_rand32 = new byte[32];
            secp256k1.SchnorrsigSign32(sig64, msghash32, keypair, aux_rand32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SchnorrsigSign32_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[64];
            var msghash32 = new byte[32];
            var keypair = new byte[95]; // Should be 96
            var aux_rand32 = new byte[32];
            secp256k1.SchnorrsigSign32(sig64, msghash32, keypair, aux_rand32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SchnorrsigSign32_TooSmallAuxRand_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[64];
            var msghash32 = new byte[32];
            var keypair = new byte[96];
            var aux_rand32 = new byte[31]; // Should be 32
            secp256k1.SchnorrsigSign32(sig64, msghash32, keypair, aux_rand32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SchnorrsigVerify_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[63]; // Should be 64
            var msg = new byte[32];
            var pubkey = new byte[64];
            secp256k1.SchnorrsigVerify(sig64, msg, pubkey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SchnorrsigVerify_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[64];
            var msg = new byte[32];
            var pubkey = new byte[63]; // Should be 64
            secp256k1.SchnorrsigVerify(sig64, msg, pubkey);
        }

        // Ellswift functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftEncode_TooSmallEll64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var ell64 = new byte[63]; // Should be 64
            var pubkey = new byte[64];
            var rnd32 = new byte[32];
            secp256k1.EllswiftEncode(ell64, pubkey, rnd32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftEncode_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var ell64 = new byte[64];
            var pubkey = new byte[63]; // Should be 64
            var rnd32 = new byte[32];
            secp256k1.EllswiftEncode(ell64, pubkey, rnd32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftEncode_TooSmallRnd_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var ell64 = new byte[64];
            var pubkey = new byte[64];
            var rnd32 = new byte[31]; // Should be 32
            secp256k1.EllswiftEncode(ell64, pubkey, rnd32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftDecode_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            var ell64 = new byte[64];
            secp256k1.EllswiftDecode(pubkey, ell64);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftDecode_TooSmallEll64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            var ell64 = new byte[63]; // Should be 64
            secp256k1.EllswiftDecode(pubkey, ell64);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftCreate_TooSmallEll64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var ell64 = new byte[63]; // Should be 64
            var seckey32 = new byte[32];
            var auxrnd32 = new byte[32];
            secp256k1.EllswiftCreate(ell64, seckey32, auxrnd32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftCreate_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var ell64 = new byte[64];
            var seckey32 = new byte[31]; // Should be 32
            var auxrnd32 = new byte[32];
            secp256k1.EllswiftCreate(ell64, seckey32, auxrnd32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftCreate_TooSmallAuxrnd_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var ell64 = new byte[64];
            var seckey32 = new byte[32];
            var auxrnd32 = new byte[31]; // Should be 32
            secp256k1.EllswiftCreate(ell64, seckey32, auxrnd32);
        }

        // MuSig functions
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyAgg_TooSmallAggPk_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var aggPk = new byte[63]; // Should be 64
            var keyaggCache = new byte[197];
            var pubkeys = new[] { new byte[64], new byte[64] };
            secp256k1.MusigPubkeyAgg(aggPk, keyaggCache, pubkeys);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyAgg_TooSmallKeyaggCache_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var aggPk = new byte[64];
            var keyaggCache = new byte[196]; // Should be 197
            var pubkeys = new[] { new byte[64], new byte[64] };
            secp256k1.MusigPubkeyAgg(aggPk, keyaggCache, pubkeys);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyAgg_EmptyPubkeys_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var aggPk = new byte[64];
            var keyaggCache = new byte[197];
            var pubkeys = new byte[0][];
            secp256k1.MusigPubkeyAgg(aggPk, keyaggCache, pubkeys);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGen_TooSmallSecnonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[131]; // Should be 132
            var pubnonce = new byte[132];
            var sessionSecrand32 = new byte[32];
            var seckey = new byte[32];
            var pubkey = new byte[64];
            var msg32 = new byte[32];
            var keyaggCache = new byte[197];
            var extraInput32 = new byte[32];
            secp256k1.MusigNonceGen(secnonce, pubnonce, sessionSecrand32, seckey, pubkey, msg32, keyaggCache, extraInput32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGen_TooSmallPubnonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[131]; // Should be 132
            var sessionSecrand32 = new byte[32];
            var seckey = new byte[32];
            var pubkey = new byte[64];
            var msg32 = new byte[32];
            var keyaggCache = new byte[197];
            var extraInput32 = new byte[32];
            secp256k1.MusigNonceGen(secnonce, pubnonce, sessionSecrand32, seckey, pubkey, msg32, keyaggCache, extraInput32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSign_TooSmallPartialSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partialSig = new byte[35]; // Should be 36
            var secnonce = new byte[132];
            var keypair = new byte[96];
            var keyaggCache = new byte[197];
            var session = new byte[133];
            secp256k1.MusigPartialSign(partialSig, secnonce, keypair, keyaggCache, session);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSign_TooSmallSecnonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partialSig = new byte[36];
            var secnonce = new byte[131]; // Should be 132
            var keypair = new byte[96];
            var keyaggCache = new byte[197];
            var session = new byte[133];
            secp256k1.MusigPartialSign(partialSig, secnonce, keypair, keyaggCache, session);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSign_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partialSig = new byte[36];
            var secnonce = new byte[132];
            var keypair = new byte[95]; // Should be 96
            var keyaggCache = new byte[197];
            var session = new byte[133];
            secp256k1.MusigPartialSign(partialSig, secnonce, keypair, keyaggCache, session);
        }

        // Tagged hash function
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TaggedSha256_TooSmallHash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var hash32 = new byte[31]; // Should be 32
            var tag = System.Text.Encoding.UTF8.GetBytes("test");
            var msg = System.Text.Encoding.UTF8.GetBytes("message");
            secp256k1.TaggedSha256(hash32, tag, msg);
        }

        // Global function pointer wrappers
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NonceFunctionRfc6979_TooSmallNonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce32 = new byte[31]; // Should be 32
            var msg32 = new byte[32];
            var key32 = new byte[32];
            var algo16 = new byte[16];
            var data = new byte[1];
            secp256k1.NonceFunctionRfc6979(nonce32, msg32, key32, algo16, data, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NonceFunctionRfc6979_TooSmallMsg_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce32 = new byte[32];
            var msg32 = new byte[31]; // Should be 32
            var key32 = new byte[32];
            var algo16 = new byte[16];
            var data = new byte[1];
            secp256k1.NonceFunctionRfc6979(nonce32, msg32, key32, algo16, data, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NonceFunctionRfc6979_TooSmallKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce32 = new byte[32];
            var msg32 = new byte[32];
            var key32 = new byte[31]; // Should be 32
            var algo16 = new byte[16];
            var data = new byte[1];
            secp256k1.NonceFunctionRfc6979(nonce32, msg32, key32, algo16, data, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdhHashFunctionDefault_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[31]; // Should be 32
            var x32 = new byte[32];
            var y32 = new byte[32];
            var data = new byte[1];
            secp256k1.EcdhHashFunctionDefault(output, x32, y32, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdhHashFunctionSha256_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[31]; // Should be 32
            var x32 = new byte[32];
            var y32 = new byte[32];
            var data = new byte[1];
            secp256k1.EcdhHashFunctionSha256(output, x32, y32, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NonceFunctionBip340_TooSmallNonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce32 = new byte[31]; // Should be 32
            var msg = new byte[32];
            var key32 = new byte[32];
            var xonly_pk32 = new byte[32];
            var algo = System.Text.Encoding.UTF8.GetBytes("BIP0340/nonce");
            var data = new byte[1];
            secp256k1.NonceFunctionBip340(nonce32, msg, (nuint)msg.Length, key32, xonly_pk32, algo, (nuint)algo.Length, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NonceFunctionBip340_TooSmallKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce32 = new byte[32];
            var msg = new byte[32];
            var key32 = new byte[31]; // Should be 32
            var xonly_pk32 = new byte[32];
            var algo = System.Text.Encoding.UTF8.GetBytes("BIP0340/nonce");
            var data = new byte[1];
            secp256k1.NonceFunctionBip340(nonce32, msg, (nuint)msg.Length, key32, xonly_pk32, algo, (nuint)algo.Length, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NonceFunctionBip340_TooSmallXonlyPk_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce32 = new byte[32];
            var msg = new byte[32];
            var key32 = new byte[32];
            var xonly_pk32 = new byte[31]; // Should be 32
            var algo = System.Text.Encoding.UTF8.GetBytes("BIP0340/nonce");
            var data = new byte[1];
            secp256k1.NonceFunctionBip340(nonce32, msg, (nuint)msg.Length, key32, xonly_pk32, algo, (nuint)algo.Length, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhHashFunctionPrefix_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[31]; // Should be 32
            var x32 = new byte[32];
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[64];
            var data = new byte[1];
            secp256k1.EllswiftXdhHashFunctionPrefix(output, x32, ell_a64, ell_b64, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhHashFunctionPrefix_TooSmallX32_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[31]; // Should be 32
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[64];
            var data = new byte[1];
            secp256k1.EllswiftXdhHashFunctionPrefix(output, x32, ell_a64, ell_b64, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhHashFunctionPrefix_TooSmallEllA64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[32];
            var ell_a64 = new byte[63]; // Should be 64
            var ell_b64 = new byte[64];
            var data = new byte[1];
            secp256k1.EllswiftXdhHashFunctionPrefix(output, x32, ell_a64, ell_b64, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhHashFunctionPrefix_TooSmallEllB64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[32];
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[63]; // Should be 64
            var data = new byte[1];
            secp256k1.EllswiftXdhHashFunctionPrefix(output, x32, ell_a64, ell_b64, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhHashFunctionBip324_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[31]; // Should be 32
            var x32 = new byte[32];
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[64];
            var data = new byte[1];
            secp256k1.EllswiftXdhHashFunctionBip324(output, x32, ell_a64, ell_b64, data);
        }

        // EllswiftXdhHashFunctionBip324 remaining parameters
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhHashFunctionBip324_TooSmallX32_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[31]; // Should be 32
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[64];
            var data = new byte[1];
            secp256k1.EllswiftXdhHashFunctionBip324(output, x32, ell_a64, ell_b64, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhHashFunctionBip324_TooSmallEllA64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[32];
            var ell_a64 = new byte[63]; // Should be 64
            var ell_b64 = new byte[64];
            var data = new byte[1];
            secp256k1.EllswiftXdhHashFunctionBip324(output, x32, ell_a64, ell_b64, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhHashFunctionBip324_TooSmallEllB64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[32];
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[63]; // Should be 64
            var data = new byte[1];
            secp256k1.EllswiftXdhHashFunctionBip324(output, x32, ell_a64, ell_b64, data);
        }

        // EcdsaSignatureSerializeDer tests
        [TestMethod]
        public void EcdsaSignatureSerializeDer_TooSmallOutput_ReturnsFalse()
        {
            // Variable-length output buffers are not validated by the wrapper.
            // The native library handles size checking and returns failure.
            using var secp256k1 = new Secp256k1();

            // First create a valid signature
            var sig = new byte[64];
            var msg = new byte[32];
            for (int i = 0; i < msg.Length; i++) msg[i] = (byte)(i + 1);
            Assert.IsTrue(secp256k1.EcdsaSign(sig, msg, TestPrivateKey), "Sign should succeed");

            // Try to serialize with too small output - native library returns 0 (false)
            var output = new byte[31]; // Too small for DER signature (typically 71-72 bytes)
            nuint outputLen = (nuint)output.Length;
            var result = secp256k1.EcdsaSignatureSerializeDer(output, ref outputLen, sig);
            Assert.IsFalse(result, "Native library should reject too-small buffer");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignatureSerializeDer_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[72];
            nuint outputLen = 72;
            var sig = new byte[63]; // Should be 64
            secp256k1.EcdsaSignatureSerializeDer(output, ref outputLen, sig);
        }

        // EcdsaSignatureParseDer tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignatureParseDer_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[63]; // Should be 64
            var input = new byte[72];
            secp256k1.EcdsaSignatureParseDer(sig, input);
        }

        // EcdsaSignRecoverable additional tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignRecoverable_TooSmallMsghash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[65];
            var msghash32 = new byte[31]; // Should be 32
            secp256k1.EcdsaSignRecoverable(sig, msghash32, TestPrivateKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignRecoverable_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[65];
            var msghash32 = new byte[32];
            var seckey = new byte[31]; // Should be 32
            secp256k1.EcdsaSignRecoverable(sig, msghash32, seckey);
        }

        // XonlyPubkeyTweakAddCheck tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyTweakAddCheck_TooSmallTweakedPubkey32_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var tweaked_pubkey32 = new byte[31]; // Should be 32
            var internal_pubkey = new byte[64];
            var tweak32 = new byte[32];
            secp256k1.XonlyPubkeyTweakAddCheck(tweaked_pubkey32, 0, internal_pubkey, tweak32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyTweakAddCheck_TooSmallInternalPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var tweaked_pubkey32 = new byte[32];
            var internal_pubkey = new byte[63]; // Should be 64
            var tweak32 = new byte[32];
            secp256k1.XonlyPubkeyTweakAddCheck(tweaked_pubkey32, 0, internal_pubkey, tweak32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void XonlyPubkeyTweakAddCheck_TooSmallTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var tweaked_pubkey32 = new byte[32];
            var internal_pubkey = new byte[64];
            var tweak32 = new byte[31]; // Should be 32
            secp256k1.XonlyPubkeyTweakAddCheck(tweaked_pubkey32, 0, internal_pubkey, tweak32);
        }

        // KeypairXonlyPub tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairXonlyPub_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[63]; // Should be 64
            var keypair = new byte[96];
            secp256k1.KeypairXonlyPub(pubkey, out _, keypair);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairXonlyPub_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkey = new byte[64];
            var keypair = new byte[95]; // Should be 96
            secp256k1.KeypairXonlyPub(pubkey, out _, keypair);
        }

        // KeypairXonlyTweakAdd tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairXonlyTweakAdd_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var keypair = new byte[95]; // Should be 96
            var tweak32 = new byte[32];
            secp256k1.KeypairXonlyTweakAdd(keypair, tweak32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void KeypairXonlyTweakAdd_TooSmallTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var keypair = new byte[96];
            var tweak32 = new byte[31]; // Should be 32
            secp256k1.KeypairXonlyTweakAdd(keypair, tweak32);
        }

        // SchnorrsigSignCustom tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SchnorrsigSignCustom_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[63]; // Should be 64
            var keypair = new byte[96];
            var extraparams = new byte[1];
            secp256k1.SchnorrsigSignCustom(sig64, Array.Empty<byte>(), keypair, extraparams);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SchnorrsigSignCustom_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[64];
            var keypair = new byte[95]; // Should be 96
            var extraparams = new byte[1];
            secp256k1.SchnorrsigSignCustom(sig64, Array.Empty<byte>(), keypair, extraparams);
        }

        // EcdhHashFunctionSha256 additional tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdhHashFunctionSha256_TooSmallX32_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[31]; // Should be 32
            var y32 = new byte[32];
            var data = new byte[1];
            secp256k1.EcdhHashFunctionSha256(output, x32, y32, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdhHashFunctionSha256_TooSmallY32_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[32];
            var y32 = new byte[31]; // Should be 32
            var data = new byte[1];
            secp256k1.EcdhHashFunctionSha256(output, x32, y32, data);
        }

        // EcdhHashFunctionDefault additional tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdhHashFunctionDefault_TooSmallX32_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[31]; // Should be 32
            var y32 = new byte[32];
            var data = new byte[1];
            secp256k1.EcdhHashFunctionDefault(output, x32, y32, data);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdhHashFunctionDefault_TooSmallY32_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var x32 = new byte[32];
            var y32 = new byte[31]; // Should be 32
            var data = new byte[1];
            secp256k1.EcdhHashFunctionDefault(output, x32, y32, data);
        }

        // NonceFunctionDefault tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NonceFunctionDefault_TooSmallNonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce32 = new byte[31]; // Should be 32
            var msg32 = new byte[32];
            var key32 = new byte[32];
            var algo16 = new byte[16];
            var data = new byte[32];
            secp256k1.NonceFunctionDefault(nonce32, msg32, key32, algo16, data, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NonceFunctionDefault_TooSmallMsg_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce32 = new byte[32];
            var msg32 = new byte[31]; // Should be 32
            var key32 = new byte[32];
            var algo16 = new byte[16];
            var data = new byte[32];
            secp256k1.NonceFunctionDefault(nonce32, msg32, key32, algo16, data, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void NonceFunctionDefault_TooSmallKey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce32 = new byte[32];
            var msg32 = new byte[32];
            var key32 = new byte[31]; // Should be 32
            var algo16 = new byte[16];
            var data = new byte[32];
            secp256k1.NonceFunctionDefault(nonce32, msg32, key32, algo16, data, 0);
        }

        // MusigPubnonceParse tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubnonceParse_TooSmallNonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce = new byte[131]; // Should be 132
            var in66 = new byte[66];
            secp256k1.MusigPubnonceParse(nonce, in66);
        }

        // MusigPubnonceSerialize tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubnonceSerialize_TooSmallNonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var out66 = new byte[66];
            var nonce = new byte[131]; // Should be 132
            secp256k1.MusigPubnonceSerialize(out66, nonce);
        }

        // MusigAggnonceParse tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigAggnonceParse_TooSmallNonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var nonce = new byte[131]; // Should be 132
            var in66 = new byte[66];
            secp256k1.MusigAggnonceParse(nonce, in66);
        }

        // MusigAggnonceSerialize tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigAggnonceSerialize_TooSmallNonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var out66 = new byte[66];
            var nonce = new byte[131]; // Should be 132
            secp256k1.MusigAggnonceSerialize(out66, nonce);
        }

        // MusigPartialSigParse tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigParse_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[35]; // Should be 36
            var in32 = new byte[32];
            secp256k1.MusigPartialSigParse(sig, in32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigParse_TooSmallIn32_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[36];
            var in32 = new byte[31]; // Should be 32
            secp256k1.MusigPartialSigParse(sig, in32);
        }

        // MusigPartialSigSerialize tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigSerialize_TooSmallOut32_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var out32 = new byte[31]; // Should be 32
            var sig = new byte[36];
            secp256k1.MusigPartialSigSerialize(out32, sig);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigSerialize_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var out32 = new byte[32];
            var sig = new byte[35]; // Should be 36
            secp256k1.MusigPartialSigSerialize(out32, sig);
        }

        // MusigPubkeyAgg additional tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyAgg_TooSmallPubkeyElement_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var agg_pk = new byte[64];
            var keyagg_cache = new byte[197];
            var pubkeys = new byte[][] { new byte[63] }; // Each should be 64
            secp256k1.MusigPubkeyAgg(agg_pk, keyagg_cache, pubkeys);
        }

        // MusigPubkeyGet tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyGet_TooSmallAggPk_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var agg_pk = new byte[63]; // Should be 64
            var keyagg_cache = new byte[197];
            secp256k1.MusigPubkeyGet(agg_pk, keyagg_cache);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyGet_TooSmallKeyaggCache_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var agg_pk = new byte[64];
            var keyagg_cache = new byte[196]; // Should be 197
            secp256k1.MusigPubkeyGet(agg_pk, keyagg_cache);
        }

        // MusigPubkeyEcTweakAdd tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyEcTweakAdd_TooSmallOutputPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output_pubkey = new byte[63]; // Should be 64
            var keyagg_cache = new byte[197];
            var tweak32 = new byte[32];
            secp256k1.MusigPubkeyEcTweakAdd(output_pubkey, keyagg_cache, tweak32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyEcTweakAdd_TooSmallKeyaggCache_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output_pubkey = new byte[64];
            var keyagg_cache = new byte[196]; // Should be 197
            var tweak32 = new byte[32];
            secp256k1.MusigPubkeyEcTweakAdd(output_pubkey, keyagg_cache, tweak32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyEcTweakAdd_TooSmallTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output_pubkey = new byte[64];
            var keyagg_cache = new byte[197];
            var tweak32 = new byte[31]; // Should be 32
            secp256k1.MusigPubkeyEcTweakAdd(output_pubkey, keyagg_cache, tweak32);
        }

        // MusigPubkeyXonlyTweakAdd tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyXonlyTweakAdd_TooSmallOutputPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output_pubkey = new byte[63]; // Should be 64
            var keyagg_cache = new byte[197];
            var tweak32 = new byte[32];
            secp256k1.MusigPubkeyXonlyTweakAdd(output_pubkey, keyagg_cache, tweak32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyXonlyTweakAdd_TooSmallKeyaggCache_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output_pubkey = new byte[64];
            var keyagg_cache = new byte[196]; // Should be 197
            var tweak32 = new byte[32];
            secp256k1.MusigPubkeyXonlyTweakAdd(output_pubkey, keyagg_cache, tweak32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPubkeyXonlyTweakAdd_TooSmallTweak_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output_pubkey = new byte[64];
            var keyagg_cache = new byte[197];
            var tweak32 = new byte[31]; // Should be 32
            secp256k1.MusigPubkeyXonlyTweakAdd(output_pubkey, keyagg_cache, tweak32);
        }

        // MusigNonceGen additional tests (many parameters)
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGen_TooSmallSessionSecrand_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var session_secrand32 = new byte[31]; // Should be 32
            var seckey = new byte[32];
            var pubkey = new byte[64];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGen(secnonce, pubnonce, session_secrand32, seckey, pubkey, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGen_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var session_secrand32 = new byte[32];
            var seckey = new byte[31]; // Should be 32
            var pubkey = new byte[64];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGen(secnonce, pubnonce, session_secrand32, seckey, pubkey, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGen_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var session_secrand32 = new byte[32];
            var seckey = new byte[32];
            var pubkey = new byte[63]; // Should be 64
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGen(secnonce, pubnonce, session_secrand32, seckey, pubkey, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGen_TooSmallMsg_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var session_secrand32 = new byte[32];
            var seckey = new byte[32];
            var pubkey = new byte[64];
            var msg32 = new byte[31]; // Should be 32
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGen(secnonce, pubnonce, session_secrand32, seckey, pubkey, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGen_TooSmallKeyaggCache_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var session_secrand32 = new byte[32];
            var seckey = new byte[32];
            var pubkey = new byte[64];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[196]; // Should be 197
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGen(secnonce, pubnonce, session_secrand32, seckey, pubkey, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGen_TooSmallExtraInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var session_secrand32 = new byte[32];
            var seckey = new byte[32];
            var pubkey = new byte[64];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[31]; // Should be 32
            secp256k1.MusigNonceGen(secnonce, pubnonce, session_secrand32, seckey, pubkey, msg32, keyagg_cache, extra_input32);
        }

        // MusigNonceGenCounter tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGenCounter_TooSmallSecnonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[131]; // Should be 132
            var pubnonce = new byte[132];
            var keypair = new byte[96];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGenCounter(secnonce, pubnonce, 0, keypair, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGenCounter_TooSmallPubnonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[131]; // Should be 132
            var keypair = new byte[96];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGenCounter(secnonce, pubnonce, 0, keypair, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGenCounter_TooSmallKeypair_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var keypair = new byte[95]; // Should be 96
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGenCounter(secnonce, pubnonce, 0, keypair, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGenCounter_TooSmallMsg_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var keypair = new byte[96];
            var msg32 = new byte[31]; // Should be 32
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGenCounter(secnonce, pubnonce, 0, keypair, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGenCounter_TooSmallKeyaggCache_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var keypair = new byte[96];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[196]; // Should be 197
            var extra_input32 = new byte[32];
            secp256k1.MusigNonceGenCounter(secnonce, pubnonce, 0, keypair, msg32, keyagg_cache, extra_input32);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceGenCounter_TooSmallExtraInput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var secnonce = new byte[132];
            var pubnonce = new byte[132];
            var keypair = new byte[96];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            var extra_input32 = new byte[31]; // Should be 32
            secp256k1.MusigNonceGenCounter(secnonce, pubnonce, 0, keypair, msg32, keyagg_cache, extra_input32);
        }

        // MusigNonceAgg tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceAgg_EmptyPubnonces_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var aggnonce = new byte[132];
            var pubnonces = Array.Empty<byte[]>();
            secp256k1.MusigNonceAgg(aggnonce, pubnonces);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceAgg_TooSmallPubnonceElement_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var aggnonce = new byte[132];
            var pubnonces = new byte[][] { new byte[131] }; // Each should be 132
            secp256k1.MusigNonceAgg(aggnonce, pubnonces);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceAgg_TooSmallAggnonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var aggnonce = new byte[131]; // Should be 132
            var pubnonces = new byte[][] { new byte[132] };
            secp256k1.MusigNonceAgg(aggnonce, pubnonces);
        }

        // MusigNonceProcess tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceProcess_TooSmallSession_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var session = new byte[132]; // Should be 133
            var aggnonce = new byte[132];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            secp256k1.MusigNonceProcess(session, aggnonce, msg32, keyagg_cache);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceProcess_TooSmallAggnonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var session = new byte[133];
            var aggnonce = new byte[131]; // Should be 132
            var msg32 = new byte[32];
            var keyagg_cache = new byte[197];
            secp256k1.MusigNonceProcess(session, aggnonce, msg32, keyagg_cache);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceProcess_TooSmallMsg_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var session = new byte[133];
            var aggnonce = new byte[132];
            var msg32 = new byte[31]; // Should be 32
            var keyagg_cache = new byte[197];
            secp256k1.MusigNonceProcess(session, aggnonce, msg32, keyagg_cache);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigNonceProcess_TooSmallKeyaggCache_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var session = new byte[133];
            var aggnonce = new byte[132];
            var msg32 = new byte[32];
            var keyagg_cache = new byte[196]; // Should be 197
            secp256k1.MusigNonceProcess(session, aggnonce, msg32, keyagg_cache);
        }

        // MusigPartialSign additional tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSign_TooSmallKeyaggCache_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partial_sig = new byte[36];
            var secnonce = new byte[132];
            var keypair = new byte[96];
            var keyagg_cache = new byte[196]; // Should be 197
            var session = new byte[133];
            secp256k1.MusigPartialSign(partial_sig, secnonce, keypair, keyagg_cache, session);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSign_TooSmallSession_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partial_sig = new byte[36];
            var secnonce = new byte[132];
            var keypair = new byte[96];
            var keyagg_cache = new byte[197];
            var session = new byte[132]; // Should be 133
            secp256k1.MusigPartialSign(partial_sig, secnonce, keypair, keyagg_cache, session);
        }

        // MusigPartialSigVerify tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigVerify_TooSmallPartialSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partial_sig = new byte[35]; // Should be 36
            var pubnonce = new byte[132];
            var pubkey = new byte[64];
            var keyagg_cache = new byte[197];
            var session = new byte[133];
            secp256k1.MusigPartialSigVerify(partial_sig, pubnonce, pubkey, keyagg_cache, session);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigVerify_TooSmallPubnonce_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partial_sig = new byte[36];
            var pubnonce = new byte[131]; // Should be 132
            var pubkey = new byte[64];
            var keyagg_cache = new byte[197];
            var session = new byte[133];
            secp256k1.MusigPartialSigVerify(partial_sig, pubnonce, pubkey, keyagg_cache, session);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigVerify_TooSmallPubkey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partial_sig = new byte[36];
            var pubnonce = new byte[132];
            var pubkey = new byte[63]; // Should be 64
            var keyagg_cache = new byte[197];
            var session = new byte[133];
            secp256k1.MusigPartialSigVerify(partial_sig, pubnonce, pubkey, keyagg_cache, session);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigVerify_TooSmallKeyaggCache_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partial_sig = new byte[36];
            var pubnonce = new byte[132];
            var pubkey = new byte[64];
            var keyagg_cache = new byte[196]; // Should be 197
            var session = new byte[133];
            secp256k1.MusigPartialSigVerify(partial_sig, pubnonce, pubkey, keyagg_cache, session);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigVerify_TooSmallSession_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var partial_sig = new byte[36];
            var pubnonce = new byte[132];
            var pubkey = new byte[64];
            var keyagg_cache = new byte[197];
            var session = new byte[132]; // Should be 133
            secp256k1.MusigPartialSigVerify(partial_sig, pubnonce, pubkey, keyagg_cache, session);
        }

        // MusigPartialSigAgg tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigAgg_EmptyPartialSigs_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[64];
            var session = new byte[133];
            var partial_sigs = Array.Empty<byte[]>();
            secp256k1.MusigPartialSigAgg(sig64, session, partial_sigs);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigAgg_TooSmallPartialSigElement_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[64];
            var session = new byte[133];
            var partial_sigs = new byte[][] { new byte[35] }; // Each should be 36
            secp256k1.MusigPartialSigAgg(sig64, session, partial_sigs);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigAgg_TooSmallSig64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[63]; // Should be 64
            var session = new byte[133];
            var partial_sigs = new byte[][] { new byte[36] };
            secp256k1.MusigPartialSigAgg(sig64, session, partial_sigs);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MusigPartialSigAgg_TooSmallSession_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig64 = new byte[64];
            var session = new byte[132]; // Should be 133
            var partial_sigs = new byte[][] { new byte[36] };
            secp256k1.MusigPartialSigAgg(sig64, session, partial_sigs);
        }

        // EcPubkeyCombine additional tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeyCombine_TooSmallOut_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var @out = new byte[63]; // Should be 64
            var ins = new byte[][] { new byte[64], new byte[64] };
            secp256k1.EcPubkeyCombine(@out, ins);
        }

        // EcdsaSign with NonceFunction callback tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignWithCallback_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[63]; // Should be 64
            var msghash32 = new byte[32];
            NonceFunction noncefp = (Span<byte> nonce, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> key, ReadOnlySpan<byte> algo, IntPtr data, uint attempt) => 1;
            secp256k1.EcdsaSign(sig, msghash32, TestPrivateKey, noncefp, IntPtr.Zero);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignWithCallback_TooSmallMsghash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64];
            var msghash32 = new byte[31]; // Should be 32
            NonceFunction noncefp = (Span<byte> nonce, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> key, ReadOnlySpan<byte> algo, IntPtr data, uint attempt) => 1;
            secp256k1.EcdsaSign(sig, msghash32, TestPrivateKey, noncefp, IntPtr.Zero);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignWithCallback_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64];
            var msghash32 = new byte[32];
            var seckey = new byte[31]; // Should be 32
            NonceFunction noncefp = (Span<byte> nonce, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> key, ReadOnlySpan<byte> algo, IntPtr data, uint attempt) => 1;
            secp256k1.EcdsaSign(sig, msghash32, seckey, noncefp, IntPtr.Zero);
        }

        // EcdsaSignRecoverable with NonceFunction callback tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignRecoverableWithCallback_TooSmallSig_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[64]; // Should be 65
            var msghash32 = new byte[32];
            NonceFunction noncefp = (Span<byte> nonce, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> key, ReadOnlySpan<byte> algo, IntPtr data, uint attempt) => 1;
            secp256k1.EcdsaSignRecoverable(sig, msghash32, TestPrivateKey, noncefp, IntPtr.Zero);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignRecoverableWithCallback_TooSmallMsghash_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[65];
            var msghash32 = new byte[31]; // Should be 32
            NonceFunction noncefp = (Span<byte> nonce, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> key, ReadOnlySpan<byte> algo, IntPtr data, uint attempt) => 1;
            secp256k1.EcdsaSignRecoverable(sig, msghash32, TestPrivateKey, noncefp, IntPtr.Zero);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcdsaSignRecoverableWithCallback_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var sig = new byte[65];
            var msghash32 = new byte[32];
            var seckey = new byte[31]; // Should be 32
            NonceFunction noncefp = (Span<byte> nonce, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> key, ReadOnlySpan<byte> algo, IntPtr data, uint attempt) => 1;
            secp256k1.EcdsaSignRecoverable(sig, msghash32, seckey, noncefp, IntPtr.Zero);
        }

        // EcPubkeySort tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeySort_NullArray_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            secp256k1.EcPubkeySort(null!);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeySort_EmptyArray_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            secp256k1.EcPubkeySort(Array.Empty<byte[]>());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeySort_NullElement_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkeys = new byte[][] { null! };
            secp256k1.EcPubkeySort(pubkeys);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EcPubkeySort_TooSmallElement_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var pubkeys = new byte[][] { new byte[63] }; // Should be 64
            secp256k1.EcPubkeySort(pubkeys);
        }

        // EllswiftXdh with callback tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhWithCallback_TooSmallOutput_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[31]; // Should be 32
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[64];
            var seckey32 = new byte[32];
            EllswiftXdhHashFunction hashfp = (Span<byte> o, ReadOnlySpan<byte> x32, ReadOnlySpan<byte> ell_a, ReadOnlySpan<byte> ell_b, IntPtr data) => 1;
            secp256k1.EllswiftXdh(output, ell_a64, ell_b64, seckey32, 0, hashfp, IntPtr.Zero);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhWithCallback_TooSmallEllA64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var ell_a64 = new byte[63]; // Should be 64
            var ell_b64 = new byte[64];
            var seckey32 = new byte[32];
            EllswiftXdhHashFunction hashfp = (Span<byte> o, ReadOnlySpan<byte> x32, ReadOnlySpan<byte> ell_a, ReadOnlySpan<byte> ell_b, IntPtr data) => 1;
            secp256k1.EllswiftXdh(output, ell_a64, ell_b64, seckey32, 0, hashfp, IntPtr.Zero);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhWithCallback_TooSmallEllB64_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[63]; // Should be 64
            var seckey32 = new byte[32];
            EllswiftXdhHashFunction hashfp = (Span<byte> o, ReadOnlySpan<byte> x32, ReadOnlySpan<byte> ell_a, ReadOnlySpan<byte> ell_b, IntPtr data) => 1;
            secp256k1.EllswiftXdh(output, ell_a64, ell_b64, seckey32, 0, hashfp, IntPtr.Zero);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EllswiftXdhWithCallback_TooSmallSeckey_ThrowsArgumentException()
        {
            using var secp256k1 = new Secp256k1();
            var output = new byte[32];
            var ell_a64 = new byte[64];
            var ell_b64 = new byte[64];
            var seckey32 = new byte[31]; // Should be 32
            EllswiftXdhHashFunction hashfp = (Span<byte> o, ReadOnlySpan<byte> x32, ReadOnlySpan<byte> ell_a, ReadOnlySpan<byte> ell_b, IntPtr data) => 1;
            secp256k1.EllswiftXdh(output, ell_a64, ell_b64, seckey32, 0, hashfp, IntPtr.Zero);
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
