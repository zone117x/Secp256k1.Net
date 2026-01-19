using System;
using System.IO;
using System.Runtime.InteropServices;
using Secp256k1Net;

namespace NativeLibTest
{
    class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine("=== Secp256k1.Net Native Library Test ===");
            Console.WriteLine();
            Console.WriteLine($"OS: {RuntimeInformation.OSDescription}");
            Console.WriteLine($"Architecture: {RuntimeInformation.ProcessArchitecture}");
            Console.WriteLine($"Framework: {RuntimeInformation.FrameworkDescription}");
            Console.WriteLine();

            try
            {
                // Test 1: Library loading
                Console.Write("Test 1: Loading native library... ");
                using var secp256k1 = new Secp256k1();
                Console.WriteLine($"OK");
                Console.WriteLine($"        Library path: {Secp256k1.LibPath}");

                // Test 2: Key generation
                Console.Write("Test 2: Generating key pair... ");
                var privateKey = new byte[32];
                var publicKey = new byte[64];

                // Use a deterministic private key for testing
                for (int i = 0; i < 32; i++)
                    privateKey[i] = (byte)(i + 1);

                if (!secp256k1.EcSeckeyVerify(privateKey))
                {
                    Console.WriteLine("FAILED (invalid secret key)");
                    return 1;
                }

                if (!secp256k1.EcPubkeyCreate(publicKey, privateKey))
                {
                    Console.WriteLine("FAILED (could not create public key)");
                    return 1;
                }
                Console.WriteLine("OK");

                // Test 3: Public key serialization
                Console.Write("Test 3: Serializing public key... ");
                var serializedPubKey = new byte[33];
                nuint pubKeyLen = 33;
                if (!secp256k1.EcPubkeySerialize(serializedPubKey, ref pubKeyLen, publicKey, (uint)Flags.SECP256K1_EC_COMPRESSED))
                {
                    Console.WriteLine("FAILED");
                    return 1;
                }
                Console.WriteLine($"OK ({BitConverter.ToString(serializedPubKey).Substring(0, 20)}...)");

                // Test 4: Signing
                Console.Write("Test 4: Signing message... ");
                var messageHash = new byte[32];
                for (int i = 0; i < 32; i++)
                    messageHash[i] = (byte)(255 - i);

                var signature = new byte[64];
                if (!secp256k1.EcdsaSign(signature, messageHash, privateKey))
                {
                    Console.WriteLine("FAILED");
                    return 1;
                }
                Console.WriteLine("OK");

                // Test 5: Verification
                Console.Write("Test 5: Verifying signature... ");
                if (!secp256k1.EcdsaVerify(signature, messageHash, publicKey))
                {
                    Console.WriteLine("FAILED");
                    return 1;
                }
                Console.WriteLine("OK");

                // Test 6: ECDH
                Console.Write("Test 6: ECDH key exchange... ");
                var privateKey2 = new byte[32];
                var publicKey2 = new byte[64];
                for (int i = 0; i < 32; i++)
                    privateKey2[i] = (byte)(32 - i);

                if (!secp256k1.EcPubkeyCreate(publicKey2, privateKey2))
                {
                    Console.WriteLine("FAILED (could not create second public key)");
                    return 1;
                }

                var sharedSecret1 = new byte[32];
                var sharedSecret2 = new byte[32];

                if (!secp256k1.Ecdh(sharedSecret1, publicKey2, privateKey))
                {
                    Console.WriteLine("FAILED (ECDH with key1)");
                    return 1;
                }

                if (!secp256k1.Ecdh(sharedSecret2, publicKey, privateKey2))
                {
                    Console.WriteLine("FAILED (ECDH with key2)");
                    return 1;
                }

                bool secretsMatch = true;
                for (int i = 0; i < 32; i++)
                {
                    if (sharedSecret1[i] != sharedSecret2[i])
                    {
                        secretsMatch = false;
                        break;
                    }
                }

                if (!secretsMatch)
                {
                    Console.WriteLine("FAILED (shared secrets don't match)");
                    return 1;
                }
                Console.WriteLine("OK");

                // Test 7: DER signature serialization
                Console.Write("Test 7: DER signature serialization... ");
                var derSig = new byte[72];
                nuint derLen = 72;
                if (!secp256k1.EcdsaSignatureSerializeDer(derSig, ref derLen, signature))
                {
                    Console.WriteLine("FAILED");
                    return 1;
                }
                Console.WriteLine($"OK (length: {derLen})");

                Console.WriteLine();
                Console.WriteLine("=== All tests passed! ===");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED with exception:");
                Console.WriteLine(ex);
                return 1;
            }
        }
    }
}
