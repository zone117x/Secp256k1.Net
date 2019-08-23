using Secp256k1Net;
using System;
using System.Diagnostics;
using System.Text;

namespace Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create a secp256k1 context (ensure disposal to prevent unmanaged memory leaks).
            using (var secp256k1 = new Secp256k1())
            {

                // Generate a private key.
                var privateKey = new byte[32];
                var rnd = System.Security.Cryptography.RandomNumberGenerator.Create();
                do { rnd.GetBytes(privateKey); }
                while (!secp256k1.SecretKeyVerify(privateKey));


                // Create public key from private key.
                var publicKey = new byte[64];
                Debug.Assert(secp256k1.PublicKeyCreate(publicKey, privateKey));


                // Sign a message hash.
                var messageBytes = Encoding.UTF8.GetBytes("Hello world.");
                var messageHash = System.Security.Cryptography.SHA256.Create().ComputeHash(messageBytes);
                var signature = new byte[64];
                Debug.Assert(secp256k1.Sign(signature, messageHash, privateKey));

                // Serialize a DER signature from ECDSA signature
                byte[] signatureDer = new byte[Secp256k1.SERIALIZED_DER_SIGNATURE_MAX_SIZE];
                int outL = 0;
                Debug.Assert(secp256k1.SignatureSerializeDer(signatureDer, signature, out outL));
                Array.Resize(ref signatureDer, outL);

                // Verify message hash.
                Debug.Assert(secp256k1.Verify(signature, messageHash, publicKey));

            }
        }
    }
}
