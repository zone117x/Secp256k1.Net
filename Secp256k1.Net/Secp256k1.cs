using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Secp256k1Net
{
    public unsafe class Secp256k1 : IDisposable
    {
        public IntPtr Context => _ctx;

        public const int SERIALIZED_PUBKEY_LENGTH = 65;
        public const int PUBKEY_LENGTH = 64;
        public const int PRIVKEY_LENGTH = 32;
        public const int UNSERIALIZED_SIGNATURE_SIZE = 65;
        public const int SERIALIZED_SIGNATURE_SIZE = 64;


        readonly Lazy<secp256k1_context_create> secp256k1_context_create;
        readonly Lazy<secp256k1_ecdsa_recover> secp256k1_ecdsa_recover;
        readonly Lazy<secp256k1_ec_pubkey_create> secp256k1_ec_pubkey_create;
        readonly Lazy<secp256k1_ec_seckey_verify> secp256k1_ec_seckey_verify;
        readonly Lazy<secp256k1_ecdsa_recoverable_signature_parse_compact> secp256k1_ecdsa_recoverable_signature_parse_compact;
        readonly Lazy<secp256k1_ecdsa_sign_recoverable> secp256k1_ecdsa_sign_recoverable;
        readonly Lazy<secp256k1_ecdsa_recoverable_signature_serialize_compact> secp256k1_ecdsa_recoverable_signature_serialize_compact;
        readonly Lazy<secp256k1_ec_pubkey_serialize> secp256k1_ec_pubkey_serialize;
        readonly Lazy<secp256k1_context_destroy> secp256k1_context_destroy;
        readonly Lazy<secp256k1_ec_pubkey_parse> secp256k1_ec_pubkey_parse;
        readonly Lazy<secp256k1_ecdsa_signature_normalize> secp256k1_ecdsa_signature_normalize;

        const string LIB = "secp256k1";
        public readonly string LibPath;
        readonly IntPtr _libPtr;
        IntPtr _ctx;

        public Secp256k1()
        {
            LibPath = LibPathResolver.Resolve(LIB);
            _libPtr = LoadLibNative.LoadLib(LibPath);

            secp256k1_context_create = LazyDelegate<secp256k1_context_create>();
            secp256k1_ecdsa_recover = LazyDelegate<secp256k1_ecdsa_recover>();
            secp256k1_ec_pubkey_create = LazyDelegate<secp256k1_ec_pubkey_create>();
            secp256k1_ec_seckey_verify = LazyDelegate<secp256k1_ec_seckey_verify>();
            secp256k1_ecdsa_recoverable_signature_parse_compact = LazyDelegate<secp256k1_ecdsa_recoverable_signature_parse_compact>();
            secp256k1_ecdsa_sign_recoverable = LazyDelegate<secp256k1_ecdsa_sign_recoverable>();
            secp256k1_ecdsa_recoverable_signature_serialize_compact = LazyDelegate<secp256k1_ecdsa_recoverable_signature_serialize_compact>();
            secp256k1_ec_pubkey_serialize = LazyDelegate<secp256k1_ec_pubkey_serialize>();
            secp256k1_context_destroy = LazyDelegate<secp256k1_context_destroy>();
            secp256k1_ec_pubkey_parse = LazyDelegate<secp256k1_ec_pubkey_parse>();
            secp256k1_ecdsa_signature_normalize = LazyDelegate<secp256k1_ecdsa_signature_normalize>();

            _ctx = secp256k1_context_create.Value(((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY)));
        }

        Lazy<TDelegate> LazyDelegate<TDelegate>()
        {
            var symbol = SymbolNameCache<TDelegate>.SymbolName;
            return new Lazy<TDelegate>(() => LoadLibNative.GetDelegate<TDelegate>(_libPtr, symbol), isThreadSafe: false);
        }

        /// <summary>
        /// Recover an ECDSA public key from a signature.
        /// </summary>
        /// <param name="publicKeyOutput">Output for the 64 byte recovered public key to be written to.</param>
        /// <param name="signature">The initialized signature that supports pubkey recovery.</param>
        /// <param name="message">The 32-byte message hash assumed to be signed.</param>
        /// <returns>
        /// True if the public key successfully recovered (which guarantees a correct signature).
        /// </returns>
        public bool Recover(Span<byte> publicKeyOutput, Span<byte> signature, Span<byte> message)
        {
            if (publicKeyOutput.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKeyOutput)} must be {PUBKEY_LENGTH} bytes");
            }
            if (signature.Length < UNSERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signature)} must be {UNSERIALIZED_SIGNATURE_SIZE} bytes");
            }
            if (message.Length < 32)
            {
                throw new ArgumentException($"{nameof(message)} must be 32 bytes");
            }

            var publicKeyPtr = Unsafe.AsPointer(ref publicKeyOutput[0]);
            var sigPtr = Unsafe.AsPointer(ref signature[0]);
            var msgPtr = Unsafe.AsPointer(ref message[0]);
            var result = secp256k1_ecdsa_recover.Value(_ctx, publicKeyPtr, sigPtr, msgPtr);

            // Verify we succeeded
            return result == 1;
        }

        /// <summary>
        /// Verify an ECDSA secret key.
        /// </summary>
        /// <param name="secretKey">32-byte secret key.</param>
        /// <returns>True if secret key is valid, false if secret key is invalid.</returns>
        public bool SecretKeyVerify(Span<byte> secretKey)
        {
            if (secretKey.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(secretKey)} must be {PRIVKEY_LENGTH} bytes");
            }
            var privKeyPtr = Unsafe.AsPointer(ref secretKey[0]);
            var result = secp256k1_ec_seckey_verify.Value(_ctx, privKeyPtr);
            return result == 1;
        }

        /// <summary>
        /// Gets the public key for a given private key.
        /// </summary>
        /// <param name="publicKeyOutput">Output for the 64 byte recovered public key to be written to.</param>
        /// <param name="privateKeyInput">The input private key to obtain the public key for.</param>
        /// <returns>
        /// True if the private key is valid and public key was obtained.
        /// </returns>
        public bool PublicKeyCreate(Span<byte> publicKeyOutput, Span<byte> privateKeyInput)
        {
            if (publicKeyOutput.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKeyOutput)} must be {PUBKEY_LENGTH} bytes");
            }
            if (privateKeyInput.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(privateKeyInput)} must be {PRIVKEY_LENGTH} bytes");
            }

            var pubKeyPtr = Unsafe.AsPointer(ref publicKeyOutput[0]);
            var privKeyPtr = Unsafe.AsPointer(ref privateKeyInput[0]);
            var result = secp256k1_ec_pubkey_create.Value(_ctx, pubKeyPtr, privKeyPtr);

            // Verify we succeeded
            return result == 1;
        }

        /// <summary>
        /// Parse a compact ECDSA signature (64 bytes + recovery id).
        /// </summary>
        /// <param name="signatureOutput">Output for the signature to be written to.</param>
        /// <param name="compactSignature">The 64-byte compact signature input.</param>
        /// <param name="recoveryID">The recovery id (0, 1, 2 or 3).</param>
        /// <returns>True when the signature could be parsed.</returns>
        public bool RecoverableSignatureParseCompact(Span<byte> signatureOutput, Span<byte> compactSignature, int recoveryID)
        {
            if (signatureOutput.Length < UNSERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signatureOutput)} must be 64 bytes");
            }
            if (compactSignature.Length < SERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(compactSignature)} must be 64 bytes");
            }

            var sigPtr = Unsafe.AsPointer(ref signatureOutput[0]);
            var intputPtr = Unsafe.AsPointer(ref compactSignature[0]);
            var result = secp256k1_ecdsa_recoverable_signature_parse_compact.Value(_ctx, sigPtr, intputPtr, recoveryID);

            return result == 1;
        }

        /// <summary>
        /// Create a recoverable ECDSA signature.
        /// </summary>
        /// <param name="signatureOutput">Output where the signature will be placed.</param>
        /// <param name="messageHash">The 32-byte message hash being signed.</param>
        /// <param name="secretKey">A 32-byte secret key.</param>
        /// <returns>
        /// True if signature created, false if the nonce generation function failed, or the private key was invalid.
        /// </returns>
        public bool SignRecoverable(Span<byte> signatureOutput, Span<byte> messageHash, Span<byte> secretKey)
        {
            if (signatureOutput.Length < UNSERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signatureOutput)} must be 65 bytes");
            }
            if (messageHash.Length < 32)
            {
                throw new ArgumentException($"{nameof(messageHash)} must be 32 bytes");
            }
            if (secretKey.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(secretKey)} must be 32 bytes");
            }

            var sigPtr = Unsafe.AsPointer(ref signatureOutput[0]);
            var msgPtr = Unsafe.AsPointer(ref messageHash[0]);
            var secPtr = Unsafe.AsPointer(ref secretKey.Slice(secretKey.Length - 32)[0]);
            var result = secp256k1_ecdsa_sign_recoverable.Value(_ctx, sigPtr, msgPtr, secPtr, IntPtr.Zero, IntPtr.Zero);

            // Verify we didn't fail.
            return result == 1;
        }


        /// <summary>
        /// Serialize an ECDSA signature in compact format (64 bytes + recovery id).
        /// </summary>
        /// <param name="compactSignatureOutput">Output for the 64-byte array of the compact signature.</param>
        /// <param name="recoveryID">The recovery ID.</param>
        /// <param name="signature">The initialized signature.</param>
        public bool RecoverableSignatureSerializeCompact(Span<byte> compactSignatureOutput, out int recoveryID, Span<byte> signature)
        {
            if (compactSignatureOutput.Length < SERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(compactSignatureOutput)} must be {SERIALIZED_SIGNATURE_SIZE} bytes");
            }
            if (signature.Length < UNSERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signature)} must be {UNSERIALIZED_SIGNATURE_SIZE} bytes");
            }

            int recID = 0;
            var compactSigPtr = Unsafe.AsPointer(ref compactSignatureOutput[0]);
            var sigPtr = Unsafe.AsPointer(ref signature[0]);
            var result = secp256k1_ecdsa_recoverable_signature_serialize_compact.Value(_ctx, compactSigPtr, ref recID, sigPtr);
            recoveryID = recID;

            return result == 1;
        }

        /// <summary>
        /// Serialize a pubkey object into a serialized byte sequence.
        /// </summary>
        /// <param name="serializedPublicKeyOutput">65-byte (if compressed==0) or 33-byte (if compressed==1) output to place the serialized key in.</param>
        /// <param name="publicKey">The secp256k1_pubkey initialized public key.</param>
        /// <param name="flags">SECP256K1_EC_COMPRESSED if serialization should be in compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.</param>
        public bool PublicKeySerialize(Span<byte> serializedPublicKeyOutput, Span<byte> publicKey, Flags flags = Flags.SECP256K1_EC_UNCOMPRESSED)
        {
            if (serializedPublicKeyOutput.Length < SERIALIZED_PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(serializedPublicKeyOutput)} must be {SERIALIZED_PUBKEY_LENGTH} bytes");
            }
            if (publicKey.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey)} must be {PUBKEY_LENGTH} bytes");
            }
            var serializedPtr = Unsafe.AsPointer(ref serializedPublicKeyOutput[0]);
            var pubKeyPtr = Unsafe.AsPointer(ref publicKey[0]);

            uint newLength = SERIALIZED_PUBKEY_LENGTH;
            var result = secp256k1_ec_pubkey_serialize.Value(_ctx, serializedPtr, ref newLength, pubKeyPtr, (uint)flags);
            return result == 1 && newLength == SERIALIZED_PUBKEY_LENGTH;
        }

        /// <summary>
        /// Parse a variable-length public key into the pubkey object.
        /// This function supports parsing compressed (33 bytes, header byte 0x02 or
        /// 0x03), uncompressed(65 bytes, header byte 0x04), or hybrid(65 bytes, header
        /// byte 0x06 or 0x07) format public keys.
        /// </summary>
        /// <param name="publicKeyOutput">(Output) pointer to a pubkey object. If 1 is returned, it is set to a parsed version of input. If not, its value is undefined.</param>
        /// <param name="serializedPublicKey">Serialized public key.</param>
        /// <returns>True if the public key was fully valid, false if the public key could not be parsed or is invalid.</returns>
        public bool PublicKeyParse(Span<byte> publicKeyOutput, Span<byte> serializedPublicKey)
        {
            var inputLen = serializedPublicKey.Length;
            if (inputLen != 33 && inputLen != 65)
            {
                throw new ArgumentException($"{nameof(serializedPublicKey)} must be 33 or 65 bytes");
            }
            if (publicKeyOutput.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKeyOutput)} must be {PUBKEY_LENGTH} bytes");
            }
            var pubKeyPtr = Unsafe.AsPointer(ref publicKeyOutput[0]);
            var serializedPtr = Unsafe.AsPointer(ref serializedPublicKey[0]);
            var result = secp256k1_ec_pubkey_parse.Value(_ctx, pubKeyPtr, serializedPtr, (uint)inputLen);
            return result == 1;
        }

        /// <summary>
        /// Normalizes a signature and enforces a low-S.
        /// </summary>
        /// <param name="normalizedSignatureOutput">(Output) Signature to fill with the normalized form, or copy if the input was already normalized.</param>
        /// <param name="signatureInput">(Input) signature to check/normalize, can be identical to sigout</param>
        /// <returns>True if sigin was not normalized, false if it already was.</returns>
        public bool SignatureNormalize(Span<byte> normalizedSignatureOutput, Span<byte> signatureInput)
        {
            if (normalizedSignatureOutput.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(normalizedSignatureOutput)} must be {PRIVKEY_LENGTH} bytes");
            }
            if (signatureInput.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(signatureInput)} must be {PRIVKEY_LENGTH} bytes");
            }
            var outPtr = Unsafe.AsPointer(ref normalizedSignatureOutput[0]);
            var intPtr = Unsafe.AsPointer(ref signatureInput[0]);
            var result = secp256k1_ecdsa_signature_normalize.Value(_ctx, outPtr, intPtr);
            return result == 1;
        }


        public void Dispose()
        {
            if (_ctx != IntPtr.Zero)
            {
                secp256k1_context_destroy.Value(_ctx);
                _ctx = IntPtr.Zero;
            }
        }



    }
}
