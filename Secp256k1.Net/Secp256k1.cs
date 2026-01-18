using System;
using System.Runtime.InteropServices;

namespace Secp256k1Net
{

    /// <summary>
    /// A pointer to a function that applies hash function to a point.
    /// Returns: 1 if a point was successfully hashed. 0 will cause ecdh to fail.
    /// </summary>
    /// <param name="output">Pointer to an array to be filled by the function.</param>
    /// <param name="x">Pointer to a 32-byte x coordinate.</param>
    /// <param name="y">Pointer to a 32-byte y coordinate.</param>
    /// <param name="data">Arbitrary data pointer that is passed through.</param>
    /// <returns>Returns: 1 if a point was successfully hashed. 0 will cause ecdh to fail.</returns>
    public delegate int EcdhHashFunction(Span<byte> output, Span<byte> x, Span<byte> y, IntPtr data);


    public unsafe class Secp256k1 : IDisposable
    {

        public const int SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH = 65;
        public const int SERIALIZED_COMPRESSED_PUBKEY_LENGTH = 33;
        public const int PUBKEY_LENGTH = 64;
        public const int PRIVKEY_LENGTH = 32;
        public const int UNSERIALIZED_SIGNATURE_SIZE = 65;
        public const int SERIALIZED_SIGNATURE_SIZE = 64;
        public const int SERIALIZED_DER_SIGNATURE_MAX_SIZE = 72;
        public const int SIGNATURE_LENGTH = 64;
        public const int HASH_LENGTH = 32;
        public const int SECRET_LENGTH = 32;
        public const int NONCE_LENGTH = 32;

        internal const string LIB = "secp256k1";

#if !NET8_0_OR_GREATER
        // Legacy delegate-based loading for netstandard2.0 / .NET Framework
        static readonly Lazy<secp256k1_context_create> secp256k1_context_create_delegate
            = LazyDelegate<secp256k1_context_create>("secp256k1_context_create");
        static readonly Lazy<secp256k1_context_set_illegal_callback> secp256k1_context_set_illegal_callback_delegate
            = LazyDelegate<secp256k1_context_set_illegal_callback>("secp256k1_context_set_illegal_callback");
        static readonly Lazy<secp256k1_context_set_error_callback> secp256k1_context_set_error_callback_delegate
            = LazyDelegate<secp256k1_context_set_error_callback>("secp256k1_context_set_error_callback");
        static readonly Lazy<secp256k1_context_destroy> secp256k1_context_destroy_delegate
            = LazyDelegate<secp256k1_context_destroy>("secp256k1_context_destroy");
        static readonly Lazy<secp256k1_ec_pubkey_create> secp256k1_ec_pubkey_create_delegate
            = LazyDelegate<secp256k1_ec_pubkey_create>("secp256k1_ec_pubkey_create");
        static readonly Lazy<secp256k1_ec_seckey_verify> secp256k1_ec_seckey_verify_delegate
            = LazyDelegate<secp256k1_ec_seckey_verify>("secp256k1_ec_seckey_verify");
        static readonly Lazy<secp256k1_ec_pubkey_serialize> secp256k1_ec_pubkey_serialize_delegate
            = LazyDelegate<secp256k1_ec_pubkey_serialize>("secp256k1_ec_pubkey_serialize");
        static readonly Lazy<secp256k1_ec_pubkey_parse> secp256k1_ec_pubkey_parse_delegate
            = LazyDelegate<secp256k1_ec_pubkey_parse>("secp256k1_ec_pubkey_parse");
        static readonly Lazy<secp256k1_ecdsa_recoverable_signature_parse_compact> secp256k1_ecdsa_recoverable_signature_parse_compact_delegate
            = LazyDelegate<secp256k1_ecdsa_recoverable_signature_parse_compact>("secp256k1_ecdsa_recoverable_signature_parse_compact");
        static readonly Lazy<secp256k1_ecdsa_recoverable_signature_serialize_compact> secp256k1_ecdsa_recoverable_signature_serialize_compact_delegate
            = LazyDelegate<secp256k1_ecdsa_recoverable_signature_serialize_compact>("secp256k1_ecdsa_recoverable_signature_serialize_compact");
        static readonly Lazy<secp256k1_ecdsa_sign_recoverable> secp256k1_ecdsa_sign_recoverable_delegate
            = LazyDelegate<secp256k1_ecdsa_sign_recoverable>("secp256k1_ecdsa_sign_recoverable");
        static readonly Lazy<secp256k1_ecdsa_sign> secp256k1_ecdsa_sign_delegate
            = LazyDelegate<secp256k1_ecdsa_sign>("secp256k1_ecdsa_sign");
        static readonly Lazy<secp256k1_ecdsa_recover> secp256k1_ecdsa_recover_delegate
            = LazyDelegate<secp256k1_ecdsa_recover>("secp256k1_ecdsa_recover");
        static readonly Lazy<secp256k1_ecdsa_signature_normalize> secp256k1_ecdsa_signature_normalize_delegate
            = LazyDelegate<secp256k1_ecdsa_signature_normalize>("secp256k1_ecdsa_signature_normalize");
        static readonly Lazy<secp256k1_ecdsa_signature_parse_der> secp256k1_ecdsa_signature_parse_der_delegate
            = LazyDelegate<secp256k1_ecdsa_signature_parse_der>("secp256k1_ecdsa_signature_parse_der");
        static readonly Lazy<secp256k1_ecdsa_signature_parse_compact> secp256k1_ecdsa_signature_parse_compact_delegate
            = LazyDelegate<secp256k1_ecdsa_signature_parse_compact>("secp256k1_ecdsa_signature_parse_compact");
        static readonly Lazy<secp256k1_ecdsa_signature_serialize_der> secp256k1_ecdsa_signature_serialize_der_delegate
            = LazyDelegate<secp256k1_ecdsa_signature_serialize_der>("secp256k1_ecdsa_signature_serialize_der");
        static readonly Lazy<secp256k1_ecdsa_signature_serialize_compact> secp256k1_ecdsa_signature_serialize_compact_delegate
            = LazyDelegate<secp256k1_ecdsa_signature_serialize_compact>("secp256k1_ecdsa_signature_serialize_compact");
        static readonly Lazy<secp256k1_ecdsa_verify> secp256k1_ecdsa_verify_delegate
            = LazyDelegate<secp256k1_ecdsa_verify>("secp256k1_ecdsa_verify");
        static readonly Lazy<secp256k1_ecdh> secp256k1_ecdh_delegate
            = LazyDelegate<secp256k1_ecdh>("secp256k1_ecdh");
        static readonly Lazy<secp256k1_ec_pubkey_tweak_mul> secp256k1_ec_pubkey_tweak_mul_delegate
            = LazyDelegate<secp256k1_ec_pubkey_tweak_mul>("secp256k1_ec_pubkey_tweak_mul");
        static readonly Lazy<secp256k1_nonce_function> secp256k1_nonce_function_rfc6979_delegate
            = LazyDelegate<secp256k1_nonce_function>("secp256k1_nonce_function_rfc6979", Marshal.ReadIntPtr);
        static readonly Lazy<secp256k1_ec_pubkey_negate> secp256k1_ec_pubkey_negate_delegate =
            LazyDelegate<secp256k1_ec_pubkey_negate>("secp256k1_ec_pubkey_negate");
        static readonly Lazy<secp256k1_ec_pubkey_combine> secp256k1_ec_pubkey_combine_delegate =
            LazyDelegate<secp256k1_ec_pubkey_combine>("secp256k1_ec_pubkey_combine");

        /// <summary>
        /// Gets the resolved path to the native library (legacy mode only).
        /// </summary>
        public static string LibPath => _libPath.Value;
        static readonly Lazy<string> _libPath = new Lazy<string>(() => LibPathResolver.Resolve(LIB));
        static readonly Lazy<IntPtr> _libPtr = new Lazy<IntPtr>(() => LoadLibNative.LoadLib(_libPath.Value));

        static Lazy<TDelegate> LazyDelegate<TDelegate>(string symbol)
        {
            return new Lazy<TDelegate>(() =>
            {
                return LoadLibNative.GetDelegate<TDelegate>(_libPtr.Value, symbol);
            });
        }

        static Lazy<TDelegate> LazyDelegate<TDelegate>(string symbol, Func<IntPtr, IntPtr> pointerDereferenceFunc)
        {
            return new Lazy<TDelegate>(() =>
            {
                return LoadLibNative.GetDelegate<TDelegate>(_libPtr.Value, symbol, pointerDereferenceFunc);
            });
        }
#else
        // .NET 8+ uses LibraryImport with NativeLibrary resolver
        static Secp256k1()
        {
            NativeLibraryResolver.Initialize();
        }

        /// <summary>
        /// Gets the resolved path to the native library (for backwards compatibility).
        /// On .NET 8+, this uses LibPathResolver as a fallback mechanism.
        /// </summary>
        public static string LibPath => _libPath.Value;
        static readonly Lazy<string> _libPath = new Lazy<string>(() => LibPathResolver.Resolve(LIB));
#endif

        IntPtr _ctx;

        private ErrorCallbackDelegate _errorCallback;
        private GCHandle _errorCallbackHandle;
        private IntPtr _errorCallbackPtr;

        private static void DefaultErrorCallback(string message, void* data)
        {
            Console.Error.WriteLine(message);
        }

        public Secp256k1(ErrorCallbackDelegate errorCallback = null)
        {
#if NET8_0_OR_GREATER
            _ctx = Secp256k1Native.secp256k1_context_create((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
#else
            _ctx = secp256k1_context_create_delegate.Value((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
#endif
            SetErrorCallback(errorCallback ?? DefaultErrorCallback, null);
        }

        /// <summary>
        /// Sets user-defined error calback for this context.
        /// </summary>
        /// <param name="cb">User-defined callback, it is called in the case of the error or illegal operation.</param>
        /// <param name="data">User-defined callback marker, it is passed as second argument when callback is called.</param>
        public void SetErrorCallback(ErrorCallbackDelegate cb, void* data = null)
        {
            if (_errorCallbackPtr != IntPtr.Zero)
            {
                _errorCallbackHandle.Free();
            }
            _errorCallback = cb;
            _errorCallbackHandle = GCHandle.Alloc(_errorCallback);
            _errorCallbackPtr = Marshal.GetFunctionPointerForDelegate(_errorCallback);

#if NET8_0_OR_GREATER
            Secp256k1Native.secp256k1_context_set_illegal_callback(_ctx, _errorCallbackPtr, data);
            Secp256k1Native.secp256k1_context_set_error_callback(_ctx, _errorCallbackPtr, data);
#else
            secp256k1_context_set_illegal_callback_delegate.Value(_ctx, _errorCallback, data);
            secp256k1_context_set_error_callback_delegate.Value(_ctx, _errorCallback, data);
#endif
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

            fixed (byte* publicKeyPtr = &MemoryMarshal.GetReference(publicKeyOutput),
                sigPtr = &MemoryMarshal.GetReference(signature),
                msgPtr = &MemoryMarshal.GetReference(message))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdsa_recover(_ctx, publicKeyPtr, sigPtr, msgPtr) == 1;
#else
                return secp256k1_ecdsa_recover_delegate.Value(_ctx, publicKeyPtr, sigPtr, msgPtr) == 1;
#endif
            }
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

            fixed (byte* privKeyPtr = &MemoryMarshal.GetReference(secretKey))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ec_seckey_verify(_ctx, privKeyPtr) == 1;
#else
                return secp256k1_ec_seckey_verify_delegate.Value(_ctx, privKeyPtr) == 1;
#endif
            }
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

            fixed (byte* pubKeyPtr = &MemoryMarshal.GetReference(publicKeyOutput),
                privKeyPtr = &MemoryMarshal.GetReference(privateKeyInput))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ec_pubkey_create(_ctx, pubKeyPtr, privKeyPtr) == 1;
#else
                return secp256k1_ec_pubkey_create_delegate.Value(_ctx, pubKeyPtr, privKeyPtr) == 1;
#endif
            }
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

            fixed (byte* sigPtr = &MemoryMarshal.GetReference(signatureOutput),
                inputPtr = &MemoryMarshal.GetReference(compactSignature))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdsa_recoverable_signature_parse_compact(_ctx, sigPtr, inputPtr, recoveryID) == 1;
#else
                return secp256k1_ecdsa_recoverable_signature_parse_compact_delegate.Value(_ctx, sigPtr, inputPtr, recoveryID) == 1;
#endif
            }
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

            fixed (byte* sigPtr = &MemoryMarshal.GetReference(signatureOutput),
                msgPtr = &MemoryMarshal.GetReference(messageHash),
                secPtr = &MemoryMarshal.GetReference(secretKey.Slice(secretKey.Length - 32)))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdsa_sign_recoverable(_ctx, sigPtr, msgPtr, secPtr, IntPtr.Zero, IntPtr.Zero) == 1;
#else
                return secp256k1_ecdsa_sign_recoverable_delegate.Value(_ctx, sigPtr, msgPtr, secPtr, IntPtr.Zero, IntPtr.Zero) == 1;
#endif
            }
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
            fixed (byte* compactSigPtr = &MemoryMarshal.GetReference(compactSignatureOutput),
                sigPtr = &MemoryMarshal.GetReference(signature))
            {
#if NET8_0_OR_GREATER
                var result = Secp256k1Native.secp256k1_ecdsa_recoverable_signature_serialize_compact(_ctx, compactSigPtr, &recID, sigPtr);
#else
                var result = secp256k1_ecdsa_recoverable_signature_serialize_compact_delegate.Value(_ctx, compactSigPtr, ref recID, sigPtr);
#endif
                recoveryID = recID;

                return result == 1;
            }
        }

        /// <summary>
        /// Serialize a pubkey object into a serialized byte sequence.
        /// </summary>
        /// <param name="serializedPublicKeyOutput">65-byte (if compressed==0) or 33-byte (if compressed==1) output to place the serialized key in.</param>
        /// <param name="publicKey">The secp256k1_pubkey initialized public key.</param>
        /// <param name="flags">SECP256K1_EC_COMPRESSED if serialization should be in compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.</param>
        public bool PublicKeySerialize(Span<byte> serializedPublicKeyOutput, Span<byte> publicKey, Flags flags = Flags.SECP256K1_EC_UNCOMPRESSED)
        {
            bool compressed = flags.HasFlag(Flags.SECP256K1_EC_COMPRESSED);
            int serializedPubKeyLength = compressed ? SERIALIZED_COMPRESSED_PUBKEY_LENGTH : SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            if (serializedPublicKeyOutput.Length < serializedPubKeyLength)
            {
                string compressedStr = compressed ? "compressed" : "uncompressed";
                throw new ArgumentException($"{nameof(serializedPublicKeyOutput)} ({compressedStr}) must be {serializedPubKeyLength} bytes");
            }
            if (publicKey.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey)} must be {PUBKEY_LENGTH} bytes");
            }

            fixed (byte* serializedPtr = &MemoryMarshal.GetReference(serializedPublicKeyOutput),
                pubKeyPtr = &MemoryMarshal.GetReference(publicKey))
            {
#if NET8_0_OR_GREATER
                nuint newLength = (nuint)serializedPubKeyLength;
                var result = Secp256k1Native.secp256k1_ec_pubkey_serialize(_ctx, serializedPtr, ref newLength, pubKeyPtr, (uint)flags);
                return result == 1 && newLength == (nuint)serializedPubKeyLength;
#else
                uint newLength = (uint)serializedPubKeyLength;
                var result = secp256k1_ec_pubkey_serialize_delegate.Value(_ctx, serializedPtr, ref newLength, pubKeyPtr, (uint) flags);
                return result == 1 && newLength == serializedPubKeyLength;
#endif
            }
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

            fixed (byte* pubKeyPtr = &MemoryMarshal.GetReference(publicKeyOutput),
                serializedPtr = &MemoryMarshal.GetReference(serializedPublicKey))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ec_pubkey_parse(_ctx, pubKeyPtr, serializedPtr, (nuint)inputLen) == 1;
#else
                return secp256k1_ec_pubkey_parse_delegate.Value(_ctx, pubKeyPtr, serializedPtr, (uint) inputLen) == 1;
#endif
            }
        }

        /// <summary>
        /// Normalizes a signature and enforces a low-S.
        /// </summary>
        /// <param name="normalizedSignatureOutput">(Output) Signature to fill with the normalized form, or copy if the input was already normalized.</param>
        /// <param name="signatureInput">(Input) signature to check/normalize, can be identical to sigout</param>
        /// <returns>True if sigin was not normalized, false if it already was.</returns>
        public bool SignatureNormalize(Span<byte> normalizedSignatureOutput, Span<byte> signatureInput)
        {
            if (normalizedSignatureOutput.Length < SIGNATURE_LENGTH)
            {
                throw new ArgumentException($"{nameof(normalizedSignatureOutput)} must be {SIGNATURE_LENGTH} bytes");
            }
            if (signatureInput.Length < SIGNATURE_LENGTH)
            {
                throw new ArgumentException($"{nameof(signatureInput)} must be {SIGNATURE_LENGTH} bytes");
            }

            fixed (byte* outPtr = &MemoryMarshal.GetReference(normalizedSignatureOutput),
                intPtr = &MemoryMarshal.GetReference(signatureInput))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdsa_signature_normalize(_ctx, outPtr, intPtr) == 1;
#else
                return secp256k1_ecdsa_signature_normalize_delegate.Value(_ctx, outPtr, intPtr) == 1;
#endif
            }
        }

        /// <summary>
        /// Parse a DER ECDSA signature
        /// This function will accept any valid DER encoded signature, even if the
        /// encoded numbers are out of range.
        /// After the call, sig will always be initialized. If parsing failed or the
        /// encoded numbers are out of range, signature validation with it is
        /// guaranteed to fail for every message and public key.
        /// </summary>
        /// <param name="signatureOutput">(Output) a signature object</param>
        /// <param name="signatureInput">(Input) a signature to be parsed</param>
        /// <returns>True when the signature could be parsed, false otherwise.</returns>
        public bool SignatureParseDer(Span<byte> signatureOutput, Span<byte> signatureInput)
        {
            if (signatureOutput.Length < SIGNATURE_LENGTH)
            {
                throw new ArgumentException($"{nameof(signatureOutput)} must be {SIGNATURE_LENGTH} bytes");
            }

            fixed (byte* sig = &MemoryMarshal.GetReference(signatureOutput),
                input = &MemoryMarshal.GetReference(signatureInput))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdsa_signature_parse_der(_ctx, sig, input, (nuint)signatureInput.Length) == 1;
#else
                return secp256k1_ecdsa_signature_parse_der_delegate.Value(_ctx, sig, input, (uint)signatureInput.Length) == 1;
#endif
            }
        }

        /// <summary>
        /// Serialize an ECDSA signature in DER format (72 bytes maximum)
        /// This function will accept any valid ECDSA encoded signature
        /// </summary>
        /// <param name="signatureOutput">(Output) a signature object</param>
        /// <param name="signatureInput">(Input) a signature to be parsed</param>
        /// <param name="singatureOutputLength">(Output) lenght of serialized DER signature</param>
        /// <returns>True when the signature could be serialized, false otherwise.</returns>
        public bool SignatureSerializeDer(Span<byte> signatureOutput, Span<byte> signatureInput, out int singatureOutputLength)
        {
            if (signatureOutput.Length < SERIALIZED_DER_SIGNATURE_MAX_SIZE)
            {
                throw new ArgumentException($"{nameof(signatureOutput)} must be {SERIALIZED_DER_SIGNATURE_MAX_SIZE} bytes as maximum to void truncate signature");
            }

            fixed (byte* sig = &MemoryMarshal.GetReference(signatureOutput),
                input = &MemoryMarshal.GetReference(signatureInput))
            {
#if NET8_0_OR_GREATER
                nuint sigOutputLength = (nuint)SERIALIZED_DER_SIGNATURE_MAX_SIZE;
                var result = Secp256k1Native.secp256k1_ecdsa_signature_serialize_der(_ctx, sig, ref sigOutputLength, input);
                singatureOutputLength = (int)sigOutputLength;
#else
                uint sigOutputLength = (uint)SERIALIZED_DER_SIGNATURE_MAX_SIZE;
                var result = secp256k1_ecdsa_signature_serialize_der_delegate.Value(_ctx, sig, ref sigOutputLength, input);
                singatureOutputLength = (int)sigOutputLength;
#endif
                return result == 1;
            }
        }

        /// <summary>
        /// Serialize an ECDSA signature in compact (64 byte) format.
        /// </summary>
        /// <param name="signatureOutput">(Output) a 64-byte array to store the compact serialization</param>
        /// <param name="signatureInput">(Input) an initialized signature object</param>
        /// <returns>True when the signature could be serialized, false otherwise.</returns>
        public bool SignatureSerializeCompact(Span<byte> signatureOutput, Span<byte> signatureInput)
        {
            if (signatureOutput.Length < SERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signatureOutput)} must be {SIGNATURE_LENGTH} bytes");
            }

            if (signatureInput.Length < SIGNATURE_LENGTH)
            {
                throw new ArgumentException($"{nameof(signatureInput)} must be {SIGNATURE_LENGTH} bytes");
            }

            fixed (byte* output = &MemoryMarshal.GetReference(signatureOutput),
                sig = &MemoryMarshal.GetReference(signatureInput))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdsa_signature_serialize_compact(_ctx, output, sig) == 1;
#else
                return secp256k1_ecdsa_signature_serialize_compact_delegate.Value(_ctx, output, sig) == 1;
#endif
            }
        }

        /// <summary>
        /// Parse an ECDSA signature in compact (64 bytes) format.
        /// The signature must consist of a 32-byte big endian R value, followed by a
        /// 32-byte big endian S value. If R or S fall outside of[0..order - 1], the
        /// encoding is invalid. R and S with value 0 are allowed in the encoding.
        /// After the call, sig will always be initialized.If parsing failed or R or
        /// S are zero, the resulting sig value is guaranteed to fail verification for
        /// any message and public key.
        /// </summary>
        /// <param name="signatureOutput">(Output) a 64-byte array to store the parsed signature</param>
        /// <param name="signatureInput">(Input) a 64-byte array of the serialized signature</param>
        /// <returns>True when the signature could be parsed, false otherwise.</returns>
        public bool SignatureParseCompact(Span<byte> signatureOutput, Span<byte> signatureInput)
        {
            if (signatureOutput.Length < SIGNATURE_LENGTH)
            {
                throw new ArgumentException($"{nameof(signatureOutput)} must be {SIGNATURE_LENGTH} bytes");
            }

            if (signatureInput.Length < SERIALIZED_SIGNATURE_SIZE)
            {
                throw new ArgumentException($"{nameof(signatureInput)} must be {SIGNATURE_LENGTH} bytes");
            }

            fixed (byte* output = &MemoryMarshal.GetReference(signatureOutput),
                sig = &MemoryMarshal.GetReference(signatureInput))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdsa_signature_parse_compact(_ctx, output, sig) == 1;
#else
                return secp256k1_ecdsa_signature_parse_compact_delegate.Value(_ctx, output, sig) == 1;
#endif
            }
        }

        /// <summary>
        /// Verify an ECDSA signature.
        /// To avoid accepting malleable signatures, only ECDSA signatures in lower-S
        /// form are accepted.
        /// If you need to accept ECDSA signatures from sources that do not obey this
        /// rule, apply secp256k1_ecdsa_signature_normalize to the signature prior to
        /// validation, but be aware that doing so results in malleable signatures.
        /// For details, see the comments for that function.
        /// </summary>
        /// <param name="signature">The signature being verified.</param>
        /// <param name="messageHash">The 32-byte message hash being verified.</param>
        /// <param name="publicKey">An initialized public key to verify with.</param>
        /// <returns>True if correct signature, false if incorrect or unparseable signature.</returns>
        public bool Verify(Span<byte> signature, Span<byte> messageHash, Span<byte> publicKey)
        {
            if (signature.Length < SIGNATURE_LENGTH)
            {
                throw new ArgumentException($"{nameof(signature)} must be {SIGNATURE_LENGTH} bytes");
            }
            if (messageHash.Length < HASH_LENGTH)
            {
                throw new ArgumentException($"{nameof(messageHash)} must be {HASH_LENGTH} bytes");
            }
            if (publicKey.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey)} must be {PUBKEY_LENGTH} bytes");
            }

            fixed (byte* sigPtr = &MemoryMarshal.GetReference(signature),
                msgPtr = &MemoryMarshal.GetReference(messageHash),
                pubPtr = &MemoryMarshal.GetReference(publicKey))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdsa_verify(_ctx, sigPtr, msgPtr, pubPtr) == 1;
#else
                return secp256k1_ecdsa_verify_delegate.Value(_ctx, sigPtr, msgPtr, pubPtr) == 1;
#endif
            }
        }

        /// <summary>
        /// Create an ECDSA signature.
        /// The created signature is always in lower-S form. See
        /// secp256k1_ecdsa_signature_normalize for more details.
        /// </summary>
        /// <param name="signatureOutput">An array where the signature will be placed.</param>
        /// <param name="messageHash">The 32-byte message hash being signed.</param>
        /// <param name="secretKey">A 32-byte secret key.</param>
        /// <returns></returns>
        public bool Sign(Span<byte> signatureOutput, Span<byte> messageHash, Span<byte> secretKey)
        {
            if (signatureOutput.Length < SIGNATURE_LENGTH)
            {
                throw new ArgumentException($"{nameof(signatureOutput)} must be {SIGNATURE_LENGTH} bytes");
            }
            if (messageHash.Length < HASH_LENGTH)
            {
                throw new ArgumentException($"{nameof(messageHash)} must be {HASH_LENGTH} bytes");
            }
            if (secretKey.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(secretKey)} must be {PRIVKEY_LENGTH} bytes");
            }

            fixed (byte* sigPtr = &MemoryMarshal.GetReference(signatureOutput),
                msgPtr = &MemoryMarshal.GetReference(messageHash),
                secPtr = &MemoryMarshal.GetReference(secretKey))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdsa_sign(_ctx, sigPtr, msgPtr, secPtr, IntPtr.Zero, null) == 1;
#else
                return secp256k1_ecdsa_sign_delegate.Value(_ctx, sigPtr, msgPtr, secPtr, IntPtr.Zero, IntPtr.Zero.ToPointer()) == 1;
#endif
            }
        }

        /// <summary>
        /// Compute an EC Diffie-Hellman secret in constant time.
        /// </summary>
        /// <param name="resultOutput">A 32-byte array which will be populated by an ECDH secret computed from the point and scalar.</param>
        /// <param name="publicKey">A secp256k1_pubkey containing an initialized public key.</param>
        /// <param name="privateKey">A 32-byte scalar with which to multiply the point.</param>
        /// <returns>True if exponentiation was successful, false if scalar was invalid (zero or overflow).</returns>
        public bool Ecdh(Span<byte> resultOutput, Span<byte> publicKey, Span<byte> privateKey)
        {
            if (resultOutput.Length < SECRET_LENGTH)
            {
                throw new ArgumentException($"{nameof(resultOutput)} must be {SECRET_LENGTH} bytes");
            }
            if (publicKey.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey)} must be {PUBKEY_LENGTH} bytes");
            }
            if (privateKey.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(privateKey)} must be {PRIVKEY_LENGTH} bytes");
            }

            fixed (byte* resPtr = &MemoryMarshal.GetReference(resultOutput),
                pubPtr = &MemoryMarshal.GetReference(publicKey),
                privPtr = &MemoryMarshal.GetReference(privateKey))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ecdh(_ctx, resPtr, pubPtr, privPtr, IntPtr.Zero, IntPtr.Zero) == 1;
#else
                return secp256k1_ecdh_delegate.Value(_ctx, resPtr, pubPtr, privPtr, null, IntPtr.Zero) == 1;
#endif
            }
        }

        /// <summary>
        /// Compute an EC Diffie-Hellman secret in constant time.
        /// </summary>
        /// <param name="resultOutput">A 32-byte array which will be populated by an ECDH secret computed from the point and scalar.</param>
        /// <param name="publicKey">A secp256k1_pubkey containing an initialized public key.</param>
        /// <param name="privateKey">A 32-byte scalar with which to multiply the point.</param>
        /// <param name="hashFunction">Pointer to a hash function. If null, sha256 is used.</param>
        /// <param name="data">Arbitrary data that is passed through.</param>
        /// <returns>True if exponentiation was successful, false if scalar was invalid (zero or overflow).</returns>
        public bool Ecdh(Span<byte> resultOutput, Span<byte> publicKey, Span<byte> privateKey, EcdhHashFunction hashFunction, IntPtr data)
        {
            if (resultOutput.Length < SECRET_LENGTH)
            {
                throw new ArgumentException($"{nameof(resultOutput)} must be {SECRET_LENGTH} bytes");
            }
            if (publicKey.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey)} must be {PUBKEY_LENGTH} bytes");
            }
            if (privateKey.Length < PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(privateKey)} must be {PRIVKEY_LENGTH} bytes");
            }

            int outputLength = resultOutput.Length;

            secp256k1_ecdh_hash_function hashFunctionPtr = (void* output, void* x, void* y, IntPtr d) =>
            {
                var outputSpan = new Span<byte>(output, outputLength);
                var xSpan = new Span<byte>(x, 32);
                var ySpan = new Span<byte>(y, 32);
                return hashFunction(outputSpan, xSpan, ySpan, d);
            };

            fixed (byte* resPtr = &MemoryMarshal.GetReference(resultOutput),
                pubPtr = &MemoryMarshal.GetReference(publicKey),
                privPtr = &MemoryMarshal.GetReference(privateKey))
            {
#if NET8_0_OR_GREATER
                var funcPtr = Marshal.GetFunctionPointerForDelegate(hashFunctionPtr);
                return Secp256k1Native.secp256k1_ecdh(_ctx, resPtr, pubPtr, privPtr, funcPtr, data) == 1;
#else
                return secp256k1_ecdh_delegate.Value(_ctx, resPtr, pubPtr, privPtr, hashFunctionPtr, data) == 1;
#endif
            }
        }

        /// <summary>
        /// Adds two public keys.
        /// </summary>
        /// <param name="outputPublicKey">The sum public key to be written to.</param>
        /// <param name="publicKey1">The first public key.</param>
        /// <param name="publicKey2">The second public key.</param>
        /// <returns>True if the sum of the public keys is valid, false if the sum of the public keys is not valid.</returns>
        /// <exception cref="ArgumentException"></exception>
        public bool PublicKeysCombine(Span<byte> outputPublicKey, Span<byte> publicKey1, Span<byte> publicKey2)
        {
            if ( outputPublicKey.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(outputPublicKey)} must be {PUBKEY_LENGTH} bytes");
            }

            if ( publicKey1.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey1)} must be {PUBKEY_LENGTH} bytes");
            }
            if ( publicKey2.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey2)} must be {PUBKEY_LENGTH} bytes");
            }

            var intPtrSize = Marshal.SizeOf(typeof(IntPtr));
            var nativeArray = Marshal.AllocHGlobal(intPtrSize * 2);
            try
            {
                fixed (
                    byte* outPubPtr = &MemoryMarshal.GetReference(outputPublicKey),
                    inPubPtr1 = &MemoryMarshal.GetReference(publicKey1),
                    inPubPtr2 = &MemoryMarshal.GetReference(publicKey2))
                {
                    Marshal.WriteIntPtr(nativeArray, 0, (IntPtr)inPubPtr1);
                    Marshal.WriteIntPtr(nativeArray, intPtrSize, (IntPtr)inPubPtr2);
#if NET8_0_OR_GREATER
                    return Secp256k1Native.secp256k1_ec_pubkey_combine(_ctx, outPubPtr, nativeArray, 2) == 1;
#else
                    return secp256k1_ec_pubkey_combine_delegate.Value(_ctx, outPubPtr, nativeArray, 2) == 1;
#endif
                }
            }
            finally
            {
                Marshal.FreeHGlobal(nativeArray);
            }
        }
        /// <summary>
        /// Negates a public key in place.
        /// </summary>
        /// <param name="publicKey">The 65 byte public key which will be negated in place.</param>
        /// <returns>True always.</returns>
        /// <exception cref="ArgumentException"></exception>
        public bool PublicKeyNegate(Span<byte> publicKey)
        {
            if (publicKey.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey)} must be {PUBKEY_LENGTH} bytes");
            }
            fixed (byte* pubPtr = &MemoryMarshal.GetReference(publicKey))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ec_pubkey_negate(_ctx, pubPtr) == 1;
#else
                return secp256k1_ec_pubkey_negate_delegate.Value(_ctx, pubPtr) == 1;
#endif
            }
        }

        /// <summary>
        /// Multiplies the public key with a 32 byte scalar.
        /// </summary>
        /// <param name="publicKey">The public key to be multiplied and the result to be written to.</param>
        /// <param name="tweak">The 32 byte scalar.</param>
        /// <returns>True if the arguments are valid and false otherwise.</returns>
        /// <exception cref="ArgumentException"></exception>
        public bool PublicKeyMultiply(Span<byte> publicKey, Span<byte> tweak)
        {
            if (publicKey.Length < PUBKEY_LENGTH)
            {
                throw new ArgumentException($"{nameof(publicKey)} must be {PUBKEY_LENGTH} bytes");
            }
            if (tweak.Length < SECRET_LENGTH)
            {
                throw new ArgumentException($"{nameof(tweak)} must be {SECRET_LENGTH} bytes");
            }
            fixed (byte* pubPtr = &MemoryMarshal.GetReference(publicKey),
                   tweakPtr = &MemoryMarshal.GetReference(tweak))
            {
#if NET8_0_OR_GREATER
                return Secp256k1Native.secp256k1_ec_pubkey_tweak_mul(_ctx, pubPtr, tweakPtr) == 1;
#else
                return secp256k1_ec_pubkey_tweak_mul_delegate.Value(_ctx, pubPtr, tweakPtr) == 1;
#endif
            }
        }

        /// <summary>
        /// Deterministically generate a 32 byte nonce according to RFC6979 standard.
        /// </summary>
        /// <param name="nonceOutput">The 32 byte output nonce to be written to.</param>
        /// <param name="hash">The 32 byte message hash being verified.</param>
        /// <param name="secretKey">The 32 byte secret key.</param>
        /// <param name="algo">A 16 byte array describing the signature algorithm (will be NULL for ECDSA for compatibility).</param>
        /// <param name="data">Arbitrary data that is passed through.</param>
        /// <param name="attempt">How many iterations we have tried to find a nonce. This will almost always be 0, but different attempt values are required to result in a different nonce.</param>
        /// <returns>True if a nonce was successfully generated, false otherwise.</returns>
        /// <exception cref="ArgumentException"></exception>
        public bool Rfc6979Nonce(Span<byte> nonceOutput, Span<byte> hash, Span<byte> secretKey, Span<byte> algo, Span<byte> data, uint attempt)
        {
            if (nonceOutput.Length < NONCE_LENGTH)
            {
                throw new ArgumentException($"{nameof(nonceOutput)} must be {NONCE_LENGTH} bytes");
            }
            if (hash.Length < HASH_LENGTH)
            {
                throw new ArgumentException($"{nameof(hash)} must be {HASH_LENGTH} bytes");
            }
            if (secretKey.Length < SECRET_LENGTH)
            {
                throw new ArgumentException($"{nameof(secretKey)} must be {SECRET_LENGTH} bytes");
            }
            fixed (byte* nonceOutPtr = &MemoryMarshal.GetReference(nonceOutput),
                   hashPtr = &MemoryMarshal.GetReference(hash),
                   secPtr = &MemoryMarshal.GetReference(secretKey),
                   algoPtr = &MemoryMarshal.GetReference(algo),
                   dataPtr = &MemoryMarshal.GetReference(data))
            {
#if NET8_0_OR_GREATER
                // For .NET 8+, we need to get the function pointer from the data symbol
                // and call it via delegate since it's a data export, not a function
                var nonceFuncPtr = Secp256k1Native.GetNonceFunctionRfc6979Ptr();
                var nonceFunc = Marshal.GetDelegateForFunctionPointer<secp256k1_nonce_function>(nonceFuncPtr);
                return nonceFunc(nonceOutPtr, hashPtr, secPtr, algoPtr, dataPtr, attempt) == 1;
#else
                return secp256k1_nonce_function_rfc6979_delegate.Value(nonceOutPtr, hashPtr, secPtr, algoPtr, dataPtr, attempt) == 1;
#endif
            }
        }

        public void Dispose()
        {
            if (_errorCallbackPtr != IntPtr.Zero)
            {
                _errorCallbackHandle.Free();
                _errorCallbackPtr = IntPtr.Zero;
            }
            if (_ctx != IntPtr.Zero)
            {
#if NET8_0_OR_GREATER
                Secp256k1Native.secp256k1_context_destroy(_ctx);
#else
                secp256k1_context_destroy_delegate.Value(_ctx);
#endif
                _ctx = IntPtr.Zero;
            }
        }



    }
}
