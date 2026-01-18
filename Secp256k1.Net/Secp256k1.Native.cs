#if NET8_0_OR_GREATER
using System;
using System.Runtime.InteropServices;

namespace Secp256k1Net
{
    /// <summary>
    /// Native P/Invoke declarations for secp256k1 using LibraryImport (source-generated).
    /// </summary>
    internal static unsafe partial class Secp256k1Native
    {
        internal const string LIB = "secp256k1";

        /// <summary>
        /// Create a secp256k1 context object.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_context_create")]
        internal static partial IntPtr secp256k1_context_create(uint flags);

        /// <summary>
        /// Destroy a secp256k1 context object.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_context_destroy")]
        internal static partial void secp256k1_context_destroy(IntPtr ctx);

        /// <summary>
        /// Sets illegal callback for secp256k1 context object.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_context_set_illegal_callback")]
        internal static partial void secp256k1_context_set_illegal_callback(IntPtr ctx, IntPtr fun, void* data);

        /// <summary>
        /// Sets error callback for secp256k1 context object.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_context_set_error_callback")]
        internal static partial void secp256k1_context_set_error_callback(IntPtr ctx, IntPtr fun, void* data);

        /// <summary>
        /// Obtains the public key for a given private key.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ec_pubkey_create")]
        internal static partial int secp256k1_ec_pubkey_create(IntPtr ctx, byte* pubkey, byte* seckey);

        /// <summary>
        /// Verify an ECDSA secret key.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ec_seckey_verify")]
        internal static partial int secp256k1_ec_seckey_verify(IntPtr ctx, byte* seckey);

        /// <summary>
        /// Serialize a pubkey object into a serialized byte sequence.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ec_pubkey_serialize")]
        internal static partial int secp256k1_ec_pubkey_serialize(IntPtr ctx, byte* output, ref nuint outputlen, byte* pubkey, uint flags);

        /// <summary>
        /// Parse a variable-length public key into the pubkey object.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ec_pubkey_parse")]
        internal static partial int secp256k1_ec_pubkey_parse(IntPtr ctx, byte* pubkey, byte* input, nuint inputlen);

        /// <summary>
        /// Create a recoverable ECDSA signature.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_sign_recoverable")]
        internal static partial int secp256k1_ecdsa_sign_recoverable(IntPtr ctx, byte* sig, byte* msg32, byte* seckey, IntPtr noncefp, IntPtr ndata);

        /// <summary>
        /// Parse a compact ECDSA signature (64 bytes + recovery id).
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_recoverable_signature_parse_compact")]
        internal static partial int secp256k1_ecdsa_recoverable_signature_parse_compact(IntPtr ctx, byte* sig, byte* input64, int recid);

        /// <summary>
        /// Serialize an ECDSA signature in compact format (64 bytes + recovery id).
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_recoverable_signature_serialize_compact")]
        internal static partial int secp256k1_ecdsa_recoverable_signature_serialize_compact(IntPtr ctx, byte* output64, int* recid, byte* sig);

        /// <summary>
        /// Recover an ECDSA public key from a signature.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_recover")]
        internal static partial int secp256k1_ecdsa_recover(IntPtr ctx, byte* pubkey, byte* sig, byte* msg32);

        /// <summary>
        /// Create an ECDSA signature.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_sign")]
        internal static partial int secp256k1_ecdsa_sign(IntPtr ctx, byte* sig, byte* msg32, byte* seckey, IntPtr noncefp, void* ndata);

        /// <summary>
        /// Verify an ECDSA signature.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_verify")]
        internal static partial int secp256k1_ecdsa_verify(IntPtr ctx, byte* sig, byte* msg32, byte* pubkey);

        /// <summary>
        /// Normalizes a signature and enforces a low-S.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_signature_normalize")]
        internal static partial int secp256k1_ecdsa_signature_normalize(IntPtr ctx, byte* sigout, byte* sigin);

        /// <summary>
        /// Parse a DER ECDSA signature.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_signature_parse_der")]
        internal static partial int secp256k1_ecdsa_signature_parse_der(IntPtr ctx, byte* sig, byte* input, nuint inputlen);

        /// <summary>
        /// Parse an ECDSA signature in compact (64 bytes) format.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_signature_parse_compact")]
        internal static partial int secp256k1_ecdsa_signature_parse_compact(IntPtr ctx, byte* sig, byte* input64);

        /// <summary>
        /// Serialize an ECDSA signature in DER format.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_signature_serialize_der")]
        internal static partial int secp256k1_ecdsa_signature_serialize_der(IntPtr ctx, byte* output, ref nuint outputlen, byte* sig);

        /// <summary>
        /// Serialize an ECDSA signature in compact (64 byte) format.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdsa_signature_serialize_compact")]
        internal static partial int secp256k1_ecdsa_signature_serialize_compact(IntPtr ctx, byte* output64, byte* sig);

        /// <summary>
        /// Compute an EC Diffie-Hellman secret in constant time.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ecdh")]
        internal static partial int secp256k1_ecdh(IntPtr ctx, byte* output, byte* pubkey, byte* privkey, IntPtr hashfp, IntPtr data);

        /// <summary>
        /// Tweak a public key by multiplying it by a tweak.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ec_pubkey_tweak_mul")]
        internal static partial int secp256k1_ec_pubkey_tweak_mul(IntPtr ctx, byte* pubkey, byte* tweak);

        /// <summary>
        /// Negates a public key in place.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ec_pubkey_negate")]
        internal static partial int secp256k1_ec_pubkey_negate(IntPtr ctx, byte* pubkey);

        /// <summary>
        /// Add a number of public keys together.
        /// </summary>
        [LibraryImport(LIB, EntryPoint = "secp256k1_ec_pubkey_combine")]
        internal static partial int secp256k1_ec_pubkey_combine(IntPtr ctx, byte* outpubkey, IntPtr inpubkeys, nuint n);

        // Cached library handle for symbol lookups
        private static IntPtr _libHandle;
        private static readonly object _libLock = new();

        private static IntPtr GetLibHandle()
        {
            if (_libHandle != IntPtr.Zero)
                return _libHandle;

            lock (_libLock)
            {
                if (_libHandle != IntPtr.Zero)
                    return _libHandle;

                // Try standard resolution first, then fallback to LibPathResolver
                if (!NativeLibrary.TryLoad(LIB, typeof(Secp256k1Native).Assembly, null, out _libHandle))
                {
                    var path = LibPathResolver.Resolve(LIB);
                    _libHandle = NativeLibrary.Load(path);
                }
            }
            return _libHandle;
        }

        /// <summary>
        /// Gets the pointer to the RFC6979 nonce function.
        /// secp256k1_nonce_function_rfc6979 is a data symbol (function pointer), not a function.
        /// We get its address and dereference it.
        /// </summary>
        internal static IntPtr GetNonceFunctionRfc6979Ptr()
        {
            var libHandle = GetLibHandle();
            var symbolPtr = NativeLibrary.GetExport(libHandle, "secp256k1_nonce_function_rfc6979");
            // The symbol is a pointer to the function, so we need to read the pointer value
            return Marshal.ReadIntPtr(symbolPtr);
        }
    }
}
#endif
