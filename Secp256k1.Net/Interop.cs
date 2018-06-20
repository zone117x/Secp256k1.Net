using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Secp256k1Net
{
    public static unsafe class Interop
    {
        public const string LIB = "secp256k1";

        static Interop()
        {
            var libPath = LibPathResolver.Resolve(LIB);
            LoadLibNative.LoadLib(libPath);
        }

        /// <summary>
        /// Create a secp256k1 context object.
        /// </summary>
        /// <param name="flags">which parts of the context to initialize.</param>
        /// <returns>a newly created context object.</returns>
        [DllImport(LIB)]
        public static extern IntPtr secp256k1_context_create(uint flags);


        /// <summary>
        /// Destroy a secp256k1 context object. The context pointer may not be used afterwards.
        /// </summary>
        /// <param name="ctx">ctx: an existing context to destroy (cannot be NULL).</param>
        [DllImport(LIB)]
        public static extern void secp256k1_context_destroy(IntPtr ctx);


        /// <summary>
        /// Create a recoverable ECDSA signature.
        /// </summary>
        /// <param name="ctx">pointer to a context object, initialized for signing (cannot be NULL)</param>
        /// <param name="sig">(Output) pointer to an array where the signature will be placed (cannot be NULL)</param>
        /// <param name="msg32">the 32-byte message hash being signed (cannot be NULL)</param>
        /// <param name="seckey">pointer to a 32-byte secret key (cannot be NULL)</param>
        /// <param name="noncefp">pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used</param>
        /// <param name="ndata">pointer to arbitrary data used by the nonce generation function (can be NULL)</param>
        /// <returns>
        /// 1: signature created
        /// 0: the nonce generation function failed, or the private key was invalid.
        /// </returns>
        [DllImport(LIB)]
        public static extern int secp256k1_ecdsa_sign_recoverable(IntPtr ctx,
            void* sig,      // secp256k1_ecdsa_recoverable_signature *sig 
            void* msg32,    // const unsigned char* msg32
            void* seckey,   // const unsigned char* seckey
            IntPtr noncefp, // secp256k1_nonce_function noncefp
            IntPtr ndata    // const void* ndata
        );

        /// <summary>
        /// Obtains the public key for a given private key.
        /// </summary>
        /// <param name="ctx">pointer to a context object, initialized for signing (cannot be NULL)</param>
        /// <param name="pubKeyOut">(Output) pointer to the created public key (cannot be NULL)</param>
        /// <param name="privKeyIn">(Input) pointer to a 32-byte private key (cannot be NULL)</param>
        /// <returns>
        /// 1: secret was valid, public key stores
        /// 0: secret was invalid, try again
        /// </returns>
        [DllImport(LIB)]
        public static extern int secp256k1_ec_pubkey_create(IntPtr ctx, 
            void* pubKeyOut,    // secp256k1_pubkey *pubkey,
            void* privKeyIn     // const unsigned char *seckey
        );

        /// <summary>
        /// Parse a variable-length public key into the pubkey object.
        /// This function supports parsing compressed (33 bytes, header byte 0x02 or
        /// 0x03), uncompressed(65 bytes, header byte 0x04), or hybrid(65 bytes, header
        /// byte 0x06 or 0x07) format public keys.
        /// </summary>
        /// <param name="ctx">a secp256k1 context object.</param>
        /// <param name="pubkey">(Output) pointer to a pubkey object. If 1 is returned, it is set to a parsed version of input. If not, its value is undefined.</param>
        /// <param name="input">pointer to a serialized public key.</param>
        /// <param name="inputlen">length of the array pointed to by input</param>
        /// <returns>1 if the public key was fully valid, 0 if the public key could not be parsed or is invalid.</returns>
        [DllImport(LIB)]
        public static extern int secp256k1_ec_pubkey_parse(IntPtr ctx, 
            void* pubkey,   // secp256k1_pubkey* pubkey,  
            void* input,    // const unsigned char* input,
            uint inputlen   // size_t inputlen
        );

        /// <summary>
        /// Serialize a pubkey object into a serialized byte sequence.
        /// </summary>
        /// <param name="ctx">a secp256k1 context object.</param>
        /// <param name="output">a pointer to a 65-byte (if compressed==0) or 33-byte (if compressed==1) byte array to place the serialized key in.</param>
        /// <param name="outputlen">a pointer to an integer which is initially set to the size of output, and is overwritten with the written size.</param>
        /// <param name="pubkey">a pointer to a secp256k1_pubkey containing an initialized public key.</param>
        /// <param name="flags">SECP256K1_EC_COMPRESSED if serialization should be in compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.</param>
        /// <returns>1 always</returns>
        [DllImport(LIB)]
        public static extern int secp256k1_ec_pubkey_serialize(IntPtr ctx, 
            void* output,       // unsigned char* output
            ref uint outputlen, // size_t *outputlen
            void* pubkey,       // const secp256k1_pubkey* pubkey
            uint flags          // unsigned int flags
        );
    
        /// <summary>
        /// Normalizes a signature and enforces a low-S.
        /// </summary>
        /// <param name="ctx">pointer to a context object, initialized for signing (cannot be NULL)</param>
        /// <param name="sigout">(Output) pointer to an array where the normalized signature will be placed (cannot be NULL)</param>
        /// <param name="sigin">(Input) pointer to an array where a signature to normalize resides (cannot be NULL)</param>
        /// <returns>1: correct signature, 0: incorrect or unparseable signature</returns>
        [DllImport(LIB)]
        public static extern int secp256k1_ecdsa_signature_normalize(IntPtr ctx, 
            void* sigout,   // secp256k1_ecdsa_signature* sigout
            void* sigin     // const secp256k1_ecdsa_signature* sigin
        );

        /// <summary>
        /// Serialize an ECDSA signature in compact format (64 bytes + recovery id).
        /// </summary>
        /// <param name="ctx">a secp256k1 context object</param>
        /// <param name="output64">(Output) a pointer to a 64-byte array of the compact signature (cannot be NULL).</param>
        /// <param name="recid">(Output) a pointer to an integer to hold the recovery id (can be NULL).</param>
        /// <param name="sig">a pointer to an initialized signature object (cannot be NULL).</param>
        /// <returns>1 always</returns>
        [DllImport(LIB)]
        public static extern int secp256k1_ecdsa_recoverable_signature_serialize_compact(IntPtr ctx, 
            void* output64, // unsigned char* output64
            ref int recid,  // int* recid
            void* sig       // const secp256k1_ecdsa_recoverable_signature* sig
        );

        /// <summary>
        /// Recover an ECDSA public key from a signature.
        /// </summary>
        /// <param name="ctx">pointer to a context object, initialized for verification (cannot be NULL)</param>
        /// <param name="pubkey">(Output) pointer to the recovered public key (cannot be NULL)</param>
        /// <param name="sig">pointer to initialized signature that supports pubkey recovery (cannot be NULL)</param>
        /// <param name="msg32">the 32-byte message hash assumed to be signed (cannot be NULL)</param>
        /// <returns>
        /// 1: public key successfully recovered (which guarantees a correct signature).
        /// 0: otherwise.
        /// </returns>
        [DllImport(LIB)]
        public static extern int secp256k1_ecdsa_recover(IntPtr ctx, 
            void* pubkey,   // secp256k1_pubkey* pubkey
            void* sig,      // const secp256k1_ecdsa_recoverable_signature* sig
            void* msg32     // const unsigned char* msg32
        );

        /// <summary>
        /// Parse a compact ECDSA signature (64 bytes + recovery id).
        /// </summary>
        /// <param name="ctx">a secp256k1 context object</param>
        /// <param name="sig">(Output) a pointer to a signature object</param>
        /// <param name="input64">a pointer to a 64-byte compact signature</param>
        /// <param name="recid">the recovery id (0, 1, 2 or 3)</param>
        /// <returns>1 when the signature could be parsed, 0 otherwise</returns>
        [DllImport(LIB)]
        public static extern int secp256k1_ecdsa_recoverable_signature_parse_compact(IntPtr ctx, 
            void* sig,      // secp256k1_ecdsa_recoverable_signature* sig
            void* input64,  // const unsigned char* input64
            int recid       // int recid
        );


        // Flags copied from
        // https://github.com/bitcoin-core/secp256k1/blob/452d8e4d2a2f9f1b5be6b02e18f1ba102e5ca0b4/include/secp256k1.h#L157

        [Flags]
        public enum Flags : uint
        {
            /** All flags' lower 8 bits indicate what they're for. Do not use directly. */
            SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1),
            SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0),
            SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1),

            /** The higher bits contain the actual data. Do not use directly. */
            SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8),
            SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9),
            SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8),

            /** Flags to pass to secp256k1_context_create. */
            SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY),
            SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN),
            SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT),

            /** Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export. */
            SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION),
            SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)
        }


    }
}
