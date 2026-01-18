#if !NET8_0_OR_GREATER
using System;
using System.Runtime.InteropServices;

namespace Secp256k1Net
{
    public unsafe partial class Secp256k1
    {
        private static readonly object _initLock = new object();
        private static volatile bool _initialized;
        private static IntPtr _libHandle;
        private static string _libPath;

        // Delegate declarations
        private static secp256k1_context_create _context_create;
        private static secp256k1_context_destroy _context_destroy;
        private static secp256k1_context_set_illegal_callback _context_set_illegal_callback;
        private static secp256k1_context_set_error_callback _context_set_error_callback;
        private static secp256k1_ec_pubkey_create _ec_pubkey_create;
        private static secp256k1_ec_seckey_verify _ec_seckey_verify;
        private static secp256k1_ec_pubkey_serialize _ec_pubkey_serialize;
        private static secp256k1_ec_pubkey_parse _ec_pubkey_parse;
        private static secp256k1_ecdsa_sign_recoverable _ecdsa_sign_recoverable;
        private static secp256k1_ecdsa_sign _ecdsa_sign;
        private static secp256k1_ecdsa_recoverable_signature_parse_compact _ecdsa_recoverable_signature_parse_compact;
        private static secp256k1_ecdsa_recoverable_signature_serialize_compact _ecdsa_recoverable_signature_serialize_compact;
        private static secp256k1_ecdsa_recover _ecdsa_recover;
        private static secp256k1_ecdsa_signature_normalize _ecdsa_signature_normalize;
        private static secp256k1_ecdsa_signature_parse_der _ecdsa_signature_parse_der;
        private static secp256k1_ecdsa_signature_parse_compact _ecdsa_signature_parse_compact;
        private static secp256k1_ecdsa_signature_serialize_der _ecdsa_signature_serialize_der;
        private static secp256k1_ecdsa_signature_serialize_compact _ecdsa_signature_serialize_compact;
        private static secp256k1_ecdsa_verify _ecdsa_verify;
        private static secp256k1_ecdh _ecdh;
        private static secp256k1_ec_pubkey_tweak_mul _ec_pubkey_tweak_mul;
        private static secp256k1_ec_pubkey_negate _ec_pubkey_negate;
        private static secp256k1_ec_pubkey_combine _ec_pubkey_combine;
        private static secp256k1_nonce_function _nonce_function_rfc6979;

        public static string LibPath => _libPath ?? throw new InvalidOperationException("Library not loaded");

        private static void EnsureInitialized()
        {
            if (_initialized) return;
            lock (_initLock)
            {
                if (_initialized) return;
                _libPath = LibPathResolver.Resolve(LIB);
                _libHandle = LoadLibNative.LoadLib(_libPath);
                LoadFunctions(_libHandle);
                _initialized = true;
            }
        }

        private static void LoadFunctions(IntPtr lib)
        {
            _context_create = LoadLibNative.GetDelegate<secp256k1_context_create>(lib, SYM_context_create);
            _context_destroy = LoadLibNative.GetDelegate<secp256k1_context_destroy>(lib, SYM_context_destroy);
            _context_set_illegal_callback = LoadLibNative.GetDelegate<secp256k1_context_set_illegal_callback>(lib, SYM_context_set_illegal_callback);
            _context_set_error_callback = LoadLibNative.GetDelegate<secp256k1_context_set_error_callback>(lib, SYM_context_set_error_callback);
            _ec_pubkey_create = LoadLibNative.GetDelegate<secp256k1_ec_pubkey_create>(lib, SYM_ec_pubkey_create);
            _ec_seckey_verify = LoadLibNative.GetDelegate<secp256k1_ec_seckey_verify>(lib, SYM_ec_seckey_verify);
            _ec_pubkey_serialize = LoadLibNative.GetDelegate<secp256k1_ec_pubkey_serialize>(lib, SYM_ec_pubkey_serialize);
            _ec_pubkey_parse = LoadLibNative.GetDelegate<secp256k1_ec_pubkey_parse>(lib, SYM_ec_pubkey_parse);
            _ecdsa_sign_recoverable = LoadLibNative.GetDelegate<secp256k1_ecdsa_sign_recoverable>(lib, SYM_ecdsa_sign_recoverable);
            _ecdsa_sign = LoadLibNative.GetDelegate<secp256k1_ecdsa_sign>(lib, SYM_ecdsa_sign);
            _ecdsa_recoverable_signature_parse_compact = LoadLibNative.GetDelegate<secp256k1_ecdsa_recoverable_signature_parse_compact>(lib, SYM_ecdsa_recoverable_signature_parse_compact);
            _ecdsa_recoverable_signature_serialize_compact = LoadLibNative.GetDelegate<secp256k1_ecdsa_recoverable_signature_serialize_compact>(lib, SYM_ecdsa_recoverable_signature_serialize_compact);
            _ecdsa_recover = LoadLibNative.GetDelegate<secp256k1_ecdsa_recover>(lib, SYM_ecdsa_recover);
            _ecdsa_signature_normalize = LoadLibNative.GetDelegate<secp256k1_ecdsa_signature_normalize>(lib, SYM_ecdsa_signature_normalize);
            _ecdsa_signature_parse_der = LoadLibNative.GetDelegate<secp256k1_ecdsa_signature_parse_der>(lib, SYM_ecdsa_signature_parse_der);
            _ecdsa_signature_parse_compact = LoadLibNative.GetDelegate<secp256k1_ecdsa_signature_parse_compact>(lib, SYM_ecdsa_signature_parse_compact);
            _ecdsa_signature_serialize_der = LoadLibNative.GetDelegate<secp256k1_ecdsa_signature_serialize_der>(lib, SYM_ecdsa_signature_serialize_der);
            _ecdsa_signature_serialize_compact = LoadLibNative.GetDelegate<secp256k1_ecdsa_signature_serialize_compact>(lib, SYM_ecdsa_signature_serialize_compact);
            _ecdsa_verify = LoadLibNative.GetDelegate<secp256k1_ecdsa_verify>(lib, SYM_ecdsa_verify);
            _ecdh = LoadLibNative.GetDelegate<secp256k1_ecdh>(lib, SYM_ecdh);
            _ec_pubkey_tweak_mul = LoadLibNative.GetDelegate<secp256k1_ec_pubkey_tweak_mul>(lib, SYM_ec_pubkey_tweak_mul);
            _ec_pubkey_negate = LoadLibNative.GetDelegate<secp256k1_ec_pubkey_negate>(lib, SYM_ec_pubkey_negate);
            _ec_pubkey_combine = LoadLibNative.GetDelegate<secp256k1_ec_pubkey_combine>(lib, SYM_ec_pubkey_combine);

            // secp256k1_nonce_function_rfc6979 is a data symbol (function pointer), not a function
            _nonce_function_rfc6979 = LoadLibNative.GetDelegate<secp256k1_nonce_function>(lib, SYM_nonce_function_rfc6979, Marshal.ReadIntPtr);
        }
    }
}
#endif
