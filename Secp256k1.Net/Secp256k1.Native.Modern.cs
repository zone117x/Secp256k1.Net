#if NET8_0_OR_GREATER
using System;
using System.Runtime.InteropServices;

namespace Secp256k1Net
{
    public unsafe partial class Secp256k1
    {
        private static readonly object _initLock = new();
        private static volatile bool _initialized;
        private static IntPtr _libHandle;
        private static string _libPath;

        // Function pointer declarations
        private static delegate* unmanaged[Cdecl]<uint, IntPtr> _context_create;
        private static delegate* unmanaged[Cdecl]<IntPtr, void> _context_destroy;
        private static delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void*, void> _context_set_illegal_callback;
        private static delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void*, void> _context_set_error_callback;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int> _ec_pubkey_create;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, int> _ec_seckey_verify;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, nuint*, void*, uint, int> _ec_pubkey_serialize;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, uint, int> _ec_pubkey_parse;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, IntPtr, IntPtr, int> _ecdsa_sign_recoverable;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, IntPtr, void*, int> _ecdsa_sign;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int, int> _ecdsa_recoverable_signature_parse_compact;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, int*, void*, int> _ecdsa_recoverable_signature_serialize_compact;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, int> _ecdsa_recover;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int> _ecdsa_signature_normalize;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, uint, int> _ecdsa_signature_parse_der;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int> _ecdsa_signature_parse_compact;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, nuint*, void*, int> _ecdsa_signature_serialize_der;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int> _ecdsa_signature_serialize_compact;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, int> _ecdsa_verify;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, IntPtr, IntPtr, int> _ecdh;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int> _ec_pubkey_tweak_mul;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, int> _ec_pubkey_negate;
        private static delegate* unmanaged[Cdecl]<IntPtr, void*, IntPtr, uint, int> _ec_pubkey_combine;
        private static delegate* unmanaged[Cdecl]<void*, void*, void*, void*, void*, uint, int> _nonce_function_rfc6979;

        public static string LibPath => _libPath ?? throw new InvalidOperationException("Library not loaded");

        private static void EnsureInitialized()
        {
            if (_initialized) return;
            lock (_initLock)
            {
                if (_initialized) return;
                _libHandle = LoadLibrary();
                LoadFunctions(_libHandle);
                _initialized = true;
            }
        }

        private static IntPtr LoadLibrary()
        {
            // Try standard resolution first (works for RID-specific builds and NativeAOT)
            if (NativeLibrary.TryLoad("secp256k1", typeof(Secp256k1).Assembly,
                DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.ApplicationDirectory,
                out var handle))
            {
                _libPath = "secp256k1";
                return handle;
            }

            // Also try with lib prefix for Unix
            if (NativeLibrary.TryLoad("libsecp256k1", typeof(Secp256k1).Assembly,
                DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.ApplicationDirectory,
                out handle))
            {
                _libPath = "libsecp256k1";
                return handle;
            }

            // Fallback: use LibPathResolver for comprehensive path probing
            _libPath = LibPathResolver.Resolve(LIB);
            return NativeLibrary.Load(_libPath);
        }

        private static void LoadFunctions(IntPtr lib)
        {
            _context_create = (delegate* unmanaged[Cdecl]<uint, IntPtr>)
                NativeLibrary.GetExport(lib, SYM_context_create);
            _context_destroy = (delegate* unmanaged[Cdecl]<IntPtr, void>)
                NativeLibrary.GetExport(lib, SYM_context_destroy);
            _context_set_illegal_callback = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void*, void>)
                NativeLibrary.GetExport(lib, SYM_context_set_illegal_callback);
            _context_set_error_callback = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void*, void>)
                NativeLibrary.GetExport(lib, SYM_context_set_error_callback);
            _ec_pubkey_create = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ec_pubkey_create);
            _ec_seckey_verify = (delegate* unmanaged[Cdecl]<IntPtr, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ec_seckey_verify);
            _ec_pubkey_serialize = (delegate* unmanaged[Cdecl]<IntPtr, void*, nuint*, void*, uint, int>)
                NativeLibrary.GetExport(lib, SYM_ec_pubkey_serialize);
            _ec_pubkey_parse = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, uint, int>)
                NativeLibrary.GetExport(lib, SYM_ec_pubkey_parse);
            _ecdsa_sign_recoverable = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, IntPtr, IntPtr, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_sign_recoverable);
            _ecdsa_sign = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, IntPtr, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_sign);
            _ecdsa_recoverable_signature_parse_compact = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_recoverable_signature_parse_compact);
            _ecdsa_recoverable_signature_serialize_compact = (delegate* unmanaged[Cdecl]<IntPtr, void*, int*, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_recoverable_signature_serialize_compact);
            _ecdsa_recover = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_recover);
            _ecdsa_signature_normalize = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_signature_normalize);
            _ecdsa_signature_parse_der = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, uint, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_signature_parse_der);
            _ecdsa_signature_parse_compact = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_signature_parse_compact);
            _ecdsa_signature_serialize_der = (delegate* unmanaged[Cdecl]<IntPtr, void*, nuint*, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_signature_serialize_der);
            _ecdsa_signature_serialize_compact = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_signature_serialize_compact);
            _ecdsa_verify = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ecdsa_verify);
            _ecdh = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, void*, IntPtr, IntPtr, int>)
                NativeLibrary.GetExport(lib, SYM_ecdh);
            _ec_pubkey_tweak_mul = (delegate* unmanaged[Cdecl]<IntPtr, void*, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ec_pubkey_tweak_mul);
            _ec_pubkey_negate = (delegate* unmanaged[Cdecl]<IntPtr, void*, int>)
                NativeLibrary.GetExport(lib, SYM_ec_pubkey_negate);
            _ec_pubkey_combine = (delegate* unmanaged[Cdecl]<IntPtr, void*, IntPtr, uint, int>)
                NativeLibrary.GetExport(lib, SYM_ec_pubkey_combine);

            // secp256k1_nonce_function_rfc6979 is a data symbol (function pointer), not a function
            var noncePtr = NativeLibrary.GetExport(lib, SYM_nonce_function_rfc6979);
            _nonce_function_rfc6979 = (delegate* unmanaged[Cdecl]<void*, void*, void*, void*, void*, uint, int>)
                Marshal.ReadIntPtr(noncePtr);
        }

    }
}
#endif
