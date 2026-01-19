using System;
using System.Runtime.InteropServices;

namespace Secp256k1Net
{
    /// <summary>
    /// Type for error and illegal callback functions.
    /// </summary>
    /// <param name="message">Error message.</param>
    /// <param name="data">Callback marker, set by user together with callback.</param>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public unsafe delegate void ErrorCallbackDelegate(string message, void* data);

    public unsafe partial class Secp256k1 : IDisposable
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

        // Initialization infrastructure
        private static readonly object _initLock = new();
        private static volatile bool _initialized;
        private static IntPtr _libHandle;
        private static string _libPath;

        /// <summary>Gets the path to the loaded native library.</summary>
        public static string LibPath => _libPath ?? throw new InvalidOperationException("Library not loaded");

        internal static void EnsureInitialized()
        {
            if (_initialized) return;
            lock (_initLock)
            {
                if (_initialized) return;

                _libHandle = LoadLibNative.LoadLibrary(LIB, out var path);
                _libPath = path;

                LoadFunctions(_libHandle);
                _initialized = true;
            }
        }

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
            EnsureInitialized();
            _ctx = _context_create((uint)Secp256k1ContextFlags.None);

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

            _context_set_illegal_callback(_ctx, _errorCallbackPtr, data);
            _context_set_error_callback(_ctx, _errorCallbackPtr, data);
        }

        /// <summary>
        /// Sort an array of public keys in lexicographic order (of their compressed serialization).
        /// The input array is reordered in place.
        /// </summary>
        /// <param name="publicKeys">Array of 64-byte public keys to sort. The array will be modified in place.</param>
        /// <returns>True on success, false on failure.</returns>
        /// <exception cref="ArgumentException">Thrown when the array is null, empty, or contains invalid elements.</exception>
        public bool EcPubkeySort(byte[][] publicKeys)
        {
            if (publicKeys == null || publicKeys.Length == 0)
            {
                throw new ArgumentException($"{nameof(publicKeys)} must not be null or empty");
            }

            var count = publicKeys.Length;
            for (int i = 0; i < count; i++)
            {
                if (publicKeys[i] == null || publicKeys[i].Length < PUBKEY_LENGTH)
                {
                    throw new ArgumentException($"{nameof(publicKeys)}[{i}] must be at least {PUBKEY_LENGTH} bytes");
                }
            }

            var ptrSize = IntPtr.Size;
            var nativePtrArray = Marshal.AllocHGlobal(ptrSize * count);
            var handles = new GCHandle[count];

            try
            {
                // Pin each byte[] and store pointers in native array
                for (int i = 0; i < count; i++)
                {
                    handles[i] = GCHandle.Alloc(publicKeys[i], GCHandleType.Pinned);
                    Marshal.WriteIntPtr(nativePtrArray, i * ptrSize, handles[i].AddrOfPinnedObject());
                }

                // Call native function which sorts the pointer array in place
                var result = _ec_pubkey_sort(_ctx, nativePtrArray, (nuint)count);
                if (result != 1)
                {
                    return false;
                }

                // Read back the sorted pointers and map them to original indices
                var sortedPointers = new IntPtr[count];
                for (int i = 0; i < count; i++)
                {
                    sortedPointers[i] = Marshal.ReadIntPtr(nativePtrArray, i * ptrSize);
                }

                // Create a mapping from pointer to original index
                var pointerToIndex = new System.Collections.Generic.Dictionary<IntPtr, int>(count);
                for (int i = 0; i < count; i++)
                {
                    pointerToIndex[handles[i].AddrOfPinnedObject()] = i;
                }

                // Build the sorted array by looking up the original byte[] for each sorted pointer
                var sortedArray = new byte[count][];
                for (int i = 0; i < count; i++)
                {
                    var originalIndex = pointerToIndex[sortedPointers[i]];
                    sortedArray[i] = publicKeys[originalIndex];
                }

                // Copy back to original array
                for (int i = 0; i < count; i++)
                {
                    publicKeys[i] = sortedArray[i];
                }

                return true;
            }
            finally
            {
                // Free GCHandles
                for (int i = 0; i < count; i++)
                {
                    if (handles[i].IsAllocated)
                    {
                        handles[i].Free();
                    }
                }

                Marshal.FreeHGlobal(nativePtrArray);
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
                _context_destroy(_ctx);
                _ctx = IntPtr.Zero;
            }
        }
    }
}
