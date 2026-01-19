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

    /// <summary>
    /// Flags for secp256k1 context creation and serialization.
    /// </summary>
    [Flags]
    public enum Flags : uint
    {
        /// <summary>All flags' lower 8 bits indicate what they're for. Do not use directly.</summary>
        SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1),
        /// <summary>Context flag type.</summary>
        SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0),
        /// <summary>Compression flag type.</summary>
        SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1),

        /// <summary>The higher bits contain the actual data. Do not use directly.</summary>
        SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8),
        /// <summary>Context sign bit.</summary>
        SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9),
        /// <summary>Compression bit.</summary>
        SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8),

        /// <summary>Flag to pass to secp256k1_context_create. Creates a context sufficient for all functionality.</summary>
        SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT),

        /// <summary>Flag to pass to secp256k1_ec_pubkey_serialize for compressed format.</summary>
        SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION),
        /// <summary>Flag to pass to secp256k1_ec_pubkey_serialize for uncompressed format.</summary>
        SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)
    }

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
            _ctx = _context_create((uint)Flags.SECP256K1_CONTEXT_NONE);

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

            secp256k1_ecdh_hash_function hashFunctionPtr = (void* output, void* x, void* y, void* d) =>
            {
                var outputSpan = new Span<byte>(output, outputLength);
                var xSpan = new Span<byte>(x, 32);
                var ySpan = new Span<byte>(y, 32);
                return hashFunction(outputSpan, xSpan, ySpan, (IntPtr)d);
            };

            var hashFuncPtr = Marshal.GetFunctionPointerForDelegate(hashFunctionPtr);

            fixed (byte* resPtr = &MemoryMarshal.GetReference(resultOutput),
                pubPtr = &MemoryMarshal.GetReference(publicKey),
                privPtr = &MemoryMarshal.GetReference(privateKey))
            {
                return _ecdh(_ctx, resPtr, pubPtr, privPtr, hashFuncPtr, data.ToPointer()) == 1;
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
                return _nonce_function_rfc6979(nonceOutPtr, hashPtr, secPtr, algoPtr, dataPtr, attempt) == 1;
            }
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
