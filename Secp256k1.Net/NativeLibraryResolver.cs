#if NET5_0_OR_GREATER
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Secp256k1Net
{
    /// <summary>
    /// Handles native library resolution for secp256k1 using .NET's NativeLibrary API.
    /// Registers a DllImportResolver that first tries standard .NET resolution (runtimes/{rid}/native/),
    /// then falls back to LibPathResolver for backwards compatibility.
    /// </summary>
    internal static class NativeLibraryResolver
    {
        private static bool _initialized;
        private static readonly object _lock = new();

        /// <summary>
        /// Initializes the native library resolver for the Secp256k1 assembly.
        /// This should be called once before any P/Invoke calls are made.
        /// </summary>
        public static void Initialize()
        {
            if (_initialized) return;

            lock (_lock)
            {
                if (_initialized) return;

                NativeLibrary.SetDllImportResolver(typeof(NativeLibraryResolver).Assembly, ResolveLibrary);
                _initialized = true;
            }
        }

        private static IntPtr ResolveLibrary(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            // Only handle secp256k1 library
            if (libraryName != "secp256k1")
            {
                return IntPtr.Zero;
            }

            // First, try the standard .NET resolution which probes:
            // - runtimes/{rid}/native/
            // - Application directory
            // - System paths
            if (NativeLibrary.TryLoad(libraryName, assembly, searchPath, out IntPtr handle))
            {
                return handle;
            }

            // Try platform-specific library names
            string platformLibName = GetPlatformLibraryName(libraryName);
            if (platformLibName != libraryName && NativeLibrary.TryLoad(platformLibName, assembly, searchPath, out handle))
            {
                return handle;
            }

            // Fallback to LibPathResolver for backwards compatibility
            // This handles custom search paths, legacy directory structures, etc.
            try
            {
                string resolvedPath = LibPathResolver.Resolve(libraryName);
                if (NativeLibrary.TryLoad(resolvedPath, out handle))
                {
                    return handle;
                }
            }
            catch
            {
                // LibPathResolver.Resolve throws if not found, which is fine
            }

            // Return zero to let the runtime throw its standard DllNotFoundException
            return IntPtr.Zero;
        }

        /// <summary>
        /// Gets the platform-specific library name with proper prefix/extension.
        /// </summary>
        private static string GetPlatformLibraryName(string libraryName)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return libraryName + ".dll";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return "lib" + libraryName + ".dylib";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return "lib" + libraryName + ".so";
            }

            return libraryName;
        }
    }
}
#endif
