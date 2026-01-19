using Secp256k1Net.DynamicLinking;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Secp256k1Net
{
    internal static class LoadLibNative
    {

#if NET8_0_OR_GREATER
        /// <summary>
        /// Loads the native library using modern .NET NativeLibrary APIs.
        /// Tries standard resolution first, then falls back to LibPathResolver.
        /// </summary>
        /// <param name="libName">The library name (e.g., "secp256k1").</param>
        /// <param name="libPath">Output parameter that receives the resolved library path.</param>
        /// <returns>The handle to the loaded library.</returns>
        public static IntPtr LoadLibrary(string libName, out string libPath)
        {
            var assembly = typeof(Secp256k1).Assembly;
            // Try standard resolution first (works for RID-specific builds and NativeAOT)
            if (NativeLibrary.TryLoad(libName, assembly,
                DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.ApplicationDirectory,
                out var handle))
            {
                libPath = libName;
                return handle;
            }

            // Also try with lib prefix for Unix
            var libPrefixedName = "lib" + libName;
            if (NativeLibrary.TryLoad(libPrefixedName, assembly,
                DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.ApplicationDirectory,
                out handle))
            {
                libPath = libPrefixedName;
                return handle;
            }

            // Fallback: use LibPathResolver for comprehensive path probing
            libPath = LibPathResolver.Resolve(libName);
            return NativeLibrary.Load(libPath);
        }

        public static void CloseLibrary(IntPtr lib)
        {
            NativeLibrary.Free(lib);
        }

        public static IntPtr GetSymbolPointer(IntPtr libPtr, string symbolName)
        {
            return NativeLibrary.GetExport(libPtr, symbolName);
        }

#else

        static readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        static readonly bool IsMacOS = RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        static readonly bool IsLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        public static IntPtr LoadLibrary(string libName, out string libPath)
        {
            libPath = LibPathResolver.Resolve(libName);
            IntPtr libPtr;

            if (IsWindows)
            {
                libPtr = DynamicLinkingWindows.LoadLibrary(libPath);
            }
            else if (IsLinux)
            {
                libPtr = DynamicLinkingLinux.dlopen(libPath, DynamicLinkingLinux.RTLD_NOW);
            }
            else if (IsMacOS)
            {
                libPtr = DynamicLinkingMacOS.dlopen(libPath, DynamicLinkingMacOS.RTLD_NOW);
            }
            else
            {
                throw new Exception($"Unsupported platform: {RuntimeInformation.OSDescription}. The supported platforms are: {string.Join(", ", new[] { OSPlatform.Windows, OSPlatform.OSX, OSPlatform.Linux })}");
            }
            if (libPtr == IntPtr.Zero)
            {
                throw new Exception($"Library loading failed, file: {libPath}", GetLastError());
            }

            return libPtr;
        }

        public static void CloseLibrary(IntPtr lib)
        {
            int result;
            if (lib == IntPtr.Zero)
            {
                return;
            }
            if (IsWindows)
            {
                var freeResult = DynamicLinkingWindows.FreeLibrary(lib);
                // If the function fails, the return value is zero
                result = freeResult ? 0 : 1;
            }
            else if (IsMacOS)
            {
                result = DynamicLinkingMacOS.dlclose(lib);
            }
            else if (IsLinux)
            {
                result = DynamicLinkingLinux.dlclose(lib);
            }
            else
            {
                throw new Exception("Unsupported platform");
            }

            if (result != 0)
            {
                throw new Exception($"Library closing failed with result: {result}", GetLastError());
            }
        }

        static Exception GetLastError()
        {
            if (IsWindows)
            {
                return new Win32Exception(Marshal.GetLastWin32Error());
            }
            else
            {
                IntPtr errorPtr;
                if (IsLinux)
                {
                    errorPtr = DynamicLinkingLinux.dlerror();
                }
                else if (IsMacOS)
                {
                    errorPtr = DynamicLinkingMacOS.dlerror();
                }
                else
                {
                    throw new Exception("Unsupported platform");
                }
                if (errorPtr == IntPtr.Zero)
                {
                    return new Exception("Error information could not be found");
                }
                return new Exception(Marshal.PtrToStringAnsi(errorPtr));
            }
        }

        public static IntPtr GetSymbolPointer(IntPtr libPtr, string symbolName)
        {
            IntPtr symbolPtr;
            if (IsWindows)
            {
                symbolPtr = DynamicLinkingWindows.GetProcAddress(libPtr, symbolName);
            }
            else if (IsMacOS)
            {
                symbolPtr = DynamicLinkingMacOS.dlsym(libPtr, symbolName);
            }
            else if (IsLinux)
            {
                symbolPtr = DynamicLinkingLinux.dlsym(libPtr, symbolName);
            }
            else
            {
                throw new Exception("Unsupported platform");
            }

            if (symbolPtr == IntPtr.Zero)
            {
                throw new Exception($"Library symbol failed, symbol: {symbolName}", GetLastError());
            }

            return symbolPtr;
        }

        public static TDelegate GetDelegate<TDelegate>(IntPtr libPtr, string symbolName)
        {
            var functionPtr = GetSymbolPointer(libPtr, symbolName);
            return Marshal.GetDelegateForFunctionPointer<TDelegate>(functionPtr);
        }

        public static TDelegate GetDelegate<TDelegate>(IntPtr libPtr, string symbolName, Func<IntPtr, IntPtr> pointerDereferenceFunc)
        {
            var ptr = GetSymbolPointer(libPtr, symbolName);
            var functionPtr = pointerDereferenceFunc.Invoke(ptr);
            return Marshal.GetDelegateForFunctionPointer<TDelegate>(functionPtr);
        }
#endif
    }
}
