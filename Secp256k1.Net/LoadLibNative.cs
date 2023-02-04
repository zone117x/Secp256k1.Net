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
        static readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        static readonly bool IsMacOS = RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        static readonly bool IsLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        public static IntPtr LoadLib(string libPath)
        {
            IntPtr libPtr;

            if (IsWindows)
            {
                libPtr = DynamicLinkingWindows.LoadLibrary(libPath);
            }
            else if (IsLinux)
            {
                const int RTLD_NOW = 2;
                libPtr = DynamicLinkingLinux.dlopen(libPath, RTLD_NOW);
            }
            else if (IsMacOS)
            {
                const int RTLD_NOW = 2;
                libPtr = DynamicLinkingMacOS.dlopen(libPath, RTLD_NOW);
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
                result = DynamicLinkingWindows.FreeLibrary(lib);
                // If the function fails, the return value is zero
                result = result == 0 ? 1 : result;
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

        public static TDelegate GetDelegate<TDelegate>(IntPtr libPtr, string symbolName)
        {
            IntPtr functionPtr;
            if (IsWindows)
            {
                functionPtr = DynamicLinkingWindows.GetProcAddress(libPtr, symbolName);
            }
            else if (IsMacOS)
            {
                functionPtr = DynamicLinkingMacOS.dlsym(libPtr, symbolName);
            }
            else if (IsLinux)
            {
                functionPtr = DynamicLinkingLinux.dlsym(libPtr, symbolName);
            }
            else
            {
                throw new Exception("Unsupported platform");
            }

            if (functionPtr == IntPtr.Zero)
            {
                throw new Exception($"Library symbol failed, symbol: {symbolName}", GetLastError());
            }

            return Marshal.GetDelegateForFunctionPointer<TDelegate>(functionPtr);
        }
    }
}
