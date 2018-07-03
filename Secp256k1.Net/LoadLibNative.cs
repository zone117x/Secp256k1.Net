using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Secp256k1Net
{
    static class LoadLibNative
    {
        #region Windows Interop

        const string KERNEL32 = "kernel32";

        [DllImport(KERNEL32, SetLastError = true)]
        static extern IntPtr LoadLibrary(string path);

        [DllImport(KERNEL32, SetLastError = true)]
        public static extern int FreeLibrary(IntPtr module);

        [DllImport(KERNEL32, SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
        static extern IntPtr GetProcAddress(IntPtr module, string procName);

        #endregion



        #region Unix Interop

        const string LIBDL = "libdl";

        [DllImport(LIBDL)]
        static extern IntPtr dlopen(string path, int flags);

        [DllImport(LIBDL)]
        static extern int dlclose(IntPtr handle);

        [DllImport(LIBDL)]
        static extern IntPtr dlerror();

        [DllImport(LIBDL)]
        static extern IntPtr dlsym(IntPtr handle, string name);

        #endregion


        static readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        static readonly bool IsMacOS = RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        static readonly bool IsLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        public static IntPtr LoadLib(string libPath)
        {
            IntPtr libPtr;

            if (IsWindows)
            {
                libPtr = LoadLibrary(libPath);
            }
            else
            {
                const int RTLD_NOW = 0x002;
                libPtr = dlopen(libPath, RTLD_NOW);
            }

            if (libPtr == IntPtr.Zero)
            {
                throw new Exception($"Library loading failed, file: {libPath}", GetLastError());
            }

            return libPtr;
        }

        static Exception GetLastError()
        {
            if (IsWindows)
            {
                return new Win32Exception(Marshal.GetLastWin32Error());
            }
            else
            {
                var errorPtr = dlerror();
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
                functionPtr = GetProcAddress(libPtr, symbolName);
            }
            else
            {
                functionPtr = dlsym(libPtr, symbolName);
            }

            if (functionPtr == IntPtr.Zero)
            {
                throw new Exception($"Library symbol failed, symbol: {symbolName}", GetLastError());
            }

            return Marshal.GetDelegateForFunctionPointer<TDelegate>(functionPtr);
        }
    }
}
