using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Secp256k1Net
{
    static class LoadLibNative
    {
        [DllImport("Kernel32.dll")]
        static extern IntPtr LoadLibrary(string path);

        [DllImport("libdl")]
        static extern IntPtr dlopen(string path, int flags);

        /// <summary>
        /// Load a native library file using the OS-specific load function.
        /// </summary>
        /// <param name="libFilePath"></param>
        public static void LoadLib(string libFilePath)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                LoadLibrary(libFilePath);
            }
            else
            {
                const int RTLD_NOW = 0x002;
                dlopen(libFilePath, RTLD_NOW);
            }
        }
    }
}
