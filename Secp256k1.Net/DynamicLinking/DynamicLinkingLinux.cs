using System;
using System.Runtime.InteropServices;

namespace Secp256k1Net.DynamicLinking
{
    static class DynamicLinkingLinux
    {
        // Linux distros often do not link 'libdl.so' to 'libdl.so.2' by default.
        // This results in "System.DllNotFoundException: Unable to load shared library 'libdl'.."
        // when not using the shared lib version naming convention.
        // Run "ldconfig -p | grep libdl" on a fresh Ubuntu Server to see only "libdl.so.2"
        const string LIBDL = "libdl.so.2";

        [DllImport(LIBDL)]
        public static extern IntPtr dlopen(string path, int flags);

        [DllImport(LIBDL)]
        public static extern int dlclose(IntPtr handle);

        [DllImport(LIBDL)]
        public static extern IntPtr dlerror();

        [DllImport(LIBDL)]
        public static extern IntPtr dlsym(IntPtr handle, string name);
    }
}
