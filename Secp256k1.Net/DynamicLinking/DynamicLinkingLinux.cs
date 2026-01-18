using System;
using System.Runtime.InteropServices;

namespace Secp256k1Net.DynamicLinking
{
    static class DynamicLinkingLinux
    {
        public const int RTLD_NOW = 2;

        // Try libdl first (glibc systems), fall back to libc (musl/Alpine)
        [DllImport("libdl", EntryPoint = "dlopen")]
        private static extern IntPtr dlopen_libdl(string path, int flags);
        [DllImport("libdl", EntryPoint = "dlclose")]
        private static extern int dlclose_libdl(IntPtr handle);
        [DllImport("libdl", EntryPoint = "dlerror")]
        private static extern IntPtr dlerror_libdl();
        [DllImport("libdl", EntryPoint = "dlsym")]
        private static extern IntPtr dlsym_libdl(IntPtr handle, string name);

        // On musl-based systems (Alpine), dlopen is in libc
        [DllImport("libc", EntryPoint = "dlopen")]
        private static extern IntPtr dlopen_libc(string path, int flags);
        [DllImport("libc", EntryPoint = "dlclose")]
        private static extern int dlclose_libc(IntPtr handle);
        [DllImport("libc", EntryPoint = "dlerror")]
        private static extern IntPtr dlerror_libc();
        [DllImport("libc", EntryPoint = "dlsym")]
        private static extern IntPtr dlsym_libc(IntPtr handle, string name);

        private static readonly bool UseLibdl = ProbeLibdl();

        private static bool ProbeLibdl()
        {
            try
            {
                dlopen_libdl(null, RTLD_NOW);
                return true;
            }
            catch (DllNotFoundException)
            {
                return false;
            }
        }

        public static IntPtr dlopen(string path, int flags) =>
            UseLibdl ? dlopen_libdl(path, flags) : dlopen_libc(path, flags);

        public static int dlclose(IntPtr handle) =>
            UseLibdl ? dlclose_libdl(handle) : dlclose_libc(handle);

        public static IntPtr dlerror() =>
            UseLibdl ? dlerror_libdl() : dlerror_libc();

        public static IntPtr dlsym(IntPtr handle, string name) =>
            UseLibdl ? dlsym_libdl(handle, name) : dlsym_libc(handle, name);
    }
}
