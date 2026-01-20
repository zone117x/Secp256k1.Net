using System;
using System.Runtime.InteropServices;

namespace Secp256k1Net.DynamicLinking
{
    static class DynamicLinkingLinux
    {
        public const int RTLD_NOW = 2;

        // libdl (works on most .NET Core Linux systems)
        [DllImport("libdl", EntryPoint = "dlopen")]
        private static extern IntPtr dlopen_libdl(string path, int flags);
        [DllImport("libdl", EntryPoint = "dlclose")]
        private static extern int dlclose_libdl(IntPtr handle);
        [DllImport("libdl", EntryPoint = "dlerror")]
        private static extern IntPtr dlerror_libdl();
        [DllImport("libdl", EntryPoint = "dlsym")]
        private static extern IntPtr dlsym_libdl(IntPtr handle, string name);

        // libdl.so.2 (required for Mono on some glibc systems)
        [DllImport("libdl.so.2", EntryPoint = "dlopen")]
        private static extern IntPtr dlopen_libdl2(string path, int flags);
        [DllImport("libdl.so.2", EntryPoint = "dlclose")]
        private static extern int dlclose_libdl2(IntPtr handle);
        [DllImport("libdl.so.2", EntryPoint = "dlerror")]
        private static extern IntPtr dlerror_libdl2();
        [DllImport("libdl.so.2", EntryPoint = "dlsym")]
        private static extern IntPtr dlsym_libdl2(IntPtr handle, string name);

        // libc.so.6 (fallback for glibc systems where dlopen moved to libc)
        [DllImport("libc.so.6", EntryPoint = "dlopen")]
        private static extern IntPtr dlopen_libc6(string path, int flags);
        [DllImport("libc.so.6", EntryPoint = "dlclose")]
        private static extern int dlclose_libc6(IntPtr handle);
        [DllImport("libc.so.6", EntryPoint = "dlerror")]
        private static extern IntPtr dlerror_libc6();
        [DllImport("libc.so.6", EntryPoint = "dlsym")]
        private static extern IntPtr dlsym_libc6(IntPtr handle, string name);

        // libc (musl/Alpine systems)
        [DllImport("libc", EntryPoint = "dlopen")]
        private static extern IntPtr dlopen_libc(string path, int flags);
        [DllImport("libc", EntryPoint = "dlclose")]
        private static extern int dlclose_libc(IntPtr handle);
        [DllImport("libc", EntryPoint = "dlerror")]
        private static extern IntPtr dlerror_libc();
        [DllImport("libc", EntryPoint = "dlsym")]
        private static extern IntPtr dlsym_libc(IntPtr handle, string name);

        private enum DlLibrary { Libdl, Libdl2, Libc6, Libc }
        private static readonly DlLibrary ActiveLibrary = ProbeLibrary();

        private static DlLibrary ProbeLibrary()
        {
            // Try libdl (most .NET Core systems)
            try
            {
                dlopen_libdl(null, RTLD_NOW);
                return DlLibrary.Libdl;
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }

            // Try libdl.so.2 (Mono on glibc)
            try
            {
                dlopen_libdl2(null, RTLD_NOW);
                return DlLibrary.Libdl2;
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }

            // Try libc.so.6 (newer glibc where dlopen moved to libc)
            try
            {
                dlopen_libc6(null, RTLD_NOW);
                return DlLibrary.Libc6;
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }

            // Fall back to libc (musl/Alpine)
            return DlLibrary.Libc;
        }

        public static IntPtr dlopen(string path, int flags)
        {
            switch (ActiveLibrary)
            {
                case DlLibrary.Libdl: return dlopen_libdl(path, flags);
                case DlLibrary.Libdl2: return dlopen_libdl2(path, flags);
                case DlLibrary.Libc6: return dlopen_libc6(path, flags);
                default: return dlopen_libc(path, flags);
            }
        }

        public static int dlclose(IntPtr handle)
        {
            switch (ActiveLibrary)
            {
                case DlLibrary.Libdl: return dlclose_libdl(handle);
                case DlLibrary.Libdl2: return dlclose_libdl2(handle);
                case DlLibrary.Libc6: return dlclose_libc6(handle);
                default: return dlclose_libc(handle);
            }
        }

        public static IntPtr dlerror()
        {
            switch (ActiveLibrary)
            {
                case DlLibrary.Libdl: return dlerror_libdl();
                case DlLibrary.Libdl2: return dlerror_libdl2();
                case DlLibrary.Libc6: return dlerror_libc6();
                default: return dlerror_libc();
            }
        }

        public static IntPtr dlsym(IntPtr handle, string name)
        {
            switch (ActiveLibrary)
            {
                case DlLibrary.Libdl: return dlsym_libdl(handle, name);
                case DlLibrary.Libdl2: return dlsym_libdl2(handle, name);
                case DlLibrary.Libc6: return dlsym_libc6(handle, name);
                default: return dlsym_libc(handle, name);
            }
        }
    }
}
