using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static System.Runtime.InteropServices.OSPlatform;
using static System.Runtime.InteropServices.Architecture;
using static System.Runtime.InteropServices.RuntimeInformation;
using PlatInfo = System.ValueTuple<System.Runtime.InteropServices.OSPlatform, System.Runtime.InteropServices.Architecture>;
using System.Reflection;
using System.Collections.Concurrent;

namespace Secp256k1Net
{
    public static class LibPathResolver
    {

        static readonly Dictionary<PlatInfo, (string Prefix, string LibPrefix, string Extension)> PlatformPaths = new Dictionary<PlatInfo, (string, string, string)>
        {
            [(Windows, X64)] = ("win-x64", "", ".dll"),
            [(Windows, X86)] = ("win-x86", "", ".dll"),
            [(Windows, Arm64)] = ("win-arm64", "", ".dll"),
            [(Linux, X64)] = ("linux-x64", "lib", ".so"),
            [(Linux, X86)] = ("linux-x86", "lib", ".so"),
            [(Linux, Arm64)] = ("linux-arm64", "lib", ".so"),
            [(OSX, X64)] = ("osx-x64", "lib", ".dylib"),
            [(OSX, Arm64)] = ("osx-arm64", "lib", ".dylib"),
        };

        // Musl (Alpine) variants - checked first on musl systems
        static readonly Dictionary<PlatInfo, (string Prefix, string LibPrefix, string Extension)> MuslPlatformPaths = new Dictionary<PlatInfo, (string, string, string)>
        {
            [(Linux, X64)] = ("linux-musl-x64", "lib", ".so"),
            [(Linux, Arm64)] = ("linux-musl-arm64", "lib", ".so"),
        };

        static readonly Lazy<bool> IsMuslLinux = new Lazy<bool>(() =>
        {
            if (!IsOSPlatform(Linux))
                return false;
            try
            {
                // Alpine Linux has this file
                return File.Exists("/etc/alpine-release");
            }
            catch
            {
                return false;
            }
        });

        static readonly OSPlatform[] SupportedPlatforms = { Windows, OSX, Linux };
        static string SupportedPlatformDescriptions() => string.Join("\n", PlatformPaths.Keys.Select(GetPlatformDesc));

        static string GetPlatformDesc((OSPlatform OS, Architecture Arch) info) => $"{info.OS}; {info.Arch}";

        static readonly OSPlatform CurrentOSPlatform = SupportedPlatforms.FirstOrDefault(IsOSPlatform);
        static readonly PlatInfo CurrentPlatformInfo = (CurrentOSPlatform, ProcessArchitecture);
        static readonly Lazy<string> CurrentPlatformDesc = new Lazy<string>(() => GetPlatformDesc((CurrentOSPlatform, ProcessArchitecture)));

        static readonly ConcurrentDictionary<string, string> Cache = new ConcurrentDictionary<string, string>();

        public static List<string> ExtraNativeLibSearchPaths = new List<string>();

        public static string Resolve(string library)
        {
            if (Cache.TryGetValue(library, out string result))
            {
                return result;
            }
            if (!PlatformPaths.TryGetValue(CurrentPlatformInfo, out (string Prefix, string LibPrefix, string Extension) platform))
            {
                throw new Exception(string.Join("\n", $"Unsupported platform: {CurrentPlatformDesc.Value}", "Must be one of:", SupportedPlatformDescriptions()));
            }

            var searchedPaths = new HashSet<string>();

            // On musl Linux (Alpine), try musl-specific paths first, then fall back to glibc paths
            var platformsToTry = new List<(string Prefix, string LibPrefix, string Extension)>();
            if (IsMuslLinux.Value && MuslPlatformPaths.TryGetValue(CurrentPlatformInfo, out var muslPlatform))
            {
                platformsToTry.Add(muslPlatform);
            }
            platformsToTry.Add(platform);

            foreach (var containerDir in GetSearchLocations())
            {
                foreach (var platformToTry in platformsToTry)
                {
                    foreach (var libPath in SearchContainerPaths(containerDir, library, platformToTry))
                    {
                        if (!searchedPaths.Contains(libPath) && File.Exists(libPath))
                        {
                            Cache.TryAdd(library, libPath);
                            return libPath;
                        }
                        searchedPaths.Add(libPath);
                    }
                }
            }

            throw new Exception($"Platform can be supported but '{library}' lib not found for {CurrentPlatformDesc.Value} at: {Environment.NewLine}{string.Join(Environment.NewLine, searchedPaths)}");

        }

#if NET8_0_OR_GREATER
        [UnconditionalSuppressMessage("SingleFile", "IL3000:Assembly.Location returns empty in single-file apps",
            Justification = "AppContext.BaseDirectory is checked first; Assembly.Location is a fallback for non-single-file scenarios")]
#endif
        static IEnumerable<string> GetSearchLocations()
        {
            // AppContext.BaseDirectory is the recommended way to get the app directory,
            // especially for single-file apps where Assembly.Location returns empty.
            if (!string.IsNullOrEmpty(AppContext.BaseDirectory))
            {
                yield return AppContext.BaseDirectory;
            }

#pragma warning disable IL3000 // Assembly.Location returns empty in single-file apps (handled by AppContext.BaseDirectory above)
            string execPath = Assembly.GetExecutingAssembly()?.Location;
            if (!string.IsNullOrEmpty(execPath))
            {
                yield return Path.GetDirectoryName(execPath);
            }

            string callingPath = Assembly.GetCallingAssembly()?.Location;
            if (!string.IsNullOrEmpty(callingPath))
            {
                yield return Path.GetDirectoryName(callingPath);
            }

            var entryAssemblyPath = Assembly.GetEntryAssembly()?.Location;
            if (!string.IsNullOrEmpty(entryAssemblyPath))
            {
                yield return Path.GetDirectoryName(entryAssemblyPath);
            }
#pragma warning restore IL3000

            foreach (string extraPath in ExtraNativeLibSearchPaths)
            {
                yield return extraPath;
            }

            if (!string.IsNullOrEmpty(execPath))
            {
                // If the this lib is being executed from its nuget package directory then the native
                // files should be found up a couple directories.
                yield return Path.GetFullPath(Path.Combine(execPath, "../../content"));
            }
        }

        static IEnumerable<string> SearchContainerPaths(string containerDir, string library, (string Prefix, string LibPrefix, string Extension) platform)
        {
            foreach (var subDir in GetSearchSubDir(library, platform))
            {
                yield return Path.Combine(containerDir, subDir);
                yield return Path.Combine(containerDir, "publish", subDir);
            }
        }

        static IEnumerable<string> GetSearchSubDir(string library, (string Prefix, string LibPrefix, string Extension) platform)
        {
            string libFileName = platform.LibPrefix + library + platform.Extension;

            yield return libFileName;
            yield return Path.Combine(platform.Prefix, libFileName);
            yield return Path.Combine("native", platform.Prefix, libFileName);
            yield return Path.Combine("runtimes", platform.Prefix, "native", libFileName);

        }

    }
}
