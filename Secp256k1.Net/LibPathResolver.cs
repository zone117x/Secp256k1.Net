using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static System.Runtime.InteropServices.OSPlatform;
using static System.Runtime.InteropServices.Architecture;
using static System.Runtime.InteropServices.RuntimeInformation;
using PlatInfo = System.ValueTuple<System.Runtime.InteropServices.OSPlatform, System.Runtime.InteropServices.Architecture>;
using System.Reflection;

namespace Secp256k1.Net
{
    public static class LibPathResolver
    {
        static readonly Dictionary<PlatInfo, (string Prefix, string LibPrefix, string Extension)> PlatformPaths = new Dictionary<PlatInfo, (string, string, string)>
        {
            [(Windows, X64)] = ("win-x64", "", ".dll"),
            [(Windows, X86)] = ("win-x86", "", ".dll"),
            [(Linux, X64)] = ("linux-x64", "lib", ".so"),
            [(OSX, X64)] = ("osx-x64", "lib", ".dylib"),
        };

        static readonly OSPlatform[] SupportedPlatforms = { Windows, OSX, Linux };
        static string SupportedPlatformDescriptions() => string.Join("\n", PlatformPaths.Keys.Select(GetPlatformDesc));

        static string GetPlatformDesc((OSPlatform OS, Architecture Arch) info) => $"{info.OS}; {info.Arch}";

        static readonly OSPlatform CurrentOSPlatform = SupportedPlatforms.FirstOrDefault(IsOSPlatform);
        static readonly PlatInfo CurrentPlatformInfo = (CurrentOSPlatform, ProcessArchitecture);
        static readonly Lazy<string> CurrentPlatformDesc = new Lazy<string>(() => GetPlatformDesc((CurrentOSPlatform, ProcessArchitecture)));

        static readonly Dictionary<PlatInfo, string> Cache = new Dictionary<PlatInfo, string>();

        public static List<string> ExtraNativeLibSearchPaths = new List<string>();

        public static string Resolve(string library)
        {
            if (Cache.TryGetValue(CurrentPlatformInfo, out string result))
            {
                return result;
            }
            if (!PlatformPaths.TryGetValue(CurrentPlatformInfo, out (string Prefix, string LibPrefix, string Extension) platform))
            {
                throw new Exception(string.Join("\n", $"Unsupported platform: {CurrentPlatformDesc.Value}", "Must be one of:", SupportedPlatformDescriptions()));
            }

            string ReturnFoundFile(string found)
            {
                Cache[CurrentPlatformInfo] = found;
                return found;
            }

            var searchedPaths = new List<string>();

            string libLocation = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

            string publishedPath = Path.Combine(libLocation, platform.LibPrefix + library) + platform.Extension;
            searchedPaths.Add(publishedPath);
            if (File.Exists(publishedPath))
            {
                return ReturnFoundFile(publishedPath);
            }

            string GetPath(string subDir = "")
            {
                return Path.Combine(libLocation, "native", platform.Prefix, subDir, platform.LibPrefix + library) + platform.Extension;
            }

            string GetRuntimesPath()
            {
                return Path.Combine(libLocation, "runtimes", platform.Prefix, "native", platform.LibPrefix + library) + platform.Extension;
            }

            string filePath = GetPath();
            searchedPaths.Add(filePath);
#if DEBUG
            string debugFilePath = GetPath("Debug");
            searchedPaths.Add(debugFilePath);
            if (File.Exists(debugFilePath))
            {
                filePath = debugFilePath;
            }
#endif

            if (File.Exists(filePath))
            {
                return ReturnFoundFile(filePath);
            }

            filePath = GetRuntimesPath();
            searchedPaths.Add(filePath);
            if (File.Exists(filePath))
            {
                return ReturnFoundFile(filePath);
            }

            libLocation = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "publish");
            filePath = GetRuntimesPath();
            searchedPaths.Add(filePath);
            if (File.Exists(filePath))
            {
                return ReturnFoundFile(filePath);
            }

            libLocation = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
            filePath = GetPath();
            searchedPaths.Add(filePath);
            if (File.Exists(filePath))
            {
                return ReturnFoundFile(filePath);
            }

            filePath = GetRuntimesPath();
            searchedPaths.Add(filePath);
            if (File.Exists(filePath))
            {
                return ReturnFoundFile(filePath);
            }

            libLocation = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "publish");
            filePath = GetRuntimesPath();
            searchedPaths.Add(filePath);
            if (File.Exists(filePath))
            {
                return ReturnFoundFile(filePath);
            }

            foreach (var extraPath in ExtraNativeLibSearchPaths)
            {
                libLocation = extraPath;
                filePath = GetPath();
                searchedPaths.Add(filePath);
                if (File.Exists(filePath))
                {
                    return ReturnFoundFile(filePath);
                }
            }

            throw new Exception($"Platform can be supported but '{library}' lib not found for {CurrentPlatformDesc.Value} at: {Environment.NewLine}{string.Join(Environment.NewLine, searchedPaths)}");

        }

    }
}
