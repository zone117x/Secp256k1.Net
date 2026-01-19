using System;
using System.IO;
using System.Text.Json;

namespace Secp256k1Net.InteropGen;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: Secp256k1.Net.InteropGen <input-json> <output-directory>");
            Console.Error.WriteLine("  <input-json>       Path to secp256k1-api.json");
            Console.Error.WriteLine("  <output-directory> Directory to write generated files");
            return 1;
        }

        var inputPath = args[0];
        var outputDir = args[1];

        if (!File.Exists(inputPath))
        {
            Console.Error.WriteLine($"Error: Input file not found: {inputPath}");
            return 1;
        }

        try
        {
            var jsonContent = File.ReadAllText(inputPath);
            var api = JsonSerializer.Deserialize<Secp256k1Api>(jsonContent, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (api == null)
            {
                Console.Error.WriteLine("Error: Failed to parse secp256k1-api.json");
                return 1;
            }

            Directory.CreateDirectory(outputDir);

            var generator = new InteropGenerator();

            // Generate native interop code
            var nativeSource = generator.GenerateNative(api);
            var nativePath = Path.Combine(outputDir, "Secp256k1.Native.g.cs");
            File.WriteAllText(nativePath, nativeSource);
            Console.WriteLine($"Generated: {nativePath}");

            // Generate safe wrapper methods
            var wrappersSource = generator.GenerateWrappers(api);
            var wrappersPath = Path.Combine(outputDir, "Secp256k1.Wrappers.g.cs");
            File.WriteAllText(wrappersPath, wrappersSource);
            Console.WriteLine($"Generated: {wrappersPath}");

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }
}
