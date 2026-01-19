using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Secp256k1Net.InteropGen;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            PrintUsage();
            return 1;
        }

        var command = args[0].ToLowerInvariant();

        return command switch
        {
            "parse" => RunParse(args[1..]),
            "generate" => RunGenerate(args[1..]),
            "all" => RunAll(args[1..]),
            "-h" or "--help" or "help" => PrintUsage(),
            _ => UnknownCommand(args[0])
        };
    }

    static int PrintUsage()
    {
        Console.WriteLine("Secp256k1.Net.InteropGen - C header parser and C# interop code generator");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  InteropGen parse <include-dir> <output-json>");
        Console.WriteLine("    Parse secp256k1 header files and generate JSON API definition");
        Console.WriteLine();
        Console.WriteLine("  InteropGen generate <input-json> <output-directory>");
        Console.WriteLine("    Generate C# interop code from JSON API definition");
        Console.WriteLine();
        Console.WriteLine("  InteropGen all <include-dir> <output-directory> [--save-json <path>]");
        Console.WriteLine("    Parse headers and generate C# code in one step");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  InteropGen parse secp256k1/include api.json");
        Console.WriteLine("  InteropGen generate api.json Secp256k1.Net/Generated");
        Console.WriteLine("  InteropGen all secp256k1/include Secp256k1.Net/Generated");
        Console.WriteLine("  InteropGen all secp256k1/include Secp256k1.Net/Generated --save-json api.json");
        return 0;
    }

    static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"Unknown command: {command}");
        Console.Error.WriteLine();
        PrintUsage();
        return 1;
    }

    static int RunParse(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: InteropGen parse <include-dir> <output-json>");
            return 1;
        }

        var includeDir = args[0];
        var outputPath = args[1];

        if (!Directory.Exists(includeDir))
        {
            Console.Error.WriteLine($"Error: Include directory not found: {includeDir}");
            return 1;
        }

        try
        {
            var parser = new Secp256k1HeaderParser();
            var api = parser.ParseDirectory(includeDir);

            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            var json = JsonSerializer.Serialize(api, options);

            var outputDir = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            File.WriteAllText(outputPath, json);

            Console.WriteLine($"Generated {outputPath}");
            Console.WriteLine($"  Functions: {api.Functions.Count}");
            Console.WriteLine($"  Structs: {api.Structs.Count}");
            Console.WriteLine($"  Function pointer types: {api.FunctionPointerTypes.Count}");
            Console.WriteLine($"  Constants: {api.Constants.Count}");
            Console.WriteLine($"  Global pointers: {api.GlobalPointers.Count}");

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    static int RunGenerate(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: InteropGen generate <input-json> <output-directory>");
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
                Console.Error.WriteLine("Error: Failed to parse JSON API definition");
                return 1;
            }

            return GenerateCode(api, outputDir);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    static int RunAll(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: InteropGen all <include-dir> <output-directory> [--save-json <path>]");
            return 1;
        }

        var includeDir = args[0];
        var outputDir = args[1];
        string? jsonOutputPath = null;

        // Parse optional --save-json argument
        for (int i = 2; i < args.Length; i++)
        {
            if (args[i] == "--save-json" && i + 1 < args.Length)
            {
                jsonOutputPath = args[i + 1];
                i++;
            }
        }

        if (!Directory.Exists(includeDir))
        {
            Console.Error.WriteLine($"Error: Include directory not found: {includeDir}");
            return 1;
        }

        try
        {
            // Parse headers
            Console.WriteLine($"Parsing headers from {includeDir}...");
            var parser = new Secp256k1HeaderParser();
            var api = parser.ParseDirectory(includeDir);

            Console.WriteLine($"  Functions: {api.Functions.Count}");
            Console.WriteLine($"  Structs: {api.Structs.Count}");
            Console.WriteLine($"  Function pointer types: {api.FunctionPointerTypes.Count}");
            Console.WriteLine($"  Constants: {api.Constants.Count}");
            Console.WriteLine($"  Global pointers: {api.GlobalPointers.Count}");

            // Optionally save JSON
            if (jsonOutputPath != null)
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };

                var json = JsonSerializer.Serialize(api, options);

                var jsonDir = Path.GetDirectoryName(jsonOutputPath);
                if (!string.IsNullOrEmpty(jsonDir) && !Directory.Exists(jsonDir))
                {
                    Directory.CreateDirectory(jsonDir);
                }

                File.WriteAllText(jsonOutputPath, json);
                Console.WriteLine($"Saved JSON: {jsonOutputPath}");
            }

            // Generate C# code
            Console.WriteLine();
            return GenerateCode(api, outputDir);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    static int GenerateCode(Secp256k1Api api, string outputDir)
    {
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
}
