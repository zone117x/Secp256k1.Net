using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Secp256k1Net.InteropGen;

public partial class Secp256k1HeaderParser
{
    private readonly List<string> _headerOrder = new()
    {
        "secp256k1.h",
        "secp256k1_preallocated.h",
        "secp256k1_recovery.h",
        "secp256k1_ecdh.h",
        "secp256k1_extrakeys.h",
        "secp256k1_schnorrsig.h",
        "secp256k1_ellswift.h",
        "secp256k1_musig.h"
    };

    public Secp256k1Api ParseDirectory(string includeDir)
    {
        var api = new Secp256k1Api();

        foreach (var headerName in _headerOrder)
        {
            var headerPath = Path.Combine(includeDir, headerName);
            if (File.Exists(headerPath))
            {
                api.Headers.Add(headerName);
                ParseHeader(headerPath, headerName, api);
            }
        }

        return api;
    }

    private void ParseHeader(string headerPath, string headerName, Secp256k1Api api)
    {
        var content = File.ReadAllText(headerPath);

        // Normalize line endings and remove escaped newlines for multi-line declarations
        content = content.Replace("\r\n", "\n");

        ParseStructs(content, api);
        ParseFunctionPointerTypes(content, api);
        ParseFunctions(content, headerName, api);
        ParseConstants(content, api);
        ParseGlobalPointers(content, api);
    }

    private void ParseStructs(string content, Secp256k1Api api)
    {
        // Match typedef struct with data array: typedef struct secp256k1_pubkey { unsigned char data[64]; } secp256k1_pubkey;
        var structRegex = StructRegex();

        foreach (Match match in structRegex.Matches(content))
        {
            var name = match.Groups[1].Value;
            var size = int.Parse(match.Groups[2].Value);

            // Don't add duplicates
            if (api.Structs.Any(s => s.Name == name))
                continue;

            // Get preceding comment
            var description = GetPrecedingComment(content, match.Index);

            api.Structs.Add(new StructDef
            {
                Name = name,
                Size = size,
                Description = description
            });
        }

        // Also match opaque context struct: typedef struct secp256k1_context_struct secp256k1_context;
        var opaqueRegex = OpaqueStructRegex();
        foreach (Match match in opaqueRegex.Matches(content))
        {
            var name = match.Groups[1].Value;

            if (api.Structs.Any(s => s.Name == name))
                continue;

            var description = GetPrecedingComment(content, match.Index);

            api.Structs.Add(new StructDef
            {
                Name = name,
                Size = 0, // Opaque, size unknown
                Description = description
            });
        }
    }

    private void ParseFunctionPointerTypes(string content, Secp256k1Api api)
    {
        // Match typedef int (*name)(...);
        var funcPtrRegex = FuncPtrTypeRegex();

        foreach (Match match in funcPtrRegex.Matches(content))
        {
            var returnType = match.Groups[1].Value.Trim();
            var name = match.Groups[2].Value;
            var paramsStr = match.Groups[3].Value;

            if (api.FunctionPointerTypes.Any(f => f.Name == name))
                continue;

            var description = GetPrecedingComment(content, match.Index);
            var parameters = ParseParameters(paramsStr, description);

            api.FunctionPointerTypes.Add(new FunctionPointerType
            {
                Name = name,
                ReturnType = returnType,
                Parameters = parameters,
                Description = CleanDescription(description)
            });
        }
    }

    private void ParseFunctions(string content, string headerName, Secp256k1Api api)
    {
        // First, collapse multi-line function declarations
        var collapsedContent = CollapseMultilineDeclarations(content);

        // Match SECP256K1_API functions - use a two-step approach for nested parens
        var funcStartRegex = FunctionStartRegex();

        foreach (Match match in funcStartRegex.Matches(collapsedContent))
        {
            var returnType = match.Groups[1].Value.Trim();
            var name = match.Groups[2].Value;

            if (api.Functions.Any(f => f.Name == name))
                continue;

            // Skip invalid function names (macros, keywords, etc.)
            if (!name.StartsWith("secp256k1_"))
                continue;

            // Extract parameters by finding balanced parentheses
            var startPos = match.Index + match.Length; // Position after the opening '('
            var (paramsStr, endPos) = ExtractBalancedParens(collapsedContent, startPos - 1);

            if (string.IsNullOrEmpty(paramsStr))
                continue;

            // Get attributes after the closing paren
            var afterParams = collapsedContent.Substring(endPos);
            var semiPos = afterParams.IndexOf(';');
            var attributes = semiPos >= 0 ? afterParams.Substring(0, semiPos) : "";

            var fullDeclaration = collapsedContent.Substring(match.Index, endPos - match.Index + Math.Min(200, collapsedContent.Length - endPos));
            var warnUnused = fullDeclaration.Contains("SECP256K1_WARN_UNUSED_RESULT") ||
                             match.Value.Contains("SECP256K1_WARN_UNUSED_RESULT");

            // Check for SECP256K1_DEPRECATED macro
            var deprecated = attributes.Contains("SECP256K1_DEPRECATED");
            string? deprecatedMessage = null;
            if (deprecated)
            {
                var deprecatedMatch = DeprecatedRegex().Match(attributes);
                if (deprecatedMatch.Success)
                {
                    deprecatedMessage = deprecatedMatch.Groups[1].Value;
                }
            }

            // Extract NONNULL argument positions
            var nonnullArgs = new HashSet<int>();
            var nonnullRegex = NonnullRegex();
            foreach (Match nnMatch in nonnullRegex.Matches(attributes))
            {
                nonnullArgs.Add(int.Parse(nnMatch.Groups[1].Value));
            }

            // Get description from original content (need to find position)
            var originalPos = content.IndexOf(name + "(", StringComparison.Ordinal);
            if (originalPos < 0)
                originalPos = content.IndexOf(name + " (", StringComparison.Ordinal);

            var description = originalPos >= 0 ? GetPrecedingComment(content, originalPos) : null;

            // Also check if description explicitly marks this function as deprecated
            // Look for patterns like "DEPRECATED." or "but DEPRECATED" at function level
            // Avoid false positives from mentions of deprecated flags/parameters
            if (!deprecated && description != null)
            {
                // Check for explicit deprecation markers in function description
                // e.g., "Same as secp256k1_schnorrsig_sign32, but DEPRECATED."
                if (description.Contains("but DEPRECATED") ||
                    description.Contains("DEPRECATED.") ||
                    description.Contains("This function is deprecated"))
                {
                    deprecated = true;
                }
            }

            var returnDesc = ExtractReturnDescription(description);
            var parameters = ParseParameters(paramsStr, description);

            // Apply nonnull annotations
            for (int i = 0; i < parameters.Count; i++)
            {
                parameters[i].Nonnull = nonnullArgs.Contains(i + 1);
            }

            api.Functions.Add(new FunctionDef
            {
                Name = name,
                ReturnType = returnType,
                WarnUnusedResult = warnUnused,
                Deprecated = deprecated,
                DeprecatedMessage = deprecatedMessage,
                Parameters = parameters,
                Description = CleanDescription(description),
                ReturnDescription = returnDesc,
                SourceHeader = headerName
            });
        }
    }

    private (string content, int endPos) ExtractBalancedParens(string text, int startPos)
    {
        if (startPos >= text.Length || text[startPos] != '(')
            return ("", startPos);

        var depth = 1;
        var pos = startPos + 1;

        while (pos < text.Length && depth > 0)
        {
            if (text[pos] == '(') depth++;
            else if (text[pos] == ')') depth--;
            pos++;
        }

        if (depth != 0)
            return ("", pos);

        // Return content between parens (excluding the parens themselves)
        return (text.Substring(startPos + 1, pos - startPos - 2), pos);
    }

    private void ParseConstants(string content, Secp256k1Api api)
    {
        // Match #define SECP256K1_* constants
        var constRegex = ConstantRegex();

        foreach (Match match in constRegex.Matches(content))
        {
            var name = "SECP256K1_" + match.Groups[1].Value;
            var value = match.Groups[2].Value.Trim();

            if (api.Constants.Any(c => c.Name == name))
                continue;

            // Skip internal macros
            if (name.Contains("GNUC") || name.Contains("API") || name.Contains("BUILD") ||
                name.Contains("DEPRECATED") || name.Contains("WARN") || name.Contains("NONNULL") ||
                name.EndsWith("_H") || name.Contains("STATIC"))
                continue;

            // Get preceding comment (look for /** comment on previous line)
            var description = GetPrecedingComment(content, match.Index);

            // Try to evaluate numeric value
            long? numericValue = TryEvaluateConstant(value, api.Constants);

            api.Constants.Add(new ConstantDef
            {
                Name = name,
                Value = value,
                NumericValue = numericValue,
                Description = description
            });
        }
    }

    private void ParseGlobalPointers(string content, Secp256k1Api api)
    {
        // Match SECP256K1_API const type * const name; (global pointers)
        var globalRegex = GlobalPointerRegex();

        foreach (Match match in globalRegex.Matches(content))
        {
            var type = match.Groups[1].Value.Trim();
            var name = match.Groups[2].Value;

            if (api.GlobalPointers.Any(g => g.Name == name))
                continue;

            var description = GetPrecedingComment(content, match.Index);

            api.GlobalPointers.Add(new GlobalPointer
            {
                Name = name,
                Type = type,
                IsConst = true,
                Description = CleanDescription(description)
            });
        }

        // Match extern SECP256K1_API const type name; (function pointer constants like nonce_function_rfc6979)
        var externRegex = ExternGlobalRegex();

        foreach (Match match in externRegex.Matches(content))
        {
            var type = match.Groups[1].Value.Trim();
            var name = match.Groups[2].Value;

            if (api.GlobalPointers.Any(g => g.Name == name))
                continue;

            var description = GetPrecedingComment(content, match.Index);

            api.GlobalPointers.Add(new GlobalPointer
            {
                Name = name,
                Type = type,
                IsConst = true,
                Description = CleanDescription(description)
            });
        }

        // Match SECP256K1_API const type name; (function pointer variables like nonce_function_rfc6979)
        var funcPtrGlobalRegex = GlobalFunctionPointerRegex();

        foreach (Match match in funcPtrGlobalRegex.Matches(content))
        {
            var type = match.Groups[1].Value.Trim();
            var name = match.Groups[2].Value;

            // Skip if it's a function (has opening paren after name)
            if (content.IndexOf(name + "(", match.Index, StringComparison.Ordinal) == match.Index + match.Length - name.Length - 1)
                continue;

            if (api.GlobalPointers.Any(g => g.Name == name))
                continue;

            var description = GetPrecedingComment(content, match.Index);

            api.GlobalPointers.Add(new GlobalPointer
            {
                Name = name,
                Type = type,
                IsConst = true,
                Description = CleanDescription(description)
            });
        }
    }

    private string CollapseMultilineDeclarations(string content)
    {
        // Collapse lines that are clearly continuations of function declarations
        var lines = content.Split('\n');
        var result = new List<string>();
        var currentDecl = "";
        var inDeclaration = false;
        var parenDepth = 0;

        foreach (var line in lines)
        {
            if (!inDeclaration)
            {
                if (line.Contains("SECP256K1_API") && !line.TrimStart().StartsWith("*") && !line.TrimStart().StartsWith("//"))
                {
                    inDeclaration = true;
                    currentDecl = line;
                    parenDepth = line.Count(c => c == '(') - line.Count(c => c == ')');

                    if (parenDepth <= 0 && line.Contains(";"))
                    {
                        result.Add(currentDecl);
                        inDeclaration = false;
                        currentDecl = "";
                    }
                }
                else
                {
                    result.Add(line);
                }
            }
            else
            {
                currentDecl += " " + line.Trim();
                parenDepth += line.Count(c => c == '(') - line.Count(c => c == ')');

                if (parenDepth <= 0 && currentDecl.Contains(";"))
                {
                    result.Add(currentDecl);
                    inDeclaration = false;
                    currentDecl = "";
                }
            }
        }

        if (!string.IsNullOrEmpty(currentDecl))
            result.Add(currentDecl);

        return string.Join("\n", result);
    }

    private List<ParameterDef> ParseParameters(string paramsStr, string? docComment)
    {
        var parameters = new List<ParameterDef>();

        if (string.IsNullOrWhiteSpace(paramsStr) || paramsStr.Trim() == "void")
            return parameters;

        // Split by comma, but be careful about nested parens (function pointers)
        var paramParts = SplitParameters(paramsStr);

        foreach (var paramPart in paramParts)
        {
            var param = ParseSingleParameter(paramPart.Trim());
            if (param != null)
            {
                // Try to get parameter description from doc comment
                param.Description = ExtractParameterDescription(docComment, param.Name);
                param.Direction = InferDirection(param.Type, param.Description);
                parameters.Add(param);
            }
        }

        return parameters;
    }

    private List<string> SplitParameters(string paramsStr)
    {
        var result = new List<string>();
        var current = "";
        var parenDepth = 0;

        foreach (var c in paramsStr)
        {
            if (c == '(') parenDepth++;
            else if (c == ')') parenDepth--;

            if (c == ',' && parenDepth == 0)
            {
                result.Add(current);
                current = "";
            }
            else
            {
                current += c;
            }
        }

        if (!string.IsNullOrWhiteSpace(current))
            result.Add(current);

        return result;
    }

    private ParameterDef? ParseSingleParameter(string param)
    {
        if (string.IsNullOrWhiteSpace(param))
            return null;

        // Handle inline function pointer parameters: void (*name)(args) or type (*name)(args)
        // Pattern: return_type (*name)(params)
        var funcPtrMatch = FuncPtrParamRegex().Match(param);
        if (funcPtrMatch.Success)
        {
            return new ParameterDef
            {
                Name = funcPtrMatch.Groups[2].Value,
                Type = $"{funcPtrMatch.Groups[1].Value.Trim()} (*)({funcPtrMatch.Groups[3].Value})"
            };
        }

        // Alternative pattern for function pointers: void (*fun)(const char *message, void *data)
        var simpleFuncPtrMatch = SimpleFuncPtrParamRegex().Match(param);
        if (simpleFuncPtrMatch.Success)
        {
            var returnType = simpleFuncPtrMatch.Groups[1].Value.Trim();
            var funcName = simpleFuncPtrMatch.Groups[2].Value;
            var funcParams = simpleFuncPtrMatch.Groups[3].Value;
            return new ParameterDef
            {
                Name = funcName,
                Type = $"{returnType} (*)({funcParams})"
            };
        }

        // Handle array parameters: type name[size] or type name[]
        var arrayMatch = ArrayParamRegex().Match(param);
        if (arrayMatch.Success)
        {
            var baseType = arrayMatch.Groups[1].Value.Trim();
            var arrayName = arrayMatch.Groups[2].Value;
            return new ParameterDef
            {
                Name = arrayName,
                Type = baseType + "*"  // Treat arrays as pointers
            };
        }

        // Handle regular parameters: type name or type * name or type *name
        // Also handle: const type *name, const type * const *name, etc.
        var parts = param.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
            return null;

        // Find the name (last identifier that's not a pointer/const modifier)
        string name;

        // The name is the last part, possibly with leading *
        var lastPart = parts[^1];
        while (lastPart.StartsWith("*"))
        {
            lastPart = lastPart[1..];
        }
        name = lastPart;

        // Build the type from remaining parts
        var typeParts = new List<string>();
        for (int i = 0; i < parts.Length - 1; i++)
        {
            typeParts.Add(parts[i]);
        }

        // Add back any pointers from the last part
        var pointers = parts[^1].TakeWhile(c => c == '*').Count();
        var typeStr = string.Join(" ", typeParts);
        if (pointers > 0)
        {
            typeStr += new string('*', pointers);
        }

        if (string.IsNullOrEmpty(name))
            return null;

        return new ParameterDef
        {
            Name = name,
            Type = typeStr.Trim()
        };
    }

    private string? InferDirection(string type, string? description)
    {
        var descLower = description?.ToLowerInvariant() ?? "";

        if (descLower.Contains("(output)") || descLower.StartsWith("out:"))
            return "out";
        if (descLower.Contains("(input)") || descLower.StartsWith("in:"))
            return "in";
        if (descLower.Contains("(input/output)") || descLower.Contains("in/out:"))
            return "inout";

        // Infer from type
        if (type.Contains("const"))
            return "in";
        if (type.Contains("*") && !type.Contains("const"))
            return "out"; // Non-const pointer is likely output

        return null;
    }

    private string? GetPrecedingComment(string content, int position)
    {
        // Look backwards for /** ... */ comment
        var searchStart = Math.Max(0, position - 5000);
        var searchContent = content.Substring(searchStart, position - searchStart);

        // Find the last /** ... */ block
        var commentEnd = searchContent.LastIndexOf("*/", StringComparison.Ordinal);
        if (commentEnd < 0)
            return null;

        var commentStart = searchContent.LastIndexOf("/**", commentEnd, StringComparison.Ordinal);
        if (commentStart < 0)
            return null;

        // Make sure there's no code between the comment and our target
        var between = searchContent.Substring(commentEnd + 2);
        if (between.Contains(";") || between.Contains("{"))
        {
            // There's a statement between - this comment isn't for us
            return null;
        }

        return searchContent.Substring(commentStart, commentEnd + 2 - commentStart);
    }

    private string? ExtractReturnDescription(string? docComment)
    {
        if (string.IsNullOrEmpty(docComment))
            return null;

        // Look for "Returns:" section
        var match = ReturnsRegex().Match(docComment);
        if (match.Success)
        {
            var returnDesc = match.Groups[1].Value;
            // Clean up and capture multi-line return descriptions
            return CleanMultilineText(returnDesc);
        }

        return null;
    }

    private string? ExtractParameterDescription(string? docComment, string paramName)
    {
        if (string.IsNullOrEmpty(docComment))
            return null;

        // Look for param in Args:, In:, Out:, or In/Out: sections
        var patterns = new[]
        {
            $@"\*\s*(?:Args|In|Out|In/Out):\s*{Regex.Escape(paramName)}:\s*([^\n]+(?:\n\s*\*\s+[^\n]+)*)",
            $@"\*\s+{Regex.Escape(paramName)}:\s*([^\n]+)"
        };

        foreach (var pattern in patterns)
        {
            var match = Regex.Match(docComment, pattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return CleanMultilineText(match.Groups[1].Value);
            }
        }

        return null;
    }

    private string? CleanDescription(string? comment)
    {
        if (string.IsNullOrEmpty(comment))
            return null;

        // Remove /** and */ markers
        var text = comment
            .Replace("/**", "")
            .Replace("*/", "")
            .Trim();

        // Remove leading * from each line, preserving empty lines as paragraph breaks
        var lines = text.Split('\n')
            .Select(l => l.TrimStart().TrimStart('*').TrimStart())
            .ToList();

        // Take just the first paragraph (up to Returns: or Args:)
        var result = new List<string>();
        foreach (var line in lines)
        {
            if (line.StartsWith("Returns:") || line.StartsWith("Args:") ||
                line.StartsWith("In:") || line.StartsWith("Out:"))
                break;
            result.Add(line);
        }

        // Remove trailing empty lines
        while (result.Count > 0 && string.IsNullOrWhiteSpace(result[^1]))
            result.RemoveAt(result.Count - 1);

        // Remove leading empty lines
        while (result.Count > 0 && string.IsNullOrWhiteSpace(result[0]))
            result.RemoveAt(0);

        return result.Count > 0 ? string.Join("\n", result) : null;
    }

    private string CleanMultilineText(string text)
    {
        var lines = text.Split('\n')
            .Select(l => l.TrimStart().TrimStart('*').TrimStart())
            .ToList();

        // Remove trailing empty lines
        while (lines.Count > 0 && string.IsNullOrWhiteSpace(lines[^1]))
            lines.RemoveAt(lines.Count - 1);

        // Remove leading empty lines
        while (lines.Count > 0 && string.IsNullOrWhiteSpace(lines[0]))
            lines.RemoveAt(0);

        return string.Join("\n", lines);
    }

    private long? TryEvaluateConstant(string value, List<ConstantDef> existingConstants)
    {
        // Try direct numeric
        if (long.TryParse(value, out var num))
            return num;

        // Try hex
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (long.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex))
                return hex;
        }

        // Try to evaluate expressions like (1 << 8) or (A | B)
        try
        {
            // Replace known constants
            var evalExpr = value;
            foreach (var c in existingConstants)
            {
                if (c.NumericValue.HasValue)
                {
                    evalExpr = evalExpr.Replace(c.Name, c.NumericValue.Value.ToString());
                }
            }

            // Simple expression evaluation for bit shifts and OR
            evalExpr = evalExpr.Replace("(", "").Replace(")", "");

            if (evalExpr.Contains("<<"))
            {
                var parts = evalExpr.Split("<<").Select(p => p.Trim()).ToArray();
                if (parts.Length == 2 && long.TryParse(parts[0], out var left) && int.TryParse(parts[1], out var shift))
                {
                    return left << shift;
                }
            }

            if (evalExpr.Contains("|"))
            {
                var parts = evalExpr.Split('|').Select(p => p.Trim()).ToArray();
                long result = 0;
                foreach (var part in parts)
                {
                    if (long.TryParse(part, out var partVal))
                        result |= partVal;
                    else
                        return null;
                }
                return result;
            }
        }
        catch
        {
            // Ignore evaluation errors
        }

        return null;
    }

    // Compiled regex patterns
    [GeneratedRegex(@"typedef\s+struct\s+(\w+)\s*\{\s*unsigned\s+char\s+data\[(\d+)\];\s*\}\s*\1;", RegexOptions.Singleline)]
    private static partial Regex StructRegex();

    [GeneratedRegex(@"typedef\s+struct\s+\w+\s+(\w+);")]
    private static partial Regex OpaqueStructRegex();

    [GeneratedRegex(@"typedef\s+(\w+(?:\s*\*)?)\s*\(\*(\w+)\)\s*\(([^)]*)\);", RegexOptions.Singleline)]
    private static partial Regex FuncPtrTypeRegex();

    // This regex captures everything up to the function name and first paren - we'll extract params manually
    [GeneratedRegex(@"SECP256K1_API\s+(?:SECP256K1_WARN_UNUSED_RESULT\s+)?(\w+(?:\s*\*)*)\s*(\w+)\s*\(", RegexOptions.Singleline)]
    private static partial Regex FunctionStartRegex();

    [GeneratedRegex(@"SECP256K1_ARG_NONNULL\((\d+)\)")]
    private static partial Regex NonnullRegex();

    [GeneratedRegex(@"SECP256K1_DEPRECATED\s*\(\s*""([^""]*)""\s*\)")]
    private static partial Regex DeprecatedRegex();

    [GeneratedRegex(@"#define\s+SECP256K1_(\w+)\s+(.+)$", RegexOptions.Multiline)]
    private static partial Regex ConstantRegex();

    [GeneratedRegex(@"SECP256K1_API\s+const\s+(\w+)\s*\*\s*const\s+(\w+)")]
    private static partial Regex GlobalPointerRegex();

    [GeneratedRegex(@"extern\s+(?:const\s+)?(\w+)\s+(\w+);")]
    private static partial Regex ExternGlobalRegex();

    [GeneratedRegex(@"SECP256K1_API\s+const\s+(\w+)\s+(secp256k1_\w+);")]
    private static partial Regex GlobalFunctionPointerRegex();

    // Pattern for function pointer params: returnType (*name)(params)
    // The params can contain nested parens and commas
    [GeneratedRegex(@"^(\w+(?:\s+\w+)*)\s*\(\s*\*\s*(\w+)\s*\)\s*\((.+)\)\s*$")]
    private static partial Regex FuncPtrParamRegex();

    // Simpler pattern for: void (*fun)(const char *message, void *data)
    [GeneratedRegex(@"^(\w+)\s+\(\s*\*\s*(\w+)\s*\)\s*\((.+)\)\s*$")]
    private static partial Regex SimpleFuncPtrParamRegex();

    [GeneratedRegex(@"(.+?)\s+(\w+)\s*\[\s*\d*\s*\]")]
    private static partial Regex ArrayParamRegex();

    [GeneratedRegex(@"Returns:\s*(.+?)(?=\s*\*\s*(?:Args|In|Out|$))", RegexOptions.Singleline)]
    private static partial Regex ReturnsRegex();
}
