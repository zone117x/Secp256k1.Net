using System;
using System.Collections.Generic;

namespace Secp256k1Net.InteropGen;

public class Secp256k1Api
{
    public string Version { get; set; } = "0.7.0";
    public string GeneratedAt { get; set; } = DateTime.UtcNow.ToString("O");
    public List<string> Headers { get; set; } = new();
    public List<StructDef> Structs { get; set; } = new();
    public List<FunctionPointerType> FunctionPointerTypes { get; set; } = new();
    public List<FunctionDef> Functions { get; set; } = new();
    public List<ConstantDef> Constants { get; set; } = new();
    public List<GlobalPointer> GlobalPointers { get; set; } = new();
}

public class StructDef
{
    public string Name { get; set; } = "";
    public int Size { get; set; }
    public string? Description { get; set; }
}

public class FunctionPointerType
{
    public string Name { get; set; } = "";
    public string ReturnType { get; set; } = "";
    public List<ParameterDef> Parameters { get; set; } = new();
    public string? Description { get; set; }
}

public class FunctionDef
{
    public string Name { get; set; } = "";
    public string ReturnType { get; set; } = "";
    public bool WarnUnusedResult { get; set; }
    public bool Deprecated { get; set; }
    public string? DeprecatedMessage { get; set; }
    public List<ParameterDef> Parameters { get; set; } = new();
    public string? Description { get; set; }
    public string? ReturnDescription { get; set; }
    public string? SourceHeader { get; set; }
}

public class ParameterDef
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string? Direction { get; set; }
    public bool Nonnull { get; set; }
    public string? Description { get; set; }

    /// <summary>
    /// Fixed size in bytes for this parameter (e.g., extracted from name like "algo16" → 16,
    /// or from description like "32-byte array").
    /// </summary>
    public int? Size { get; set; }

    /// <summary>
    /// Name of another parameter that specifies the length of this parameter.
    /// Used for variable-length arrays where another param indicates the size.
    /// </summary>
    public string? LengthParam { get; set; }

    /// <summary>
    /// If this parameter is a length/size indicator for another parameter,
    /// this is the name of the parameter it describes.
    /// </summary>
    public string? IsLengthFor { get; set; }

    /// <summary>
    /// True if this parameter is known to be optional (can be null/empty even when validation
    /// would otherwise be applied). Examples: algo16, data parameters.
    /// </summary>
    public bool IsOptional { get; set; }
}

public class ConstantDef
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public long? NumericValue { get; set; }
    public string? Description { get; set; }
}

public class GlobalPointer
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public bool IsConst { get; set; }
    public string? Description { get; set; }
}
