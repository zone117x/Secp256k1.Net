using System.Collections.Generic;

namespace Secp256k1Net.InteropGen;

public class Secp256k1Api
{
    public string Version { get; set; } = "";
    public string GeneratedAt { get; set; } = "";
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
