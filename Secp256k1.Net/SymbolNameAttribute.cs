using System;

namespace Secp256k1Net
{
    class SymbolNameAttribute : Attribute
    {
        public readonly string Name;

        public SymbolNameAttribute(string name)
        {
            Name = name;
        }
    }


}