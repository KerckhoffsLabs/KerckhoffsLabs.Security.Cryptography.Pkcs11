using System.Reflection;
using System.Reflection.Emit;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Finds the types a layer of the library depends on: for each of its types, the base type and
/// interfaces, member signatures, locals, and the types, fields and methods its IL refers to. Method
/// bodies are scanned, so a dependency is found even when no signature shows it.
/// </summary>
internal static class LayerDependencies
{
    public const string Root = "KerckhoffsLabs.Security.Cryptography.Pkcs11";

    private static readonly Assembly Library = typeof(Pkcs11Library).Assembly;

    /// <summary>
    /// "<c>Type -> Dependency</c>" for every type of this library in <paramref name="layer"/> that refers to
    /// a type of this library outside <paramref name="layer"/> and <paramref name="allowed"/>, sorted.
    /// </summary>
    public static string[] Violations(string layer, params string[] allowed)
        => [.. Library.GetTypes()
            .Where(t => InNamespace(t, layer))
            .SelectMany(t => ReferencedTypes(t).SelectMany(RootTypes).Where(r => IsOutside(r, [layer, .. allowed]))
                .Select(r => $"{t.FullName} -> {r.FullName}"))
            .Distinct()
            .Order(StringComparer.Ordinal)];

    /// <summary>Whether <paramref name="type"/> is a type of this library outside every namespace in <paramref name="allowed"/>.</summary>
    /// <remarks>
    /// Only this library's own namespaces are layers. Anything else in the assembly is not ours: compiler-
    /// generated helpers (<c>&lt;PrivateImplementationDetails&gt;</c>, in no namespace) or the tracker a
    /// coverage tool injects when it instruments the library.
    /// </remarks>
    public static bool IsOutside(Type type, string[] allowed)
        => type.Assembly == Library
           && InNamespace(type, Root)
           && !allowed.Any(ns => InNamespace(type, ns));

    private static bool InNamespace(Type type, string ns)
        => type.Namespace is { } n && (n == ns || n.StartsWith(ns + ".", StringComparison.Ordinal));

    private const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic
        | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    // Every type the definition of type uses: its base and interfaces, its member signatures, its locals,
    // and the types, fields and methods its IL refers to.
    public static IEnumerable<Type> ReferencedTypes(Type type)
    {
        if (type.BaseType is not null)
            yield return type.BaseType;
        foreach (Type i in type.GetInterfaces())
            yield return i;

        foreach (FieldInfo field in type.GetFields(Declared))
            yield return field.FieldType;
        foreach (PropertyInfo property in type.GetProperties(Declared))
            yield return property.PropertyType;

        foreach (MethodBase method in type.GetMethods(Declared).Cast<MethodBase>().Concat(type.GetConstructors(Declared)))
        {
            foreach (Type t in SignatureTypes(method))
                yield return t;

            MethodBody? body = method.GetMethodBody();
            if (body is null)
                continue;
            foreach (LocalVariableInfo local in body.LocalVariables)
                yield return local.LocalType;
            foreach (MemberInfo member in IlReferences(method, body))
            {
                switch (member)
                {
                    case Type t:
                        yield return t;
                        break;
                    case FieldInfo f:
                        yield return f.DeclaringType!;
                        yield return f.FieldType;
                        break;
                    case MethodBase m:
                        yield return m.DeclaringType!;
                        foreach (Type t in SignatureTypes(m))
                            yield return t;
                        break;
                }
            }
        }
    }

    private static IEnumerable<Type> SignatureTypes(MethodBase method)
    {
        if (method is MethodInfo info)
        {
            yield return info.ReturnType;
            if (info.IsGenericMethod)
            {
                foreach (Type argument in info.GetGenericArguments())
                    yield return argument;
            }
        }
        foreach (ParameterInfo parameter in method.GetParameters())
            yield return parameter.ParameterType;
    }

    // Unwraps by-ref, array and pointer decoration and generic arguments.
    private static IEnumerable<Type> RootTypes(Type type)
    {
        Type core = type;
        while (core.HasElementType)
            core = core.GetElementType()!;
        if (core.IsGenericParameter)
            yield break;

        yield return core;
        if (core.IsGenericType)
        {
            foreach (Type argument in core.GetGenericArguments().SelectMany(RootTypes))
                yield return argument;
        }
    }

    // The members referred to by the metadata tokens in method's IL.
    private static IEnumerable<MemberInfo> IlReferences(MethodBase method, MethodBody body)
    {
        byte[] il = body.GetILAsByteArray() ?? [];
        Type[]? typeArguments = method.DeclaringType is { IsGenericType: true } d ? d.GetGenericArguments() : null;
        Type[]? methodArguments = method.IsGenericMethod ? method.GetGenericArguments() : null;

        int offset = 0;
        while (offset < il.Length)
        {
            OpCode opCode = il[offset] == 0xFE ? TwoByteOpCodes[il[offset + 1]] : OneByteOpCodes[il[offset]];
            offset += opCode.Size;

            if (opCode.OperandType is OperandType.InlineField or OperandType.InlineMethod
                or OperandType.InlineType or OperandType.InlineTok)
            {
                int token = BitConverter.ToInt32(il, offset);
                yield return method.Module.ResolveMember(token, typeArguments, methodArguments)!;
            }

            offset += opCode.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => 4 + 4 * BitConverter.ToInt32(il, offset),
                _ => 4,
            };
        }
    }

    private static readonly OpCode[] OneByteOpCodes = OpCodeTable(twoByte: false);
    private static readonly OpCode[] TwoByteOpCodes = OpCodeTable(twoByte: true);

    private static OpCode[] OpCodeTable(bool twoByte)
    {
        var table = new OpCode[256];
        foreach (FieldInfo field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            var opCode = (OpCode)field.GetValue(null)!;
            if ((opCode.Size == 2) == twoByte)
                table[opCode.Value & 0xFF] = opCode;
        }
        return table;
    }
}
