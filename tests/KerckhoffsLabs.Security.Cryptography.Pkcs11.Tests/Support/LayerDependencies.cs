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
        => Violations(layer, allowed, allowedExactly: []);

    /// <summary>
    /// As <see cref="Violations(string, string[])"/>, also allowing each namespace in
    /// <paramref name="allowedExactly"/> but none of the namespaces under it. The library's root namespace
    /// holds the public façade and contains every layer, so a layer that may use the façade allows it
    /// this way.
    /// </summary>
    public static string[] Violations(string layer, string[] allowed, string[] allowedExactly)
        => [.. Library.GetTypes()
            .Where(t => InNamespace(t, layer))
            .SelectMany(t => ReferencedTypes(t).SelectMany(RootTypes).Where(r => IsOutside(r, [layer, .. allowed], allowedExactly))
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
        => IsOutside(type, allowed, allowedExactly: []);

    /// <summary>
    /// Whether <paramref name="type"/> is a type of this library outside every namespace in
    /// <paramref name="allowed"/> and not directly in any namespace in <paramref name="allowedExactly"/>.
    /// </summary>
    public static bool IsOutside(Type type, string[] allowed, string[] allowedExactly)
        => type.Assembly == Library
           && InNamespace(type, Root)
           && !allowed.Any(ns => InNamespace(type, ns))
           && !allowedExactly.Contains(type.Namespace, StringComparer.Ordinal);

    /// <summary>
    /// "<c>Type.Member</c>" (relative to <see cref="Root"/>) for every non-public type or member of this
    /// library outside <paramref name="layer"/> that a type in <paramref name="layer"/> refers to, sorted.
    /// A member counts as non-public when it is, or when a type it is declared in is; a type counts when
    /// its definition uses it anywhere (see <see cref="ReferencedTypes"/>). Property and event accessors
    /// are listed by their accessor names (<c>get_X</c>, <c>set_X</c>), so a read and a write differ.
    /// </summary>
    public static string[] NonPublicReferences(string layer)
        => [.. Library.GetTypes()
            .Where(t => InNamespace(t, layer))
            .SelectMany(t => ReferencedTypes(t).SelectMany(RootTypes)
                .Where(r => IsOutside(r, [layer]) && !IsVisible(r))
                .Select(Name)
                .Concat(ReferencedMembers(t)
                    .Where(m => m.DeclaringType is { } d && IsOutside(d, [layer]) && !IsVisible(m))
                    .Select(m => $"{Name(m.DeclaringType!)}.{m.Name}")))
            .Distinct()
            .Order(StringComparer.Ordinal)];

    private static string Name(Type type)
        => (type.IsConstructedGenericType ? type.GetGenericTypeDefinition() : type).FullName![(Root.Length + 1)..].Replace('+', '.');

    // Reachable from another assembly: protected counts, since a consumer can derive to reach it.
    private static bool IsVisible(Type type)
    {
        for (Type? t = type; t is not null; t = t.DeclaringType)
        {
            if (!(t.IsPublic || t.IsNestedPublic || t.IsNestedFamily || t.IsNestedFamORAssem))
                return false;
        }
        return true;
    }

    private static bool IsVisible(MemberInfo member)
        => IsVisible(member.DeclaringType!) && member switch
        {
            MethodBase m => m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly,
            FieldInfo f => f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly,
            _ => true,
        };

    // The fields and methods the IL of type's methods and constructors refers to.
    private static IEnumerable<MemberInfo> ReferencedMembers(Type type)
        => type.GetMethods(Declared).Cast<MethodBase>().Concat(type.GetConstructors(Declared))
            .SelectMany(m => m.GetMethodBody() is { } body ? IlReferences(m, body) : [])
            .Where(m => m is FieldInfo or MethodBase);

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
