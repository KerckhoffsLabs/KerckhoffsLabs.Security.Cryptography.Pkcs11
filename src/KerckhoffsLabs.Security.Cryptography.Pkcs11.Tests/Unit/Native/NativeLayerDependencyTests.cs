using System.Reflection;
using System.Reflection.Emit;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The Native layer sits at the bottom: it mirrors the C ABI and owns the module, and everything else is
/// built on it. It may use the shared vocabulary (<c>Common</c>, <c>Exceptions</c>, <c>Logging</c>) but
/// nothing above it: not <c>Internal</c>, not the mechanism-parameter classes, not the public façade.
/// Method bodies are scanned too, so a call into a higher layer is caught even when no signature shows it.
/// </summary>
public sealed class NativeLayerDependencyTests
{
    private const string Root = "KerckhoffsLabs.Security.Cryptography.Pkcs11";

    private static readonly string[] AllowedNamespaces =
    [
        $"{Root}.Native",
        $"{Root}.Common",
        $"{Root}.Exceptions",
        $"{Root}.Logging",
    ];

    private static readonly Assembly Library = typeof(Pkcs11Library).Assembly;

    [Fact]
    public void NativeTypes_DependOnlyOnNativeAndTheSharedVocabulary()
    {
        string[] offenders =
        [
            .. Library.GetTypes()
                .Where(t => InNamespace(t, $"{Root}.Native"))
                .SelectMany(t => ReferencedTypes(t).SelectMany(RootTypes).Where(IsAboveNative)
                    .Select(r => $"{t.FullName} -> {r.FullName}"))
                .Distinct()
                .Order(StringComparer.Ordinal),
        ];

        Assert.True(offenders.Length == 0, "Native depends on a higher layer:\n" + string.Join("\n", offenders));
    }

    // Guards the scan itself: a reference only a method body makes is still found, so an empty list
    // above means "no dependency", not "the scanner stopped looking".
    [Fact]
    public void Scan_FindsAReferenceMadeOnlyInAMethodBody()
        => Assert.Contains(typeof(UnmanagedMemory), ReferencedTypes(typeof(MechanismParameterScope)));

    [Theory]
    [InlineData(typeof(Pkcs11Library), true)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.ObjectHandle), true)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams.CkmAesGcmParams), true)]
    [InlineData(typeof(CK_ATTRIBUTE), false)]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Common.CKR), false)]
    [InlineData(typeof(string), false)]
    public void Predicate_RecognisesTheLayers(Type type, bool above)
        => Assert.Equal(above, IsAboveNative(type));

    // Only this library's own namespaces are layers. Anything else in the assembly is not ours: compiler-
    // generated helpers (<PrivateImplementationDetails>, in no namespace) or the tracker a coverage tool
    // injects when it instruments the library.
    private static bool IsAboveNative(Type type)
        => type.Assembly == Library
           && InNamespace(type, Root)
           && !AllowedNamespaces.Any(ns => InNamespace(type, ns));

    private static bool InNamespace(Type type, string ns)
        => type.Namespace is { } n && (n == ns || n.StartsWith(ns + ".", StringComparison.Ordinal));

    private const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic
        | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    // Every type the definition of type uses: its base and interfaces, its member signatures, its locals,
    // and the types, fields and methods its IL refers to.
    private static IEnumerable<Type> ReferencedTypes(Type type)
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
