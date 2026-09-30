using System.Reflection;
using System.Reflection.Emit;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The BCL adapters in <c>Algorithms</c> are built the way a consumer would build them: on the public
/// API only. Anything they need from the core is public, so a consumer can do the same directly; and
/// the core never reaches into an adapter's internals. Checked on the compiled IL, since both halves
/// share one assembly and the compiler cannot tell <c>internal</c> apart for them.
/// </summary>
public sealed class AlgorithmsBoundaryTests
{
    private static readonly Assembly Library = typeof(Pkcs11Key).Assembly;
    private static readonly string AlgorithmsNamespace = typeof(Pkcs11.Algorithms.AesGcmPkcs11).Namespace!;

    private static readonly Dictionary<short, OpCode> OpCodesByValue = typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(f => (OpCode)f.GetValue(null)!)
        .ToDictionary(o => o.Value);

    [Fact]
    public void Algorithms_UsesOnlyThePublicSurfaceOfTheCore()
    {
        IEnumerable<string> violations = References(InAlgorithms)
            .Where(r => !InAlgorithms(r.Target) && !IsPublicSurface(r.Target))
            .Select(r => $"{r.From} -> {Describe(r.Target)}")
            .Distinct();

        AssertNone(violations);
    }

    [Fact]
    public void Core_UsesOnlyThePublicSurfaceOfAlgorithms()
    {
        IEnumerable<string> violations = References(t => !InAlgorithms(t))
            .Where(r => InAlgorithms(r.Target) && !IsPublicSurface(r.Target))
            .Select(r => $"{r.From} -> {Describe(r.Target)}")
            .Distinct();

        AssertNone(violations);
    }

    // Lists every offending reference, which Assert.Empty would truncate.
    private static void AssertNone(IEnumerable<string> violations)
    {
        string[] found = [.. violations.Order(StringComparer.Ordinal)];
        Assert.True(found.Length == 0, "Non-public references across the boundary:" + Environment.NewLine + string.Join(Environment.NewLine, found));
    }

    private static readonly string RootNamespace = typeof(Pkcs11Key).Namespace!;

    private static bool IsLibraryNamespace(Type type) =>
        type.Namespace == RootNamespace || (type.Namespace?.StartsWith(RootNamespace + ".", StringComparison.Ordinal) ?? false);

    private static bool InAlgorithms(Type type) =>
        type.Namespace == AlgorithmsNamespace || (type.Namespace?.StartsWith(AlgorithmsNamespace + ".", StringComparison.Ordinal) ?? false);

    private static bool InAlgorithms(MemberInfo member) =>
        member is Type type ? InAlgorithms(type) : member.DeclaringType is { } declaring && InAlgorithms(declaring);

    private static bool IsPublicSurface(MemberInfo member)
    {
        Type? type = member as Type ?? member.DeclaringType;
        if (type is not null && !IsVisibleType(type))
            return false;
        return member switch
        {
            Type => true,
            MethodBase m => m.IsPublic || m.IsFamily || m.IsFamilyOrAssembly,
            FieldInfo f => f.IsPublic || f.IsFamily || f.IsFamilyOrAssembly,
            _ => true,
        };
    }

    private static bool IsVisibleType(Type type)
    {
        if (type.IsGenericType && !type.IsGenericTypeDefinition)
            return IsVisibleType(type.GetGenericTypeDefinition()) && type.GetGenericArguments().All(a => a.Assembly != Library || a.IsGenericParameter || IsVisibleType(a));
        if (type.IsArray || type.IsByRef || type.IsPointer)
            return IsVisibleType(type.GetElementType()!);
        if (type.Assembly != Library || type.IsGenericParameter)
            return true;
        return type.IsNested
            ? (type.IsNestedPublic || type.IsNestedFamily || type.IsNestedFamORAssem) && IsVisibleType(type.DeclaringType!)
            : type.IsPublic;
    }

    private static string Describe(MemberInfo member) =>
        member is Type type ? type.FullName ?? type.Name : $"{member.DeclaringType?.FullName}.{member.Name}";

    private readonly record struct Reference(string From, MemberInfo Target);

    // Every member of this assembly referenced from the IL of the methods of the matching types.
    private static IEnumerable<Reference> References(Func<Type, bool> fromTypes)
    {
        const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance
            | BindingFlags.Static | BindingFlags.DeclaredOnly;

        foreach (Type type in Library.GetTypes().Where(fromTypes))
        {
            IEnumerable<MethodBase> methods = type.GetMethods(all).Cast<MethodBase>().Concat(type.GetConstructors(all));
            foreach (MethodBase method in methods)
            {
                byte[]? il = method.GetMethodBody()?.GetILAsByteArray();
                if (il is null)
                    continue;
                foreach (MemberInfo target in Tokens(method, il))
                {
                    MemberInfo root = target is Type t && t.IsGenericType && !t.IsGenericTypeDefinition ? t.GetGenericTypeDefinition() : target;
                    Type? owner = root as Type ?? root.DeclaringType;
                    // Only the library's own namespace: tools also emit types into the assembly — the
                    // compiler's <PrivateImplementationDetails> (string-switch hashes, array initialisers),
                    // Coverlet's hit tracker under coverage — which neither side chose to use.
                    if (owner?.Assembly == Library && IsLibraryNamespace(owner))
                        yield return new Reference($"{type.FullName}.{method.Name}", target);
                }
            }
        }
    }

    // Walks the IL stream and resolves every metadata-token operand to the member it names.
    private static IEnumerable<MemberInfo> Tokens(MethodBase method, byte[] il)
    {
        Type[]? typeArgs = method.DeclaringType is { IsGenericType: true } d ? d.GetGenericArguments() : null;
        Type[]? methodArgs = method.IsGenericMethod ? method.GetGenericArguments() : null;
        int i = 0;
        while (i < il.Length)
        {
            short value = il[i] == 0xFE ? unchecked((short)(0xFE00 | il[i + 1])) : il[i];
            i += il[i] == 0xFE ? 2 : 1;
            OpCode op = OpCodesByValue[value];
            switch (op.OperandType)
            {
                case OperandType.InlineMethod:
                case OperandType.InlineField:
                case OperandType.InlineType:
                case OperandType.InlineTok:
                    MemberInfo? member = Resolve(method.Module, BitConverter.ToInt32(il, i), typeArgs, methodArgs);
                    if (member is not null)
                        yield return member;
                    i += 4;
                    break;
                case OperandType.InlineSwitch:
                    i += 4 + (4 * BitConverter.ToInt32(il, i));
                    break;
                case OperandType.InlineNone:
                    break;
                case OperandType.ShortInlineBrTarget:
                case OperandType.ShortInlineI:
                case OperandType.ShortInlineVar:
                    i += 1;
                    break;
                case OperandType.InlineVar:
                    i += 2;
                    break;
                case OperandType.InlineI8:
                case OperandType.InlineR:
                    i += 8;
                    break;
                default:
                    i += 4;
                    break;
            }
        }
    }

    private static MemberInfo? Resolve(Module module, int token, Type[]? typeArgs, Type[]? methodArgs)
    {
        try
        {
            return module.ResolveMember(token, typeArgs, methodArgs);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
