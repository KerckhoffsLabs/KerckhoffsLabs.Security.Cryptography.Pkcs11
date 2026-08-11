using System.Reflection;
using KerckhoffsLabs.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// NativeCULong is a marshalling type whose width differs per RID (32-bit on Windows, pointer-sized
// elsewhere) and which ships from a separate package. On the public surface it would make consumers
// take a hard dependency on an interop package they otherwise never need, turn any breaking change
// there into a breaking change here, and force `.Value` on every composition with this library's own
// ulong-typed flags. It belongs to the marshalling layer only; everything public speaks ulong.
public sealed class PublicSurfaceDependencyTests
{
    private static readonly Assembly _interop = typeof(NativeCULong).Assembly;

    [Fact]
    public void NoPublicApiMember_ExposesATypeFromTheInteropPackage()
    {
        Assembly library = typeof(Pkcs11Library).Assembly;
        var offenders = new List<string>();

        foreach (Type type in library.GetExportedTypes())
        {
            foreach ((string member, Type signatureType) in SignatureTypes(type))
            {
                if (RootTypes(signatureType).Any(t => t.Assembly == _interop))
                    offenders.Add($"{type.FullName}.{member} : {signatureType.Name}");
            }
        }

        Assert.Empty(offenders);
    }

    // Sanity check on the reflection above: the marshalling layer really does still use the type, so
    // an empty offender list means "kept internal", not "the package vanished from the build".
    [Fact]
    public void TheInteropTypeIsStillUsed_ByNonPublicCode()
    {
        Assembly library = typeof(Pkcs11Library).Assembly;

        bool used = library.GetTypes()
            .SelectMany(t => t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Any(f => f.FieldType.Assembly == _interop);

        Assert.True(used, "Expected the marshalling layer to still hold NativeCULong fields.");
    }

    // Every type that appears in a member's signature and is therefore visible to a consumer.
    private static IEnumerable<(string Member, Type Type)> SignatureTypes(Type type)
    {
        const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic
            | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        foreach (Type i in type.GetInterfaces())
            yield return ("<interface>", i);

        if (type.BaseType is not null)
            yield return ("<base>", type.BaseType);

        foreach (FieldInfo field in type.GetFields(Declared).Where(f => IsVisible(f.IsPublic, f.IsFamily, f.IsFamilyOrAssembly)))
            yield return (field.Name, field.FieldType);

        foreach (MethodBase method in type.GetMethods(Declared).Cast<MethodBase>().Concat(type.GetConstructors(Declared))
                     .Where(m => IsVisible(m.IsPublic, m.IsFamily, m.IsFamilyOrAssembly)))
        {
            if (method is MethodInfo { ReturnType: var returnType })
                yield return (method.Name, returnType);

            foreach (ParameterInfo parameter in method.GetParameters())
                yield return ($"{method.Name}({parameter.Name})", parameter.ParameterType);
        }
    }

    private static bool IsVisible(bool isPublic, bool isFamily, bool isFamilyOrAssembly)
        => isPublic || isFamily || isFamilyOrAssembly;

    // Unwraps by-ref/array/pointer decoration and generic arguments so that, say, a
    // Nullable<NativeCULong> parameter or a IReadOnlyList<NativeCULong> return is still caught.
    private static IEnumerable<Type> RootTypes(Type type)
    {
        Type core = type;
        while (core.HasElementType)
            core = core.GetElementType()!;

        yield return core;

        if (core.IsGenericType)
        {
            foreach (Type argument in core.GetGenericArguments().SelectMany(RootTypes))
                yield return argument;
        }
    }
}
