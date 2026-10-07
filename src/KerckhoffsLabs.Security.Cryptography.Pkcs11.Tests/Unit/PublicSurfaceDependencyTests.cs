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

    // The internal/native layer is free to change in any release only while nothing of it is visible
    // to a consumer: no native struct or handle type, no raw pointer, no SafeHandle, nothing from the
    // Native or Internal namespaces. The interop-package check above covers one assembly; this covers
    // the rest of the marshalling layer, so a refactor of the dispatch code cannot quietly turn an
    // internal type into public surface.
    [Fact]
    public void NoPublicApiMember_ExposesAMarshallingLayerType()
    {
        Assembly library = typeof(Pkcs11Library).Assembly;
        var offenders = new List<string>();

        foreach (Type type in library.GetExportedTypes())
        {
            if (IsMarshallingLayerType(type))
                offenders.Add($"{type.FullName} : exported type");

            foreach ((string member, Type signatureType) in SignatureTypes(type))
            {
                if (signatureType.IsPointer || signatureType.IsFunctionPointer
                    || RootTypes(signatureType).Any(IsMarshallingLayerType))
                    offenders.Add($"{type.FullName}.{member} : {signatureType.Name}");
            }
        }

        Assert.Empty(offenders);
    }

    // Guards the predicate itself: each kind of type it must catch is still recognised, so an empty
    // offender list above means "nothing leaks", not "the predicate stopped matching anything".
    [Theory]
    [InlineData(typeof(IntPtr))]
    [InlineData(typeof(UIntPtr))]
    [InlineData(typeof(Microsoft.Win32.SafeHandles.SafeFileHandle))]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.CK_ATTRIBUTE))]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.ObjectHandle))]
    [InlineData(typeof(KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles.Pkcs11SessionHandle))]
    [InlineData(typeof(NativeCULong))]
    public void MarshallingLayerPredicate_RecognisesEachKind(Type type)
        => Assert.True(IsMarshallingLayerType(type), $"{type.FullName} should count as a marshalling-layer type.");

    private static bool IsMarshallingLayerType(Type type)
        => type.Assembly == _interop
           || type == typeof(IntPtr) || type == typeof(UIntPtr)
           || typeof(System.Runtime.InteropServices.SafeHandle).IsAssignableFrom(type)
           || type.Namespace is { } ns && MarshallingNamespaces.Any(m => ns == m || ns.StartsWith(m + ".", StringComparison.Ordinal));

    private static readonly string[] MarshallingNamespaces =
    [
        "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native",
        "KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal",
    ];

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
