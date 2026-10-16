using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Every struct with a Windows (Pack=1) sibling goes through <see cref="Pkcs11Marshal"/>'s Windows layout
/// and comes back unchanged. The layout is plain bytes, so this runs on every OS: the Windows path the
/// dispatch code takes there is checked here too, not only on the Windows legs.
/// </summary>
public sealed class WindowsLayoutRoundTripTests
{
    private static readonly Type[] PackedTypes =
    [
        .. typeof(Pkcs11Library).Assembly.GetTypes()
            .Where(t => t.IsValueType && t.GetCustomAttribute<PackedForPkcs11Attribute>() is not null)
            .OrderBy(t => t.Name, StringComparer.Ordinal),
    ];

    public static TheoryData<string> PackedTypeNames => [.. PackedTypes.Select(t => t.Name)];

    // Guards the reflection above against matching nothing and passing vacuously.
    [Fact]
    public void PackedTypes_AreFound()
        => Assert.Contains(typeof(CK_ATTRIBUTE), PackedTypes);

    // Guards the field comparison below: a changed field is reported, so a pass means "unchanged".
    [Fact]
    public void FieldComparison_ReportsAChangedField()
        => Assert.ThrowsAny<Exception>(() => AssertFieldsEqual(
            new CK_ATTRIBUTE { valueLen = (KerckhoffsLabs.Runtime.InteropServices.NativeCULong)1UL },
            new CK_ATTRIBUTE { valueLen = (KerckhoffsLabs.Runtime.InteropServices.NativeCULong)2UL },
            nameof(CK_ATTRIBUTE)));

    [Theory]
    [MemberData(nameof(PackedTypeNames))]
    public void WindowsLayout_IsTheSiblingsSize(string name)
    {
        Type type = PackedTypes.Single(t => t.Name == name);
        Type sibling = type.Assembly.GetType(type.FullName + "_Windows", throwOnError: true)!;

        Assert.Equal(SizeOfType(sibling), Invoke<int>(nameof(SizeOfWindowsLayout), type));
    }

    // A struct without a packed sibling has one layout, so the Windows layout is its natural one.
    [Fact]
    public void WindowsLayout_OfAStructWithoutASibling_IsItsNaturalLayout()
    {
        var version = new CK_VERSION { Major = 3, Minor = 2 };
        IntPtr memory = Marshal.AllocHGlobal(Pkcs11Marshal.SizeOf<CK_VERSION>(windowsLayout: true));
        try
        {
            Pkcs11Marshal.WriteStructure(memory, in version, windowsLayout: true);

            Assert.Equal(Unsafe.SizeOf<CK_VERSION>(), Pkcs11Marshal.SizeOf<CK_VERSION>(windowsLayout: true));
            Assert.Equal(version, Pkcs11Marshal.ReadStructure<CK_VERSION>(memory, windowsLayout: false));
        }
        finally
        {
            Marshal.FreeHGlobal(memory);
        }
    }

    [Theory]
    [MemberData(nameof(PackedTypeNames))]
    public void WindowsLayout_RoundTripsEveryField(string name)
    {
        Type type = PackedTypes.Single(t => t.Name == name);
        (object original, object back) = Invoke<(object, object)>(nameof(RoundTrip), type);

        AssertFieldsEqual(original, back, name);
    }

    // Field by field, so the unified struct's padding, which the packed layout drops, does not count.
    // The library's own structs are walked; every other field (a primitive, NativeCULong, an inline
    // array or fixed buffer) has no padding and is compared as bytes.
    private static void AssertFieldsEqual(object expected, object actual, string path)
    {
        Type type = expected.GetType();
        bool walk = type.Assembly == typeof(Pkcs11Library).Assembly
            && !type.IsEnum
            && type.GetCustomAttribute<InlineArrayAttribute>() is null
            && type.GetCustomAttribute<CompilerGeneratedAttribute>() is null;
        if (!walk)
        {
            Assert.True(Bytes(expected).AsSpan().SequenceEqual(Bytes(actual)), $"{path} differs after the round trip.");
            return;
        }

        foreach (FieldInfo field in type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            AssertFieldsEqual(field.GetValue(expected)!, field.GetValue(actual)!, $"{path}.{field.Name}");
    }

    private static byte[] Bytes(object value)
        => (byte[])typeof(WindowsLayoutRoundTripTests).GetMethod(nameof(BytesOf), BindingFlags.NonPublic | BindingFlags.Static)!
            .MakeGenericMethod(value.GetType()).Invoke(null, [value])!;

    private static byte[] BytesOf<TField>(TField value) where TField : struct
        => MemoryMarshal.AsBytes(new ReadOnlySpan<TField>(in value)).ToArray();

    private static int SizeOfWindowsLayout<T>() where T : unmanaged => Pkcs11Marshal.SizeOf<T>(windowsLayout: true);

    private static (object Original, object Back) RoundTrip<T>() where T : unmanaged
    {
        T value = default;
        Span<byte> bytes = MemoryMarshal.AsBytes(new Span<T>(ref value));
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = unchecked((byte)(i * 31 + 7));

        IntPtr memory = Marshal.AllocHGlobal(Pkcs11Marshal.SizeOf<T>(windowsLayout: true));
        try
        {
            Pkcs11Marshal.WriteStructure(memory, in value, windowsLayout: true);
            return (value, Pkcs11Marshal.ReadStructure<T>(memory, windowsLayout: true));
        }
        finally
        {
            Marshal.FreeHGlobal(memory);
        }
    }

    private static TResult Invoke<TResult>(string method, Type type)
        => (TResult)typeof(WindowsLayoutRoundTripTests).GetMethod(method, BindingFlags.NonPublic | BindingFlags.Static)!
            .MakeGenericMethod(type).Invoke(null, null)!;

    private static int SizeOfType(Type type)
        => (int)typeof(Unsafe).GetMethod(nameof(Unsafe.SizeOf))!.MakeGenericMethod(type).Invoke(null, null)!;
}
