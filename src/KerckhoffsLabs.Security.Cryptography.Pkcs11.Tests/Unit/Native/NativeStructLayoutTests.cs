using System.Reflection;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Layout guards for the native struct layer. Two kinds:
/// (1) <b>field-offset pins</b> (LP64 / Unix) — size-only checks pass even when two same-width fields
///     are transposed or padding compensates, so the pointer/length interleavings are pinned by offset;
/// (2) <b>drift guards</b> (host-independent) — reflection census ensuring every <c>CK_*</c> struct is
///     marshalable, every <c>[PackedForPkcs11]</c> struct has a matching generated <c>_Windows</c>
///     sibling, no orphan siblings exist, and <c>PackedDispatch</c> covers the whole set.
/// </summary>
public sealed class NativeStructLayoutTests
{
    private static readonly Assembly ProdAssembly = typeof(UnmanagedMemory).Assembly;
    private const string NativeNs = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native";
    private const string RawNs = NativeNs + ".RawMechanismParams";

    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    private static int Off<T>(string field) => (int)Marshal.OffsetOf<T>(field);

    private static IEnumerable<Type> CkStructs() =>
        ProdAssembly.GetTypes().Where(t =>
            t.IsValueType && !t.IsEnum &&
            (t.Namespace == NativeNs || t.Namespace == RawNs) &&
            t.Name.StartsWith("CK_", StringComparison.Ordinal) &&
            !t.Name.EndsWith("_Windows", StringComparison.Ordinal));

    private static bool IsPacked(Type t) =>
        t.GetCustomAttributes().Any(a => a.GetType().Name == "PackedForPkcs11Attribute");

    private static string[] FieldNames(Type t) =>
        t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Select(f => f.Name).ToArray();

    // === #3 — field-offset pins (LP64: CK_ULONG = 8, pointer = 8, natural align) ==========

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_GcmParams()
    {
        Assert.Equal(0, Off<CK_GCM_PARAMS>("Iv"));
        Assert.Equal(8, Off<CK_GCM_PARAMS>("IvLen"));
        Assert.Equal(16, Off<CK_GCM_PARAMS>("IvBits"));
        Assert.Equal(24, Off<CK_GCM_PARAMS>("AAD"));
        Assert.Equal(32, Off<CK_GCM_PARAMS>("AADLen"));
        Assert.Equal(40, Off<CK_GCM_PARAMS>("TagBits"));
    }

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_Ecdh1DeriveParams()
    {
        Assert.Equal(0, Off<CK_ECDH1_DERIVE_PARAMS>("Kdf"));
        Assert.Equal(8, Off<CK_ECDH1_DERIVE_PARAMS>("SharedDataLen"));
        Assert.Equal(16, Off<CK_ECDH1_DERIVE_PARAMS>("SharedData"));
        Assert.Equal(24, Off<CK_ECDH1_DERIVE_PARAMS>("PublicDataLen"));
        Assert.Equal(32, Off<CK_ECDH1_DERIVE_PARAMS>("PublicData"));
    }

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_OaepParams()
    {
        Assert.Equal(0, Off<CK_RSA_PKCS_OAEP_PARAMS>("HashAlg"));
        Assert.Equal(8, Off<CK_RSA_PKCS_OAEP_PARAMS>("Mgf"));
        Assert.Equal(16, Off<CK_RSA_PKCS_OAEP_PARAMS>("Source"));
        Assert.Equal(24, Off<CK_RSA_PKCS_OAEP_PARAMS>("SourceData"));
        Assert.Equal(32, Off<CK_RSA_PKCS_OAEP_PARAMS>("SourceDataLen"));
    }

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_CcmParams()
    {
        Assert.Equal(0, Off<CK_CCM_PARAMS>("DataLen"));
        Assert.Equal(8, Off<CK_CCM_PARAMS>("Nonce"));
        Assert.Equal(16, Off<CK_CCM_PARAMS>("NonceLen"));
        Assert.Equal(24, Off<CK_CCM_PARAMS>("AAD"));
        Assert.Equal(32, Off<CK_CCM_PARAMS>("AADLen"));
        Assert.Equal(40, Off<CK_CCM_PARAMS>("MACLen"));
    }

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_EddsaParams()
    {
        // PhFlag is a 1-byte BOOL; the following CK_ULONG re-aligns to offset 8.
        Assert.Equal(0, Off<CK_EDDSA_PARAMS>("PhFlag"));
        Assert.Equal(8, Off<CK_EDDSA_PARAMS>("ContextDataLen"));
        Assert.Equal(16, Off<CK_EDDSA_PARAMS>("ContextData"));
    }

    // === #2 — census / drift guards (host-independent) ====================================

    [Fact]
    public void EveryCkStruct_IsMarshalable()
    {
        var failures = new List<string>();
        foreach (var t in CkStructs())
        {
            try
            {
                if (Marshal.SizeOf(t) <= 0)
                    failures.Add($"{t.Name}: size <= 0");
            }
            catch (Exception ex)
            {
                failures.Add($"{t.Name}: {ex.GetType().Name}");
            }
        }

        Assert.True(failures.Count == 0, "Non-marshalable CK_* structs: " + string.Join(", ", failures));
    }

    [Fact]
    public void EveryPackedStruct_HasWindowsSiblingWithMatchingFields()
    {
        var packed = CkStructs().Where(IsPacked).ToList();
        Assert.NotEmpty(packed); // sanity: the reflection filter actually finds the packed set

        var failures = new List<string>();
        foreach (var t in packed)
        {
            var sibling = ProdAssembly.GetType(t.FullName + "_Windows");
            if (sibling is null)
            {
                failures.Add($"{t.Name}: no _Windows sibling generated");
                continue;
            }

            var unified = FieldNames(t).ToHashSet();
            var win = FieldNames(sibling).ToHashSet();
            if (!unified.SetEquals(win))
            {
                string missing = string.Join(",", unified.Except(win));
                string extra = string.Join(",", win.Except(unified));
                failures.Add($"{t.Name}: field mismatch (sibling missing [{missing}], extra [{extra}])");
            }
        }

        Assert.True(failures.Count == 0, string.Join("; ", failures));
    }

    [Fact]
    public void NoOrphan_WindowsSiblings()
    {
        var siblings = ProdAssembly.GetTypes().Where(t =>
            t.IsValueType &&
            (t.Namespace == NativeNs || t.Namespace == RawNs) &&
            t.Name.EndsWith("_Windows", StringComparison.Ordinal)).ToList();

        // Exactly one sibling per [PackedForPkcs11] struct, and every sibling traces back to one.
        Assert.Equal(CkStructs().Count(IsPacked), siblings.Count);

        foreach (var s in siblings)
        {
            string originName = s.FullName![..^"_Windows".Length];
            var origin = ProdAssembly.GetType(originName);
            Assert.True(origin is not null && IsPacked(origin), $"orphan sibling {s.Name} (no [PackedForPkcs11] origin)");
        }
    }

    [Fact]
    public void PackedDispatch_SizeOfWindows_CoversEveryPackedStruct()
    {
        var method = typeof(PackedDispatch).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Single(m => m.Name == "SizeOfWindows" && m.IsGenericMethodDefinition && m.GetParameters().Length == 0);

        var failures = new List<string>();
        foreach (var t in CkStructs().Where(IsPacked))
        {
            try
            {
                int dispatched = (int)method.MakeGenericMethod(t).Invoke(null, null)!;
                int expected = Marshal.SizeOf(ProdAssembly.GetType(t.FullName + "_Windows")!);
                if (dispatched != expected)
                    failures.Add($"{t.Name}: dispatch {dispatched} != sibling {expected}");
            }
            catch (Exception ex)
            {
                failures.Add($"{t.Name}: {ex.InnerException?.GetType().Name ?? ex.GetType().Name}");
            }
        }

        Assert.True(failures.Count == 0, string.Join("; ", failures));
    }
}
