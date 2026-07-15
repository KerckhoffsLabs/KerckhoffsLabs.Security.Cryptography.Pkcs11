using System.Reflection;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

// Naming each obsolete API is the whole point of this file, so every id it pins is suppressed here
// — a live demonstration of the per-id suppression the scheme exists to enable.
#pragma warning disable KLPKCS11001 // MD5
#pragma warning disable KLPKCS11002 // SHA-1
#pragma warning disable KLPKCS11003 // DES
#pragma warning disable KLPKCS11004 // Triple-DES
#pragma warning disable KLPKCS11005 // RC2
#pragma warning disable KLPKCS11006 // DSA
#pragma warning disable KLPKCS11007 // weak EC curves

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The obsoletion diagnostic ids are a public contract: consumers write them into
/// <c>#pragma warning disable</c> / <c>NoWarn</c>, so an id that silently changes (or goes
/// missing) breaks their build or, worse, silently un-suppresses. These tests pin every id to its
/// type and assert the whole obsolete surface carries one, with a documentation URL.
/// </summary>
public sealed class ObsoleteDiagnosticIdTests
{
    public static TheoryData<Type, string> ObsoleteFacades => new()
    {
        { typeof(MD5Pkcs11), "KLPKCS11001" },
        { typeof(SHA1Pkcs11), "KLPKCS11002" },
        { typeof(DESPkcs11), "KLPKCS11003" },
        { typeof(TripleDESPkcs11), "KLPKCS11004" },
        { typeof(RC2Pkcs11), "KLPKCS11005" },
        { typeof(DSAPkcs11), "KLPKCS11006" },
    };

    [Theory]
    [MemberData(nameof(ObsoleteFacades))]
    public void LegacyFacade_CarriesItsPinnedDiagnosticId(Type type, string expectedId)
    {
        var obsolete = type.GetCustomAttribute<ObsoleteAttribute>();

        Assert.NotNull(obsolete);
        Assert.Equal(expectedId, obsolete!.DiagnosticId);
        Assert.Equal(
            "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#{0}",
            obsolete.UrlFormat);
    }

    [Theory]
    [InlineData(nameof(ECCurve.NamedCurves.NistP192))]
    [InlineData(nameof(ECCurve.NamedCurves.NistP224))]
    [InlineData(nameof(ECCurve.NamedCurves.Secp192k1))]
    [InlineData(nameof(ECCurve.NamedCurves.Secp224k1))]
    [InlineData(nameof(ECCurve.NamedCurves.BrainpoolP160r1))]
    [InlineData(nameof(ECCurve.NamedCurves.BrainpoolP160t1))]
    [InlineData(nameof(ECCurve.NamedCurves.BrainpoolP192r1))]
    [InlineData(nameof(ECCurve.NamedCurves.BrainpoolP192t1))]
    [InlineData(nameof(ECCurve.NamedCurves.BrainpoolP224r1))]
    [InlineData(nameof(ECCurve.NamedCurves.BrainpoolP224t1))]
    public void WeakCurve_CarriesTheWeakCurveDiagnosticId(string curveName)
    {
        PropertyInfo? curve = typeof(ECCurve.NamedCurves)
            .GetProperty(curveName, BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(curve);

        var obsolete = curve!.GetCustomAttribute<ObsoleteAttribute>();

        Assert.NotNull(obsolete);
        Assert.Equal("KLPKCS11007", obsolete!.DiagnosticId);
    }

    // Guards the inverse: a newly-obsoleted public API must not ship with a bare [Obsolete], which
    // would force consumers back to the blanket CS0618 suppression this scheme exists to avoid.
    [Fact]
    public void EveryPublicObsoletion_HasADiagnosticIdAndUrl()
    {
        Assembly library = typeof(Pkcs11Library).Assembly;

        var offenders = library.GetExportedTypes()
            .SelectMany(t => t.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
                .Cast<MemberInfo>()
                .Append(t))
            .Distinct()
            // Only what this library declares: members inherited from BCL bases (e.g. the framework's
            // own obsoletion of Enum.ToString(string)) carry ids we neither own nor control.
            .Where(m => (m as Type ?? m.DeclaringType)?.Assembly == library)
            .Select(m => (Member: m, Obsolete: m.GetCustomAttribute<ObsoleteAttribute>(inherit: false)))
            .Where(x => x.Obsolete is not null)
            .Where(x => x.Obsolete!.DiagnosticId is null || x.Obsolete.UrlFormat is null)
            .Select(x => $"{(x.Member as Type)?.Name ?? $"{x.Member.DeclaringType?.Name}.{x.Member.Name}"}")
            .ToList();

        Assert.Empty(offenders);
    }
}
