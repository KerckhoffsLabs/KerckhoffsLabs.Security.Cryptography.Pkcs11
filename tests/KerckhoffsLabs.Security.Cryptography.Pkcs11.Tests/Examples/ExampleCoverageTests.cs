using System.Reflection;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>Every adapter has a documentation example, and every example is catalogued and runs somewhere.</summary>
public sealed class ExampleCoverageTests
{
    // Adapters whose example family has not been written yet, by type name (names, not typeof, because
    // the legacy adapters are [Obsolete] and SlhDsaPkcs11 is [Experimental]). Each family's change removes its own; the list ends empty.
    internal static readonly HashSet<string> NotYetDocumented = new(StringComparer.Ordinal)
    {
        nameof(MLKemPkcs11), nameof(MLDsaPkcs11), "SlhDsaPkcs11",
        nameof(SHA256Pkcs11), nameof(SHA384Pkcs11), nameof(SHA512Pkcs11),
        nameof(SHA3_256Pkcs11), nameof(SHA3_384Pkcs11), nameof(SHA3_512Pkcs11), nameof(HMACPkcs11),
        nameof(HkdfPkcs11), nameof(Rfc2898DeriveBytesPkcs11), nameof(SP800108HmacCounterKdfPkcs11),
        nameof(Pkcs11CertificateExtensions),
        "DESPkcs11", "TripleDESPkcs11", "RC2Pkcs11", "DSAPkcs11", "MD5Pkcs11", "SHA1Pkcs11",
    };

    private static IEnumerable<Type> Adapters() =>
        typeof(RSAPkcs11).Assembly.GetExportedTypes()
            .Where(t => t.Namespace == typeof(RSAPkcs11).Namespace && t != typeof(Pkcs11MechanismMap));

    private static HashSet<string> Documented() =>
        [.. ExampleCatalog.All.SelectMany(c => c.Covers).Select(t => t.Name)];

    [Fact]
    public void EveryAdapter_HasAnExample_OrIsListedAsPending()
    {
        HashSet<string> documented = Documented();
        string[] missing = [.. Adapters().Select(t => t.Name).Where(n => !documented.Contains(n) && !NotYetDocumented.Contains(n))];
        Assert.True(missing.Length == 0, $"Adapters with no documentation example: {string.Join(", ", missing)}.");
    }

    [Fact]
    public void PendingList_HasNoDocumentedAdapter()
    {
        string[] stale = [.. NotYetDocumented.Where(Documented().Contains)];
        Assert.True(stale.Length == 0, $"Remove from NotYetDocumented, they now have examples: {string.Join(", ", stale)}.");
    }

    [Fact]
    public void PendingList_NamesOnlyRealAdapters()
    {
        HashSet<string> adapters = [.. Adapters().Select(t => t.Name)];
        string[] unknown = [.. NotYetDocumented.Where(n => !adapters.Contains(n))];
        Assert.True(unknown.Length == 0, $"Not adapters: {string.Join(", ", unknown)}.");
    }

    [Fact]
    public void EveryExampleMethod_HasACatalogEntry()
    {
        string[] methods = [.. typeof(GettingStartedExamples).Assembly.GetExportedTypes()
            .Where(t => t is { IsAbstract: true, IsSealed: true } && t.Name.EndsWith("Examples", StringComparison.Ordinal))
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(m => $"{t.Name}.{m.Name}"))
            .Order(StringComparer.Ordinal)];
        string[] catalogued = [.. ExampleCatalog.All.Select(c => c.Name).Order(StringComparer.Ordinal)];
        Assert.Equal(methods, catalogued);
    }

    [Fact]
    public void EveryCase_MustRunSomewhere() =>
        Assert.All(ExampleCatalog.All, c => Assert.True(c.MustRunOn != 0, $"{c.Name} names no backend it must run on."));
}
