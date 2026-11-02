using System.Reflection;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Examples;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>Every adapter has a documentation example, and every example is catalogued and runs somewhere.</summary>
public sealed class ExampleCoverageTests
{
    private static IEnumerable<Type> Adapters() =>
        typeof(RSAPkcs11).Assembly.GetExportedTypes()
            .Where(t => t.Namespace == typeof(RSAPkcs11).Namespace && t != typeof(Pkcs11MechanismMap));

    private static HashSet<string> Documented() =>
        [.. ExampleCatalog.All.SelectMany(c => c.Covers).Select(t => t.Name)];

    [Fact]
    public void EveryAdapter_HasAnExample()
    {
        HashSet<string> documented = Documented();
        string[] missing = [.. Adapters().Select(t => t.Name).Where(n => !documented.Contains(n))];
        Assert.True(missing.Length == 0, $"Adapters with no documentation example: {string.Join(", ", missing)}.");
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
