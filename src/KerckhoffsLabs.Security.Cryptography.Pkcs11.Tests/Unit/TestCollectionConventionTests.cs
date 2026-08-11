using System.Reflection;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Guards the assembly's test-parallelization contract (see <c>Support/TestParallelization.cs</c>).
/// Classes run in parallel unless an xUnit <c>[Collection]</c> serializes them, and every real
/// backend — pkcs11-mock above all, which is single-session and process-global — is owned by one
/// collection. A backend test class that forgets its <c>[Collection]</c> compiles, runs, and
/// usually passes; it corrupts shared native state only when the scheduler happens to overlap it
/// with the collection that owns the module. These tests turn that intermittent failure into a
/// deterministic one at the moment the class is added.
/// </summary>
public sealed class TestCollectionConventionTests
{
    private static readonly Assembly TestAssembly = typeof(TestCollectionConventionTests).Assembly;

    private const string IntegrationNamespace =
        "KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.";

    /// <summary>
    /// Class-name suffix → the collection that class must join. The suite names every
    /// backend-bound class after its backend, so the suffix is a reliable statement of intent
    /// even when the class reaches the module through a helper rather than an injected fixture.
    /// </summary>
    private static readonly (string Suffix, string Collection)[] BackendNameSuffixes =
    [
        ("_Mock", "Mock"),
        ("_SoftHsm", "SoftHsm"),
        ("_Nss", "Nss"),
        ("_OpenCryptoki", "OpenCryptoki"),
    ];

    // -----------------------------------------------------------------------------------------
    // Rules
    // -----------------------------------------------------------------------------------------

    /// <summary>
    /// Every test class under <c>Integration/</c> either joins a backend collection or says in
    /// writing why it needs none. Silence is not an accepted answer — that is the whole point.
    /// </summary>
    [Fact]
    public void EveryIntegrationTestClass_DeclaresACollectionOrAnExplicitOptOut()
    {
        var offenders = new List<string>();

        foreach (Type type in TestClasses().Where(t => t.Namespace?.StartsWith(IntegrationNamespace, StringComparison.Ordinal) == true))
        {
            string? collection = CollectionOf(type);
            var optOut = type.GetCustomAttribute<NoBackendCollectionAttribute>();

            if (collection is null && optOut is null)
            {
                offenders.Add(
                    $"{type.FullName}: no [Collection(...)] and no [NoBackendCollection(reason)]. " +
                    "Join the collection that owns the backend it drives, or state why it drives none.");
            }
            else if (collection is not null && optOut is not null)
            {
                offenders.Add(
                    $"{type.FullName}: carries both [Collection(\"{collection}\")] and " +
                    "[NoBackendCollection] — the opt-out contradicts the collection. Drop one.");
            }
            else if (optOut is not null && string.IsNullOrWhiteSpace(optOut.Reason))
            {
                offenders.Add($"{type.FullName}: [NoBackendCollection] with an empty reason.");
            }
        }

        AssertNoOffenders(offenders);
    }

    /// <summary>
    /// A class named after a backend must be in that backend's collection. This catches the
    /// omission anywhere in the assembly — including the <c>Algorithms/</c> suites, whose
    /// backend-bound classes carry the same suffixes and the same process-global exposure.
    /// </summary>
    [Fact]
    public void EveryBackendNamedTestClass_JoinsThatBackendsCollection()
    {
        var offenders = new List<string>();

        foreach (Type type in TestClasses())
        {
            foreach ((string suffix, string required) in BackendNameSuffixes)
            {
                if (!type.Name.EndsWith(suffix, StringComparison.Ordinal)) continue;

                string? collection = CollectionOf(type);
                if (collection != required)
                {
                    offenders.Add(
                        $"{type.FullName}: named for the {required} backend but " +
                        (collection is null
                            ? "declares no [Collection]"
                            : $"joins [Collection(\"{collection}\")]") +
                        $". It must be [Collection(\"{required}\")].");
                }
            }
        }

        AssertNoOffenders(offenders);
    }

    /// <summary>
    /// A class that injects a collection fixture must be in a collection that supplies it. xUnit
    /// reports the mismatch at run time as an unresolved constructor parameter, but only for the
    /// classes that happen to execute; this reports it for all of them, always.
    /// </summary>
    [Fact]
    public void EveryInjectedCollectionFixture_IsSuppliedByTheDeclaredCollection()
    {
        Dictionary<Type, List<string>> providers = CollectionFixtureProviders();
        var offenders = new List<string>();

        foreach (Type type in TestClasses())
        {
            string? collection = CollectionOf(type);

            foreach (ParameterInfo parameter in type.GetConstructors().SelectMany(c => c.GetParameters()))
            {
                if (!providers.TryGetValue(parameter.ParameterType, out List<string>? supplying)) continue;

                if (collection is null || !supplying.Contains(collection))
                {
                    offenders.Add(
                        $"{type.FullName}: takes {parameter.ParameterType.Name} but " +
                        (collection is null
                            ? "declares no [Collection]"
                            : $"joins [Collection(\"{collection}\")]") +
                        $". That fixture is supplied by: {string.Join(", ", supplying)}.");
                }
            }
        }

        AssertNoOffenders(offenders);
    }

    /// <summary>
    /// Every <c>[Collection("name")]</c> resolves to a real <c>[CollectionDefinition("name")]</c>.
    /// A typo silently creates a brand-new, fixture-less collection instead of joining the
    /// intended one — the same race, wearing an attribute.
    /// </summary>
    [Fact]
    public void EveryDeclaredCollection_ResolvesToACollectionDefinition()
    {
        HashSet<string> defined = [.. DefinedCollections()];
        var offenders = new List<string>();

        foreach (Type type in TestClasses())
        {
            string? collection = CollectionOf(type);
            if (collection is not null && !defined.Contains(collection))
                offenders.Add($"{type.FullName}: [Collection(\"{collection}\")] has no matching [CollectionDefinition].");
        }

        AssertNoOffenders(offenders);
    }

    /// <summary>
    /// Anti-vacuity guard for the four rules above: they are only worth anything if the reflection
    /// underneath them actually sees the suite. Every rule iterates <see cref="TestClasses"/> and
    /// most of the backend classes declare nothing but <c>[ConditionalFact]</c>, so a change that
    /// stopped resolving Fact-derived attributes — or an empty fixture map — would turn all four
    /// green while guarding nothing.
    /// </summary>
    [Fact]
    public void TheRulesAbove_ActuallySeeTheSuiteTheyGuard()
    {
        List<Type> classes = [.. TestClasses()];

        Assert.Contains(typeof(Integration.Digest.DigestMd5Sha1Tests_SoftHsm), classes); // [ConditionalFact] only
        Assert.Contains(typeof(Integration.Smoke.SoftHsmAvailabilityTests), classes);    // [Fact] only
        Assert.True(classes.Count > 100, $"Only {classes.Count} test classes discovered — the suite is far larger.");

        Dictionary<Type, List<string>> providers = CollectionFixtureProviders();
        Assert.Equal(["Mock"], providers[typeof(Support.Fixtures.MockBackendFixture)]);
    }

    // -----------------------------------------------------------------------------------------
    // Reflection helpers
    // -----------------------------------------------------------------------------------------

    /// <summary>Concrete classes that declare at least one xUnit test method.</summary>
    private static IEnumerable<Type> TestClasses() =>
        TestAssembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false })
            .Where(HasTestMethods)
            .OrderBy(t => t.FullName, StringComparer.Ordinal);

    /// <summary>
    /// True when the type declares a method carrying <c>[Fact]</c> or anything derived from it —
    /// which covers <c>[Theory]</c> and the <c>[Conditional*]</c> variants this suite leans on.
    /// </summary>
    private static bool HasTestMethods(Type type) =>
        type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
            .Any(m => m.GetCustomAttributes(typeof(FactAttribute), inherit: true).Length != 0);

    private static string? CollectionOf(Type type) =>
        AttributeName(type, typeof(CollectionAttribute));

    private static IEnumerable<string> DefinedCollections() =>
        TestAssembly.GetTypes()
            .Select(t => AttributeName(t, typeof(CollectionDefinitionAttribute)))
            .OfType<string>();

    /// <summary>
    /// Reads the collection name off <c>[Collection]</c> / <c>[CollectionDefinition]</c>. xUnit v2
    /// exposes the name only as a constructor argument — neither attribute surfaces it as a
    /// property — so this goes through <see cref="CustomAttributeData"/> rather than a live
    /// attribute instance.
    /// </summary>
    private static string? AttributeName(Type type, Type attributeType) =>
        type.GetCustomAttributesData()
            .Where(a => a.AttributeType == attributeType)
            .SelectMany(a => a.ConstructorArguments)
            .Select(a => a.Value as string)
            .FirstOrDefault(n => !string.IsNullOrEmpty(n));

    /// <summary>
    /// Fixture type → the collection names whose <c>[CollectionDefinition]</c> declares
    /// <c>ICollectionFixture&lt;T&gt;</c> for it.
    /// </summary>
    private static Dictionary<Type, List<string>> CollectionFixtureProviders()
    {
        var providers = new Dictionary<Type, List<string>>();

        foreach (Type definition in TestAssembly.GetTypes())
        {
            string? name = AttributeName(definition, typeof(CollectionDefinitionAttribute));
            if (name is null) continue;

            foreach (Type fixtureInterface in definition.GetInterfaces()
                         .Where(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(ICollectionFixture<>)))
            {
                Type fixtureType = fixtureInterface.GetGenericArguments()[0];
                if (!providers.TryGetValue(fixtureType, out List<string>? names))
                    providers[fixtureType] = names = [];
                names.Add(name);
            }
        }

        return providers;
    }

    private static void AssertNoOffenders(List<string> offenders) =>
        Assert.True(offenders.Count == 0, string.Join(Environment.NewLine, ["", .. offenders]));
}
