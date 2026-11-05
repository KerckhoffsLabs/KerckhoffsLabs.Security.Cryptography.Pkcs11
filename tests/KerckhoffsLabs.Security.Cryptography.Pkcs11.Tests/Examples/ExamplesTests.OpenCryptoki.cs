using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>Every documentation example on opencryptoki — see <see cref="ExampleCatalog"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class ExamplesTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ExampleCatalog.Names), MemberType = typeof(ExampleCatalog))]
    public void Example_Runs(string name) => ExampleRunner.Run(_backend, ExampleBackend.OpenCryptoki, name);
}
