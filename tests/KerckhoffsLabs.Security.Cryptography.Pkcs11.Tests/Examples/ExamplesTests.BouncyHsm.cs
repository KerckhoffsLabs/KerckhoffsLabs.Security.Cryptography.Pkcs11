using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>Every documentation example on BouncyHsm — see <see cref="ExampleCatalog"/>.</summary>
[Collection("BouncyHsm")]
public sealed class ExamplesTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ExampleCatalog.Names), MemberType = typeof(ExampleCatalog))]
    public void Example_Runs(string name) => ExampleRunner.Run(_backend, ExampleBackend.BouncyHsm, name);
}
