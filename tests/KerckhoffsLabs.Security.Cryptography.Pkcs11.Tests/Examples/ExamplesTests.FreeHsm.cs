using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>Every documentation example on FreeHSM — see <see cref="ExampleCatalog"/>.</summary>
[Collection("FreeHsm")]
public sealed class ExamplesTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(ExampleCatalog.Names), MemberType = typeof(ExampleCatalog))]
    public void Example_Runs(string name) => ExampleRunner.Run(_backend, ExampleBackend.FreeHsm, name);
}
