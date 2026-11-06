using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>Every documentation example on Craton HSM — see <see cref="ExampleCatalog"/>.</summary>
[Collection("CratonHsm")]
public sealed class ExamplesTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(ExampleCatalog.Names), MemberType = typeof(ExampleCatalog))]
    public void Example_Runs(string name) => ExampleRunner.Run(_backend, ExampleBackend.CratonHsm, name);
}
