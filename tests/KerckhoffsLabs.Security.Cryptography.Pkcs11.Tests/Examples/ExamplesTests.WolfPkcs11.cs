using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>Every documentation example on WolfPkcs11 — see <see cref="ExampleCatalog"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class ExamplesTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(ExampleCatalog.Names), MemberType = typeof(ExampleCatalog))]
    public void Example_Runs(string name) => ExampleRunner.Run(_backend, ExampleBackend.WolfPkcs11, name);
}
