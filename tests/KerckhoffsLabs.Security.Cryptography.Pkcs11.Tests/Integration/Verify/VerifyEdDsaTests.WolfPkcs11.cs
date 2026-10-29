using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>Cross-backend port of the SoftHSM2 EdDSA verify test, run against wolfPKCS11.</summary>
[Collection("WolfPkcs11")]
public sealed class VerifyEdDsaTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Ed25519_RejectsTamperedData() => VerifyEdDsaTestCases.Assert_Ed25519_RejectsTamperedData(_backend);
}
