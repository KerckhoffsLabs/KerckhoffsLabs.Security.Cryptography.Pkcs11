using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Cross-backend port of the SoftHSM2 EdDSA sign tests, run against wolfPKCS11. The shared
/// <see cref="SignEdDsaTestCases"/> assertions gate on the live mechanism list via
/// <c>IPkcs11Backend.RequireMechanism</c>.</summary>
[Collection("WolfPkcs11")]
public sealed class SignEdDsaTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Ed25519_RoundTrip() => SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Ed448_RoundTrip() => SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
}
