using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>Cross-backend port of the SoftHSM2 EdDSA sign tests, run against tpm2-pkcs11. The shared
/// <see cref="SignEdDsaTestCases"/> assertions gate on the live mechanism list via
/// <c>IPkcs11Backend.RequireMechanism</c>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class SignEdDsaTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Ed25519_RoundTrip() => SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Ed448_RoundTrip() => SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
}
