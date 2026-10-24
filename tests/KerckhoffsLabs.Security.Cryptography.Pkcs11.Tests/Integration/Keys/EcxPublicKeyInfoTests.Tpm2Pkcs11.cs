using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// The RFC 8410 SubjectPublicKeyInfo of Edwards and Montgomery keys over tpm2-pkcs11 -- thin wrapper over
/// <see cref="EcxPublicKeyInfoTestCases"/>.
/// </summary>
[Collection("Tpm2Pkcs11")]
public sealed class EcxPublicKeyInfoTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [InlineData(EcxCurve.Ed25519)]
    [InlineData(EcxCurve.Ed448)]
    [InlineData(EcxCurve.X25519)]
    [InlineData(EcxCurve.X448)]
    public void PublicKeyInfo_IsRfc8410(EcxCurve curve) => EcxPublicKeyInfoTestCases.Assert_PublicKeyInfo_IsRfc8410(_backend, curve);
}
