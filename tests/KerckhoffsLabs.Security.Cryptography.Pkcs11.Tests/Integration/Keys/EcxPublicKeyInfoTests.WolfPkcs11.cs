using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// The RFC 8410 SubjectPublicKeyInfo of Edwards and Montgomery keys over wolfPKCS11 -- thin wrapper over
/// <see cref="EcxPublicKeyInfoTestCases"/>.
/// </summary>
[Collection("WolfPkcs11")]
public sealed class EcxPublicKeyInfoTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [InlineData(EcxCurve.Ed25519)]
    [InlineData(EcxCurve.Ed448)]
    [InlineData(EcxCurve.X25519)]
    [InlineData(EcxCurve.X448)]
    public void PublicKeyInfo_IsRfc8410(EcxCurve curve) => EcxPublicKeyInfoTestCases.Assert_PublicKeyInfo_IsRfc8410(_backend, curve);
}
