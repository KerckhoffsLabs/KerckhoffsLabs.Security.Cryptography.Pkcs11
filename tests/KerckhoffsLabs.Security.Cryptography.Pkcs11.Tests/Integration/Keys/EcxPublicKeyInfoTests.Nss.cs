using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// The RFC 8410 SubjectPublicKeyInfo of Edwards and Montgomery keys over NSS softoken -- thin wrapper over
/// <see cref="EcxPublicKeyInfoTestCases"/>.
/// </summary>
[Collection("Nss")]
public sealed class EcxPublicKeyInfoTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [InlineData(EcxCurve.Ed25519)]
    [InlineData(EcxCurve.Ed448)]
    [InlineData(EcxCurve.X25519)]
    [InlineData(EcxCurve.X448)]
    public void PublicKeyInfo_IsRfc8410(EcxCurve curve) => EcxPublicKeyInfoTestCases.Assert_PublicKeyInfo_IsRfc8410(_backend, curve);
}
