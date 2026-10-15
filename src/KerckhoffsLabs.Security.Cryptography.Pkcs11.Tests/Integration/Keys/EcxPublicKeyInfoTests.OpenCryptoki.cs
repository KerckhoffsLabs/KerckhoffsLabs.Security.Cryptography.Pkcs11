using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// The RFC 8410 SubjectPublicKeyInfo of Edwards and Montgomery keys over opencryptoki's software token -- thin wrapper over
/// <see cref="EcxPublicKeyInfoTestCases"/>.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class EcxPublicKeyInfoTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [InlineData(EcxCurve.Ed25519)]
    [InlineData(EcxCurve.Ed448)]
    [InlineData(EcxCurve.X25519)]
    [InlineData(EcxCurve.X448)]
    public void PublicKeyInfo_IsRfc8410(EcxCurve curve) => EcxPublicKeyInfoTestCases.Assert_PublicKeyInfo_IsRfc8410(_backend, curve);
}
