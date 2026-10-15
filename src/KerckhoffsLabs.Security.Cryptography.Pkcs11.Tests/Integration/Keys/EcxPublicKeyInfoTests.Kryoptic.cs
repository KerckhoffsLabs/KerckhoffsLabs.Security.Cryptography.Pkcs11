using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// The RFC 8410 SubjectPublicKeyInfo of Edwards and Montgomery keys over Kryoptic -- thin wrapper over
/// <see cref="EcxPublicKeyInfoTestCases"/>.
/// </summary>
[Collection("Kryoptic")]
public sealed class EcxPublicKeyInfoTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData(EcxCurve.Ed25519)]
    [InlineData(EcxCurve.Ed448)]
    [InlineData(EcxCurve.X25519)]
    [InlineData(EcxCurve.X448)]
    public void PublicKeyInfo_IsRfc8410(EcxCurve curve) => EcxPublicKeyInfoTestCases.Assert_PublicKeyInfo_IsRfc8410(_backend, curve);
}
