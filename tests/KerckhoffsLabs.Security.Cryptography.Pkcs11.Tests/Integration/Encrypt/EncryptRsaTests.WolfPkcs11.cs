using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>RSA PKCS#1 v1.5 gate against wolfPKCS11.</summary>
[Collection("WolfPkcs11")]
public sealed class EncryptRsaTests_WolfPkcs11(WolfPkcs11BackendFixture f)
{
    private readonly WolfPkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RsaPkcs1V15_ThrowsCryptoPolicyViolationException_ByDefault()
        => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RsaPkcs1V15_ThrowsCryptoPolicyViolationException_ByDefault_SoftHsm()
        => EncryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
