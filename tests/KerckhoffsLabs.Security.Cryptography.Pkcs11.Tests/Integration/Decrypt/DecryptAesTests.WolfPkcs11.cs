using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>AES decrypt gate tests against wolfPKCS11.</summary>
[Collection("WolfPkcs11")]
public sealed class DecryptAesTests_WolfPkcs11(WolfPkcs11BackendFixture f)
{
    private readonly WolfPkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesEcb_ThrowsCryptoPolicyViolationException_ByDefault()
        => DecryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesEcb_AllowedWhenAllowInsecureTrue()
        => DecryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesCbcPad_StreamDecrypt_LastBlockComesFromFinal()
        => DecryptAesTestCases.Assert_AesCbcPad_StreamDecrypt_LastBlockComesFromFinal(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesEcb_ThrowsCryptoPolicyViolationException_ByDefault_SoftHsm()
        => DecryptAesTestCases.Assert_AesEcb_GatedByDefault(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesEcb_AllowedWhenAllowInsecureTrue_SoftHsm()
        => DecryptAesTestCases.Assert_AesEcb_AllowedWithOptIn(_backend);
}
