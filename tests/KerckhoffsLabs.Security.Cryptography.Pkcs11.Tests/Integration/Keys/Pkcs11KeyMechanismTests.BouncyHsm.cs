using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>BouncyHsm counterpart of Pkcs11KeyMechanismTests_SoftHsm (shared Pkcs11KeyMechanismCases).</summary>
[Collection("BouncyHsm")]
public sealed class Pkcs11KeyMechanismTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaPkcs_SignVerify_RoundTrip()
    {
        using var session = OpenSession();
        Pkcs11KeyMechanismCases.Assert_RsaSignVerify_RoundTrips(session);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesCbc_EncryptDecrypt_RoundTrip()
    {
        using var session = OpenSession();
        Pkcs11KeyMechanismCases.Assert_AesCbcEncryptDecrypt_RoundTrips(session);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesKeyWrap_WrapUnwrap_RoundTrip()
    {
        _backend.RequireMechanism(CKM.CKM_AES_KEY_WRAP);
        using var session = OpenSession();
        Pkcs11KeyMechanismCases.Assert_AesKeyWrapUnwrap_RoundTrips(session);
    }
}
