using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 key wrap/unwrap integration tests, run against BouncyHsm.
/// Each case runs across every <see cref="CKM"/> AES key-wrap variant and skips the ones BouncyHsm
/// doesn't advertise (all but CKM_AES_KEY_WRAP_PAD).</summary>
[Collection("BouncyHsm")]
public sealed class WrapUnwrapKeyTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData(CKM.CKM_AES_KEY_WRAP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PKCS7)]
    public void AesKeyWrap_RoundTrip(CKM wrapMechanism)
    {
        _backend.RequireMechanism(wrapMechanism);
        WrapUnwrapKeyTestCases.Assert_AesKeyWrap_RoundTrip(_backend, wrapMechanism);
    }


    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData(CKM.CKM_AES_KEY_WRAP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PKCS7)]
    public void Unwrap_AppliesSecureDefaults(CKM wrapMechanism)
    {
        _backend.RequireMechanism(wrapMechanism);
        // BouncyHsm refuses to wrap a key whose CKA_EXTRACTABLE is FALSE with CKR_KEY_NOT_WRAPPABLE
        // (WrapKeyHandler.CheckExtractable), where PKCS#11 has CKR_KEY_UNEXTRACTABLE. The key still
        // does not leave the token; pinned, so a fix upstream fails here and the default can take over.
        WrapUnwrapKeyTestCases.Assert_Unwrap_AppliesSecureDefaults(_backend, wrapMechanism, CKR.CKR_KEY_NOT_WRAPPABLE);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData(CKM.CKM_AES_KEY_WRAP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PKCS7)]
    public void Unwrap_ExplicitExtractable_IsAllowed(CKM wrapMechanism)
    {
        _backend.RequireMechanism(wrapMechanism);
        WrapUnwrapKeyTestCases.Assert_Unwrap_ExplicitExtractable_IsAllowed(_backend, wrapMechanism);
    }

    // BouncyHsm takes the curve from the template's CKA_EC_PARAMS, not from the PKCS#8, and refuses an unwrap
    // without it with CKR_ATTRIBUTE_VALUE_INVALID (UnwrapKeyHandler.SetKeyvalueForEcdsaPrivateKeyObject).
    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Unwrap_EcPrivateKeyWithoutPublicPoint_Signs() => WrapUnwrapKeyTestCases.Assert_Unwrap_EcPrivateKeyWithoutPublicPoint_Signs(_backend, ecParamsInTemplate: true);
}
