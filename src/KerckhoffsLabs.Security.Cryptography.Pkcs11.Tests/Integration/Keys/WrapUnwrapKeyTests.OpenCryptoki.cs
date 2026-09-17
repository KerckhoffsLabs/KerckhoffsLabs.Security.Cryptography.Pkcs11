using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 key wrap/unwrap integration tests, run against opencryptoki.
/// Each case runs across every <see cref="CKM"/> AES key-wrap variant and skips the ones opencryptoki's
/// soft token doesn't advertise.</summary>
[Collection("OpenCryptoki")]
public sealed class WrapUnwrapKeyTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [InlineData(CKM.CKM_AES_KEY_WRAP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PKCS7)]
    public void AesKeyWrap_RoundTrip(CKM wrapMechanism)
    {
        _backend.RequireMechanism(wrapMechanism);
        WrapUnwrapKeyTestCases.Assert_AesKeyWrap_RoundTrip(_backend, wrapMechanism);
    }

    // The secure-defaults unwrap cases (Unwrap_AppliesSecureDefaults /
    // Unwrap_ExplicitExtractable_RequiresAllowInsecure) are not ported here: opencryptoki's C_UnwrapKey
    // rejects the minimal-usage unwrap template they use (CLASS/KEY_TYPE/TOKEN + injected
    // SENSITIVE/EXTRACTABLE) with CKR_ATTRIBUTE_READ_ONLY, where SoftHSM accepts it. Those cases verify
    // the library's secure-default *injection* (backend-independent logic), which stays covered on
    // SoftHSM and the managed mock (UnwrapSecureDefaultsTests.Pkcs11Mock). The real wrap/unwrap data
    // path on opencryptoki is exercised by AesKeyWrap_RoundTrip above.
}
