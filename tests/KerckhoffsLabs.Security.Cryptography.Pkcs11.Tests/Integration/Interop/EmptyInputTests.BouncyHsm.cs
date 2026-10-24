using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>EmptyInput over BouncyHsm — thin wrapper over <see cref="EmptyInputTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class EmptyInputTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.EmptyDigestAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm answers a digest of empty data with CKR_DATA_LEN_RANGE")]
    public void Sha256_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Sha256_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Hmac_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Hmac_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable(_backend);
}
