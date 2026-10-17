using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>EmptyInput over SoftHsm — thin wrapper over <see cref="EmptyInputTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class EmptyInputTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Sha256_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Sha256_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Hmac_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Hmac_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable(_backend);
}
