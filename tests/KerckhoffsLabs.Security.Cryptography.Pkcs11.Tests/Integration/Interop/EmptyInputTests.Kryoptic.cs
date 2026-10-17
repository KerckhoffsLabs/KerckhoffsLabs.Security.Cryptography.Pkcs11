using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>EmptyInput over Kryoptic — thin wrapper over <see cref="EmptyInputTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class EmptyInputTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Sha256_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Sha256_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Hmac_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Hmac_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable(_backend);
}
