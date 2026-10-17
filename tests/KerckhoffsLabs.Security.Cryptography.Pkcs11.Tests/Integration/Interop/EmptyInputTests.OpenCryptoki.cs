using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>EmptyInput over opencryptoki — thin wrapper over <see cref="EmptyInputTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class EmptyInputTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Sha256_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Sha256_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Hmac_EmptyInput_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_Hmac_EmptyInput_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable() => EmptyInputTestCases.Assert_AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable(_backend);
}
