using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary><see cref="CryptoPolicy.NistApproved"/> over tpm2-pkcs11 — thin wrapper over <see cref="NistApprovedPolicyTestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class NistApprovedPolicyTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void AesGcm_RoundTrips() =>
        NistApprovedPolicyTestCases.Assert_AesGcm_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#921: key pairs can only be token objects")]
    public void RsaPss_Signs() =>
        NistApprovedPolicyTestCases.Assert_RsaPss_Signs(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void ChaCha20Poly1305_IsRefused_BeforeTheToken() =>
        NistApprovedPolicyTestCases.Assert_ChaCha20Poly1305_IsRefused_BeforeTheToken(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#921: key pairs can only be token objects")]
    public void RsaPkcs1v15Encryption_IsRefused() =>
        NistApprovedPolicyTestCases.Assert_RsaPkcs1v15Encryption_IsRefused(_backend);
}
