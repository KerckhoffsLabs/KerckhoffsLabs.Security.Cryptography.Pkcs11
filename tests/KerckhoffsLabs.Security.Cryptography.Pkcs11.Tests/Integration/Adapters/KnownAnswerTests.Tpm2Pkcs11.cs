using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// The same fixed-vector known-answer tests, re-run against another real backend (tpm2-pkcs11). A
/// second (third, fourth, ...) independent implementation reproducing the identical published
/// RFC/NIST vectors is the strongest cross-backend check: a parameter/key mis-encoding the wrapper
/// and one token happen to share would still have to be reproduced bit-for-bit by an unrelated
/// token. The shared <see cref="KnownAnswerTestCases"/> assertions (defined in
/// KnownAnswerTests.cs) take an <c>IPkcs11Backend</c>, which this fixture is.
/// </summary>
[Collection("Tpm2Pkcs11")]
public sealed class KnownAnswerTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;
    public static bool Tpm2Pkcs11Available => Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available;
    // ChaCha20-Poly1305 support is not a build-time fact here: the assertion skips through
    // RequireMechanism when the token doesn't list it.
    public static bool Tpm2Pkcs11AvailableWithChaCha20Poly1305 => Tpm2Pkcs11Available;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void AesGcm_Kat()
    {
        Assert.SkipUnless(_backend.Supports(CKM.CKM_AES_GCM), "Backend does not advertise CKM_AES_GCM.");
        KnownAnswerTestCases.Assert_AesGcm_Kat(_backend);
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void AesGcm_Multipart_Kat()
    {
        Assert.SkipUnless(_backend.Supports(CKM.CKM_AES_GCM), "Backend does not advertise CKM_AES_GCM.");
        KnownAnswerTestCases.Assert_AesGcm_Multipart_Kat(_backend);
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.LongHmacKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "A TPM holds at most 128 bytes of key; RFC 4231 case 6 uses 131")]
    public void HmacSha256_Kat() => KnownAnswerTestCases.Assert_HmacSha256_Kat(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11Available), Skip = "Requires " + nameof(Tpm2Pkcs11Available))]
    public void Ed25519_Kat() => KnownAnswerTestCases.Assert_Ed25519_Kat(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11AvailableWithChaCha20Poly1305), Skip = "Requires " + nameof(Tpm2Pkcs11AvailableWithChaCha20Poly1305))]
    public void ChaCha20Poly1305_Kat() => KnownAnswerTestCases.Assert_ChaCha20Poly1305_Kat(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.LongHmacKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "A TPM holds at most 128 bytes of key; RFC 4231 case 6 uses 131")]
    public void HmacSha384_Kat() => KnownAnswerTestCases.Assert_HmacSha384_Kat(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.LongHmacKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "A TPM holds at most 128 bytes of key; RFC 4231 case 6 uses 131")]
    public void HmacSha512_Kat() => KnownAnswerTestCases.Assert_HmacSha512_Kat(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11Available), Skip = "Requires " + nameof(Tpm2Pkcs11Available))]
    public void AesKeyWrap_Kat() => KnownAnswerTestCases.Assert_AesKeyWrap_Kat(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.PrivateAndEcKeyImportAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 C_CreateObject makes only RSA public keys and data objects")]
    public void RsaOaep_Kat() => KnownAnswerTestCases.Assert_RsaOaep_Kat(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11Available), Skip = "Requires " + nameof(Tpm2Pkcs11Available))]
    public void RsaPss_Kat() => KnownAnswerTestCases.Assert_RsaPss_Kat(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.PrivateAndEcKeyImportAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 C_CreateObject makes only RSA public keys and data objects")]
    public void EcdsaP256_Kat() => KnownAnswerTestCases.Assert_EcdsaP256_Kat(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.PrivateAndEcKeyImportAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 C_CreateObject makes only RSA public keys and data objects")]
    public void EcdhP256_Kat() => KnownAnswerTestCases.Assert_EcdhP256_Kat(_backend);
}
