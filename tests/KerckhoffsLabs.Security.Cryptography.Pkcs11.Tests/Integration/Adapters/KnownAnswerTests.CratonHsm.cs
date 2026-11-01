using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// The same fixed-vector known-answer tests, re-run against another real backend (Craton HSM). A
/// second (third, fourth, ...) independent implementation reproducing the identical published
/// RFC/NIST vectors is the strongest cross-backend check: a parameter/key mis-encoding the wrapper
/// and one token happen to share would still have to be reproduced bit-for-bit by an unrelated
/// token. The shared <see cref="KnownAnswerTestCases"/> assertions (defined in
/// KnownAnswerTests.cs) take an <c>IPkcs11Backend</c>, which this fixture is.
/// </summary>
[Collection("CratonHsm")]
public sealed class KnownAnswerTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;
    public static bool CratonHsmAvailable => CratonHsmBackendFixture.CratonHsmAvailable;
    // ChaCha20-Poly1305 support is not a build-time fact here: the assertion skips through
    // RequireMechanism when the token's mechanism list lacks it.
    public static bool CratonHsmAvailableWithChaCha20Poly1305 => CratonHsmAvailable;

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void AesGcm_Kat() => KnownAnswerTestCases.Assert_AesGcm_Kat(_backend);

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void AesGcm_Multipart_Kat() => KnownAnswerTestCases.Assert_AesGcm_Multipart_Kat(_backend);

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void HmacSha256_Kat() => KnownAnswerTestCases.Assert_HmacSha256_Kat(_backend);

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void Ed25519_Kat() => KnownAnswerTestCases.Assert_Ed25519_Kat(_backend);

    [Fact(SkipUnless = nameof(CratonHsmAvailableWithChaCha20Poly1305), Skip = "Requires " + nameof(CratonHsmAvailableWithChaCha20Poly1305))]
    public void ChaCha20Poly1305_Kat() => KnownAnswerTestCases.Assert_ChaCha20Poly1305_Kat(_backend);

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void HmacSha384_Kat() => KnownAnswerTestCases.Assert_HmacSha384_Kat(_backend);

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void HmacSha512_Kat() => KnownAnswerTestCases.Assert_HmacSha512_Kat(_backend);

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void AesKeyWrap_Kat() => KnownAnswerTestCases.Assert_AesKeyWrap_Kat(_backend);

    // No RsaOaep_Kat: its vector is OAEP with SHA-1, which Craton HSM refuses with CKR_MECHANISM_PARAM_INVALID
    // (parse_oaep_hash, src/pkcs11_abi/functions.rs).

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void RsaPss_Kat() => KnownAnswerTestCases.Assert_RsaPss_Kat(_backend);

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void EcdsaP256_Kat() => KnownAnswerTestCases.Assert_EcdsaP256_Kat(_backend);

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void EcdhP256_Kat() => KnownAnswerTestCases.Assert_EcdhP256_Kat(_backend);

    [Theory(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    [MemberData(nameof(KnownAnswerTestCases.AesKeyBits), MemberType = typeof(KnownAnswerTestCases))]
    public void AesEcb_Sp80038a_Kat(int keyBits) { _backend.RequireMechanism(CKM.CKM_AES_ECB); KnownAnswerTestCases.Assert_AesEcb_Sp80038a_Kat(_backend, keyBits); }

    [Theory(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    [MemberData(nameof(KnownAnswerTestCases.AesKeyBits), MemberType = typeof(KnownAnswerTestCases))]
    public void AesCbc_Sp80038a_Kat(int keyBits) { _backend.RequireMechanism(CKM.CKM_AES_CBC); KnownAnswerTestCases.Assert_AesCbc_Sp80038a_Kat(_backend, keyBits); }

    [Theory(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    [MemberData(nameof(KnownAnswerTestCases.AesKeyBits), MemberType = typeof(KnownAnswerTestCases))]
    public void AesCtr_Sp80038a_Kat(int keyBits) { _backend.RequireMechanism(CKM.CKM_AES_CTR); KnownAnswerTestCases.Assert_AesCtr_Sp80038a_Kat(_backend, keyBits); }

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void TripleDesEcb_Kat() { _backend.RequireMechanism(CKM.CKM_DES3_ECB); KnownAnswerTestCases.Assert_TripleDesEcb_Kat(_backend); }

    [Fact(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    public void TripleDesCbc_Kat() { _backend.RequireMechanism(CKM.CKM_DES3_CBC); KnownAnswerTestCases.Assert_TripleDesCbc_Kat(_backend); }

    [Theory(SkipUnless = nameof(CratonHsmAvailable), Skip = "Requires " + nameof(CratonHsmAvailable))]
    [MemberData(nameof(KnownAnswerTestCases.DesVariableKeyRounds), MemberType = typeof(KnownAnswerTestCases))]
    public void DesEcb_Sp80020_Kat(string key, string ciphertext) { _backend.RequireMechanism(CKM.CKM_DES_ECB); KnownAnswerTestCases.Assert_DesEcb_Sp80020_Kat(_backend, key, ciphertext); }
}
