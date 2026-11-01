using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

[Collection("SoftHsm")]
public sealed class KnownAnswerTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    public static bool SoftHsmSupportsChaCha20Poly1305 => SoftHsmBackendFixture.SoftHsmSupportsChaCha20Poly1305;
    // xUnit v3's SkipUnless takes a single member, unlike v2's ConditionalFact(params string[]).
    public static bool SoftHsmAvailableWithChaCha20Poly1305 => SoftHsmAvailable && SoftHsmSupportsChaCha20Poly1305;

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void AesGcm_Kat() => KnownAnswerTestCases.Assert_AesGcm_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void AesGcm_Multipart_Kat() => KnownAnswerTestCases.Assert_AesGcm_Multipart_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void HmacSha256_Kat() => KnownAnswerTestCases.Assert_HmacSha256_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void Ed25519_Kat() => KnownAnswerTestCases.Assert_Ed25519_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailableWithChaCha20Poly1305), Skip = "Requires " + nameof(SoftHsmAvailableWithChaCha20Poly1305))]
    public void ChaCha20Poly1305_Kat() => KnownAnswerTestCases.Assert_ChaCha20Poly1305_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void HmacSha384_Kat() => KnownAnswerTestCases.Assert_HmacSha384_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void HmacSha512_Kat() => KnownAnswerTestCases.Assert_HmacSha512_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void AesKeyWrap_Kat() => KnownAnswerTestCases.Assert_AesKeyWrap_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void RsaOaep_Kat() => KnownAnswerTestCases.Assert_RsaOaep_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void RsaPss_Kat() => KnownAnswerTestCases.Assert_RsaPss_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void EcdsaP256_Kat() => KnownAnswerTestCases.Assert_EcdsaP256_Kat(_backend);

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void EcdhP256_Kat() => KnownAnswerTestCases.Assert_EcdhP256_Kat(_backend);

    [Theory(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    [MemberData(nameof(KnownAnswerTestCases.AesKeyBits), MemberType = typeof(KnownAnswerTestCases))]
    public void AesEcb_Sp80038a_Kat(int keyBits) { _backend.RequireMechanism(CKM.CKM_AES_ECB); KnownAnswerTestCases.Assert_AesEcb_Sp80038a_Kat(_backend, keyBits); }

    [Theory(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    [MemberData(nameof(KnownAnswerTestCases.AesKeyBits), MemberType = typeof(KnownAnswerTestCases))]
    public void AesCbc_Sp80038a_Kat(int keyBits) { _backend.RequireMechanism(CKM.CKM_AES_CBC); KnownAnswerTestCases.Assert_AesCbc_Sp80038a_Kat(_backend, keyBits); }

    [Theory(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    [MemberData(nameof(KnownAnswerTestCases.AesKeyBits), MemberType = typeof(KnownAnswerTestCases))]
    public void AesCtr_Sp80038a_Kat(int keyBits) { _backend.RequireMechanism(CKM.CKM_AES_CTR); KnownAnswerTestCases.Assert_AesCtr_Sp80038a_Kat(_backend, keyBits); }

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void TripleDesEcb_Kat() { _backend.RequireMechanism(CKM.CKM_DES3_ECB); KnownAnswerTestCases.Assert_TripleDesEcb_Kat(_backend); }

    [Fact(SkipUnless = nameof(SoftHsmAvailable), Skip = "Requires " + nameof(SoftHsmAvailable))]
    public void TripleDesCbc_Kat() { _backend.RequireMechanism(CKM.CKM_DES3_CBC); KnownAnswerTestCases.Assert_TripleDesCbc_Kat(_backend); }

    // SoftHSM lists CKM_DES_ECB but cannot run it: its cipher is EVP_des_ecb() (OSSLDES.cpp), which OpenSSL 3 keeps in the
    // legacy provider SoftHSM does not load, so encryptInit fails and C_EncryptInit answers CKR_MECHANISM_INVALID
    // (SoftHSM.cpp, SymEncryptInit).
    public static bool SoftHsmRunsSingleDes => false;

    [Theory(SkipUnless = nameof(SoftHsmRunsSingleDes), Skip = "Requires " + nameof(SoftHsmRunsSingleDes))]
    [MemberData(nameof(KnownAnswerTestCases.DesVariableKeyRounds), MemberType = typeof(KnownAnswerTestCases))]
    public void DesEcb_Sp80020_Kat(string key, string ciphertext) { _backend.RequireMechanism(CKM.CKM_DES_ECB); KnownAnswerTestCases.Assert_DesEcb_Sp80020_Kat(_backend, key, ciphertext); }
}
