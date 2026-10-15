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
}
