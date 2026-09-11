using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// The same fixed-vector known-answer tests, re-run against a fourth real backend (Kryoptic). A
/// second (third, fourth, ...) independent implementation reproducing the identical published
/// RFC/NIST vectors is the strongest cross-backend check: a parameter/key mis-encoding the wrapper
/// and one token happen to share would still have to be reproduced bit-for-bit by an unrelated
/// token. The shared <see cref="KnownAnswerTestCases"/> assertions (defined in
/// KnownAnswerTests.SoftHsm2.cs) take an <c>IPkcs11Backend</c>, which this fixture is.
/// </summary>
[Collection("Kryoptic")]
public sealed class KnownAnswerTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;
    public static bool KryopticSupportsChaCha20Poly1305 => KryopticBackendFixture.KryopticSupportsChaCha20Poly1305;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void AesGcm_Kat() => KnownAnswerTestCases.Assert_AesGcm_Kat(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void HmacSha256_Kat() => KnownAnswerTestCases.Assert_HmacSha256_Kat(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Ed25519_Kat() => KnownAnswerTestCases.Assert_Ed25519_Kat(_backend);

    // Kryoptic 1.5.2 has no ChaCha20 support at all (see KryopticBackendFixture.KryopticSupportsChaCha20Poly1305).
    [ConditionalFact(nameof(KryopticAvailable), nameof(KryopticSupportsChaCha20Poly1305))]
    public void ChaCha20Poly1305_Kat() => KnownAnswerTestCases.Assert_ChaCha20Poly1305_Kat(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void HmacSha384_Kat() => KnownAnswerTestCases.Assert_HmacSha384_Kat(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void HmacSha512_Kat() => KnownAnswerTestCases.Assert_HmacSha512_Kat(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void AesKeyWrap_Kat() => KnownAnswerTestCases.Assert_AesKeyWrap_Kat(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void RsaOaep_Kat() => KnownAnswerTestCases.Assert_RsaOaep_Kat(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void RsaPss_Kat() => KnownAnswerTestCases.Assert_RsaPss_Kat(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EcdsaP256_Kat() => KnownAnswerTestCases.Assert_EcdsaP256_Kat(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EcdhP256_Kat() => KnownAnswerTestCases.Assert_EcdhP256_Kat(_backend);
}
