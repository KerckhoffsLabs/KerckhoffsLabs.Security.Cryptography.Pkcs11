using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>Raw CKM_CHACHA20 over Kryoptic — thin wrapper over <see cref="RawChaCha20TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class RawChaCha20Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Encrypt_MatchesBclChaCha20Poly1305Keystream() =>
        RawChaCha20TestCases.Assert_Encrypt_MatchesBclChaCha20Poly1305Keystream(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptDecrypt_RoundTrips() =>
        RawChaCha20TestCases.Assert_EncryptDecrypt_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Decrypt_WrongCounter_ProducesGarbageNotException() =>
        RawChaCha20TestCases.Assert_Decrypt_WrongCounter_ProducesGarbageNotException(_backend);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(RawChaCha20TestCases.CounterBoundaryCases), MemberType = typeof(RawChaCha20TestCases))]
    // Kryoptic passes the counter and nonce to OpenSSL's ChaCha20 as one 16-byte IV, and OpenSSL carries a counter
    // overflow into the first nonce word: past 0xFFFFFFFF it goes on with counter 0 of nonce word 0 + 1, keystream
    // that belongs to another nonce, instead of refusing. (It takes only the RFC 8439 layout, 32-bit counter and
    // 96-bit nonce, so the 64-bit counter vectors skip.)
    public void CounterBoundary_Wycheproof(int tcId) =>
        RawChaCha20TestCases.Assert_CounterBoundary_Wycheproof(_backend, tcId,
            encryptsPastTheLastBlockBecause: tcId is 40 or 41 or 42
                ? "Kryoptic (OpenSSL) carries the 32-bit counter's overflow into the first nonce word instead of refusing."
                : null);
}
