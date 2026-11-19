using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>Raw CKM_CHACHA20 over NSS — thin wrapper over <see cref="RawChaCha20TestCases"/>.</summary>
[Collection("Nss")]
public sealed class RawChaCha20Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Encrypt_MatchesBclChaCha20Poly1305Keystream() =>
        RawChaCha20TestCases.Assert_Encrypt_MatchesBclChaCha20Poly1305Keystream(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EncryptDecrypt_RoundTrips() =>
        RawChaCha20TestCases.Assert_EncryptDecrypt_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Decrypt_WrongCounter_ProducesGarbageNotException() =>
        RawChaCha20TestCases.Assert_Decrypt_WrongCounter_ProducesGarbageNotException(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(RawChaCha20TestCases.CounterBoundaryCases), MemberType = typeof(RawChaCha20TestCases))]
    // NSS softoken never checks the 32-bit counter's end: sftk_ChaCha20Ctr hands the whole input to
    // Hacl_Chacha20_chacha20_encrypt, which adds each block's index to the counter in 32 bits, so past 0xFFFFFFFF it
    // wraps to 0 and reuses block 0's keystream. (The 64-bit counter layout it refuses outright: its context keeps the
    // counter in a PRUint32.)
    public void CounterBoundary_Wycheproof(int tcId) =>
        RawChaCha20TestCases.Assert_CounterBoundary_Wycheproof(_backend, tcId,
            encryptsPastTheLastBlockBecause: tcId is 40 or 41 or 42
                ? "NSS wraps the 32-bit counter past 0xFFFFFFFF to 0, reusing block 0's keystream."
                : null);
}
