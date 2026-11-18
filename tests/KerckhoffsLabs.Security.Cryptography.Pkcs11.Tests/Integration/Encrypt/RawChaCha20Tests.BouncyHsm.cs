using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>Raw CKM_CHACHA20 over BouncyHsm — thin wrapper over <see cref="RawChaCha20TestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class RawChaCha20Tests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Encrypt_MatchesBclChaCha20Poly1305Keystream() =>
        RawChaCha20TestCases.Assert_Encrypt_MatchesBclChaCha20Poly1305Keystream(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EncryptDecrypt_RoundTrips() =>
        RawChaCha20TestCases.Assert_EncryptDecrypt_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Decrypt_WrongCounter_ProducesGarbageNotException() =>
        RawChaCha20TestCases.Assert_Decrypt_WrongCounter_ProducesGarbageNotException(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(RawChaCha20TestCases.CounterBoundaryCases), MemberType = typeof(RawChaCha20TestCases))]
    // BouncyHsm runs CKM_CHACHA20 on BouncyCastle's engines. With a 32-bit counter (ChaCha7539Engine) it refuses the
    // counter's last block with CKR_GENERAL_ERROR: the engine advances the counter after each block it generates and
    // throws when it wraps, even when that block was the last one needed. With a 64-bit counter (ChaChaEngine) it never
    // checks: past 2^64 - 1 the counter wraps to 0 and block 0's keystream is reused.
    public void CounterBoundary_Wycheproof(int tcId) =>
        RawChaCha20TestCases.Assert_CounterBoundary_Wycheproof(_backend, tcId,
            refusesBecause: tcId is 33 or 34 or 35 or 37 or 38 or 39
                ? "BouncyHsm refuses the 32-bit counter's last block (CKR_GENERAL_ERROR): BouncyCastle's ChaCha7539Engine throws when the counter wraps after it."
                : null,
            encryptsPastTheLastBlockBecause: tcId is 26 or 27 or 28
                ? "BouncyHsm wraps the 64-bit counter past 2^64 - 1 (BouncyCastle's ChaChaEngine does not check), reusing block 0's keystream."
                : null);
}
