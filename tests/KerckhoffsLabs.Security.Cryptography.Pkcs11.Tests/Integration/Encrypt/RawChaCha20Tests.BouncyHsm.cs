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
    // BouncyHsm runs CKM_CHACHA20 on BouncyCastle's engines and writes the initial counter straight into their private
    // engineState (ChaChaEngineExtensions), which BouncyCastle's own limit accounting never sees. With a 32-bit counter
    // (ChaCha7539Engine) it refuses the counter's last block with CKR_GENERAL_ERROR: the engine advances the counter
    // right after generating each block and throws when it wraps, before that block is used. With a 64-bit counter
    // (ChaChaEngine) AdvanceCounter carries into the high word unchecked, and the 2^70-byte limit counts bytes since
    // Init rather than the counter's position: past 2^64 - 1 the counter wraps to 0 and block 0's keystream is reused.
    // Reported as harrison314/BouncyHsm#153.
    public void CounterBoundary_Wycheproof(int tcId) =>
        RawChaCha20TestCases.Assert_CounterBoundary_Wycheproof(_backend, tcId,
            refusesBecause: tcId is 33 or 34 or 35 or 37 or 38 or 39
                ? "BouncyHsm refuses the 32-bit counter's last block (CKR_GENERAL_ERROR): BouncyCastle's ChaCha7539Engine throws when the counter wraps after it (harrison314/BouncyHsm#153)."
                : null,
            encryptsPastTheLastBlockBecause: tcId is 26 or 27 or 28
                ? "BouncyHsm wraps the 64-bit counter past 2^64 - 1, reusing block 0's keystream (harrison314/BouncyHsm#153)."
                : null);
}
