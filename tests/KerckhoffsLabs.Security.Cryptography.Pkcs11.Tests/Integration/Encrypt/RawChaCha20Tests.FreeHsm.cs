using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>Raw CKM_CHACHA20 over FreeHSM — thin wrapper over <see cref="RawChaCha20TestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class RawChaCha20Tests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Encrypt_MatchesBclChaCha20Poly1305Keystream() =>
        RawChaCha20TestCases.Assert_Encrypt_MatchesBclChaCha20Poly1305Keystream(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void EncryptDecrypt_RoundTrips() =>
        RawChaCha20TestCases.Assert_EncryptDecrypt_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Decrypt_WrongCounter_ProducesGarbageNotException() =>
        RawChaCha20TestCases.Assert_Decrypt_WrongCounter_ProducesGarbageNotException(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(RawChaCha20TestCases.CounterBoundaryCases), MemberType = typeof(RawChaCha20TestCases))]
    // FreeHSM sizes the 64-bit counter's room as 2^64 - 1 - start blocks, one short of 2^64 - start
    // (ctr_blocks_max = UINT64_MAX - start in the CKM_CHACHA20 init of src/fhsm_pkcs11.c; the 32-bit layout counts
    // 2^32 - start). So it refuses the 64-bit counter's last block with CKR_DATA_LEN_RANGE: 2^64 - 1 has room for none.
    public void CounterBoundary_Wycheproof(int tcId) =>
        RawChaCha20TestCases.Assert_CounterBoundary_Wycheproof(_backend, tcId,
            refusesBecause: tcId is 19 or 20 or 21 or 23 or 24 or 25
                ? "FreeHSM refuses the 64-bit counter's last block (CKR_DATA_LEN_RANGE): its room is counted one block short."
                : null);
}
