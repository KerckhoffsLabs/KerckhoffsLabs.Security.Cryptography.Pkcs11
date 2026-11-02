using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>CkmAesCtrParams over Kryoptic — thin wrapper over <see cref="AesCtrParamsTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class AesCtrParamsTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.Rows), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_MatchesTheBclCtr(int counterBits, string blockHex, int length)
        => AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(AesCtrParamsTestCases.RowsUsingTheLastCounterValue), MemberType = typeof(AesCtrParamsTestCases))]
    public void Encrypt_UsingTheLastCounterValue_MatchesTheBclCtr(int counterBits, string blockHex, int length)
    {
        if (!KryopticBackendFixture.KryopticEncryptsTheLastCounterValue)
            Assert.Skip("Kryoptic refuses a message that uses the last AES-CTR counter value with CKR_DATA_LEN_RANGE");
        AesCtrParamsTestCases.Assert_Encrypt_MatchesTheBclCtr(_backend, counterBits, blockHex, length);
    }
}
