using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>AesCmac over NSS — thin wrapper over <see cref="AesCmacTestCases"/>.</summary>
[Collection("Nss")]
public sealed class AesCmacTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493Vectors), MemberType = typeof(AesCmacTestCases))]
    public void Sign_MatchesRfc4493(int length, string expectedMac) => AesCmacTestCases.Assert_Sign_MatchesRfc4493(_backend, length, expectedMac);

    // NSS signs with CKM_AES_CMAC but refuses to verify with it; see NssBackendFixture.SupportsCmacVerify.
    [Theory(SkipUnless = nameof(NssBackendFixture.CmacVerifyAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.CmacVerifyAvailable))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493Vectors), MemberType = typeof(AesCmacTestCases))]
    public void Verify_AcceptsRfc4493_RejectsAlteredMac(int length, string expectedMac) => AesCmacTestCases.Assert_Verify_AcceptsRfc4493_RejectsAlteredMac(_backend, length, expectedMac);
}
