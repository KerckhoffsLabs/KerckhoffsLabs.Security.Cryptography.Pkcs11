using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>AesCmac over wolfPKCS11 — thin wrapper over <see cref="AesCmacTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class AesCmacTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493Vectors), MemberType = typeof(AesCmacTestCases))]
    public void Sign_MatchesRfc4493(int length, string expectedMac) => AesCmacTestCases.Assert_Sign_MatchesRfc4493(_backend, length, expectedMac);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(AesCmacTestCases.Rfc4493Vectors), MemberType = typeof(AesCmacTestCases))]
    public void Verify_AcceptsRfc4493_RejectsAlteredMac(int length, string expectedMac) => AesCmacTestCases.Assert_Verify_AcceptsRfc4493_RejectsAlteredMac(_backend, length, expectedMac);
}
