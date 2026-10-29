using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("SoftHsm")]
public sealed class GenerateEcKeyPairTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void RejectsUnspecifiedCurve() => GenerateEcKeyPairTestCases.Assert_RejectsUnspecifiedCurve(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(GenerateEcKeyPairTestCases.CurveOidsNotACurve), MemberType = typeof(GenerateEcKeyPairTestCases))]
    public void EcKeyGen_CurveOidNotACurve_IsRefused(string oid)
    {
        if (!SoftHsmBackendFixture.SoftHsmRefusesAnOidThatIsNoCurveAsNotSupported)
            Assert.Skip("SoftHSM2 refuses a CKA_EC_PARAMS OID that names no curve with CKR_GENERAL_ERROR");
        GenerateEcKeyPairTestCases.Assert_EcKeyGen_CurveOidNotACurve_IsRefused(_backend, oid);
    }
}
