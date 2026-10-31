using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Kryoptic")]
public sealed class GenerateEcKeyPairTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void RejectsUnspecifiedCurve() => GenerateEcKeyPairTestCases.Assert_RejectsUnspecifiedCurve(_backend);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(GenerateEcKeyPairTestCases.CurveOidsNotACurve), MemberType = typeof(GenerateEcKeyPairTestCases))]
    public void EcKeyGen_CurveOidNotACurve_IsRefused(string oid)
    {
        if (!KryopticBackendFixture.KryopticRefusesAnOidThatIsNoCurveAsNotSupported)
            Assert.Skip("Kryoptic refuses a CKA_EC_PARAMS OID that names no curve with CKR_GENERAL_ERROR");
        GenerateEcKeyPairTestCases.Assert_EcKeyGen_CurveOidNotACurve_IsRefused(_backend, oid);
    }
}
