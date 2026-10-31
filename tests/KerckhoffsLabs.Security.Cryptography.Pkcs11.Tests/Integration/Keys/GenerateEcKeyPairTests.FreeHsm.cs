using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("FreeHsm")]
public sealed class GenerateEcKeyPairTests_FreeHsm(FreeHsmBackendFixture f)
{
    private readonly FreeHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RejectsUnspecifiedCurve() => GenerateEcKeyPairTestCases.Assert_RejectsUnspecifiedCurve(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(GenerateEcKeyPairTestCases.CurveOidsNotACurve), MemberType = typeof(GenerateEcKeyPairTestCases))]
    public void EcKeyGen_CurveOidNotACurve_IsRefused(string oid) => GenerateEcKeyPairTestCases.Assert_EcKeyGen_CurveOidNotACurve_IsRefused(_backend, oid);
}
