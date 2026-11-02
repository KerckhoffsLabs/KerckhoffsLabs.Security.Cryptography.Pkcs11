using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 EC key-pair generation integration tests, run against BouncyHsm.</summary>
[Collection("BouncyHsm")]
public sealed class GenerateEcKeyPairTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SigningKeyPair_SignVerifyOnly() => GenerateEcKeyPairTestCases.Assert_SigningKeyPair_SignVerifyOnly(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void KeyAgreementKeyPair_DeriveOnly() => GenerateEcKeyPairTestCases.Assert_KeyAgreementKeyPair_DeriveOnly(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RejectsUnspecifiedCurve() => GenerateEcKeyPairTestCases.Assert_RejectsUnspecifiedCurve(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void KeyAgreementKeyPair_RejectsUnspecifiedCurve() => GenerateEcKeyPairTestCases.Assert_KeyAgreementKeyPair_RejectsUnspecifiedCurve(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(GenerateEcKeyPairTestCases.CurveOidsNotACurve), MemberType = typeof(GenerateEcKeyPairTestCases))]
    public void EcKeyGen_CurveOidNotACurve_IsRefused(string oid) => GenerateEcKeyPairTestCases.Assert_EcKeyGen_CurveOidNotACurve_IsRefused(_backend, oid);
}
