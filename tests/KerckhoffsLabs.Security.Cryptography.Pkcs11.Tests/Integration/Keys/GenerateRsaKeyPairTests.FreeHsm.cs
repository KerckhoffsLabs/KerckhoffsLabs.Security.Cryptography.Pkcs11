using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("FreeHsm")]
public sealed class GenerateRsaKeyPairTests_FreeHsm(FreeHsmBackendFixture f)
{
    private readonly FreeHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void GeneratesRsa2048KeyPair() => GenerateRsaKeyPairTestCases.Assert_GeneratesRsa2048KeyPair(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SigningKeyPair_HasNoEncryptCapability() => GenerateRsaKeyPairTestCases.Assert_SigningKeyPair_HasNoEncryptCapability(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void GeneratesTransportKeyPair_EncryptDecryptOnly() => GenerateRsaKeyPairTestCases.Assert_GeneratesTransportKeyPair_EncryptDecryptOnly(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(GenerateRsaKeyPairTestCases.ModulusBitsAboveTheMaximum), MemberType = typeof(GenerateRsaKeyPairTestCases))]
    public void RsaKeyGen_ModulusBitsAboveTheMaximum_IsRefused(string row) => GenerateRsaKeyPairTestCases.Assert_RsaKeyGen_ModulusBitsAboveTheMaximum_IsRefused(_backend, row);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.PublicExponentAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "FreeHSM makes every RSA key with the exponent 65537")]
    [MemberData(nameof(GenerateRsaKeyPairTestCases.PublicExponents), MemberType = typeof(GenerateRsaKeyPairTestCases))]
    public void RsaKeyGen_PublicExponent_IsTheOneAsked(string exponent) => GenerateRsaKeyPairTestCases.Assert_RsaKeyGen_PublicExponent_IsTheOneAsked(_backend, exponent);
}
