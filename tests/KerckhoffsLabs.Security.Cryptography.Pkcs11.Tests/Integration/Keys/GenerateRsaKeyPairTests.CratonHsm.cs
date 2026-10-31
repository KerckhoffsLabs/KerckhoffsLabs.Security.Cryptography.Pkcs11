using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("CratonHsm")]
public sealed class GenerateRsaKeyPairTests_CratonHsm(CratonHsmBackendFixture f)
{
    private readonly CratonHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GeneratesRsa2048KeyPair() => GenerateRsaKeyPairTestCases.Assert_GeneratesRsa2048KeyPair(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SigningKeyPair_HasNoEncryptCapability() => GenerateRsaKeyPairTestCases.Assert_SigningKeyPair_HasNoEncryptCapability(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GeneratesTransportKeyPair_EncryptDecryptOnly() => GenerateRsaKeyPairTestCases.Assert_GeneratesTransportKeyPair_EncryptDecryptOnly(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(GenerateRsaKeyPairTestCases.ModulusBitsAboveTheMaximum), MemberType = typeof(GenerateRsaKeyPairTestCases))]
    public void RsaKeyGen_ModulusBitsAboveTheMaximum_IsRefused(string row)
    {
        if (row == "2^32 + 2048" && !CratonHsmBackendFixture.CratonHsmRefusesAModulusAbove32Bits)
            Assert.Skip("Craton HSM cuts CKA_MODULUS_BITS to 32 bits and makes a 2048-bit key");
        GenerateRsaKeyPairTestCases.Assert_RsaKeyGen_ModulusBitsAboveTheMaximum_IsRefused(_backend, row);
    }

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.PublicExponentAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM makes every RSA key with the exponent 65537")]
    [MemberData(nameof(GenerateRsaKeyPairTestCases.PublicExponents), MemberType = typeof(GenerateRsaKeyPairTestCases))]
    public void RsaKeyGen_PublicExponent_IsTheOneAsked(string exponent) => GenerateRsaKeyPairTestCases.Assert_RsaKeyGen_PublicExponent_IsTheOneAsked(_backend, exponent);
}
