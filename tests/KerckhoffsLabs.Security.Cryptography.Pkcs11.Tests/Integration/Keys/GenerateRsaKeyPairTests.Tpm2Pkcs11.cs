using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Tpm2Pkcs11")]
public sealed class GenerateRsaKeyPairTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture f)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = f;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#921: key pairs can only be token objects")]
    public void GeneratesRsa2048KeyPair() => GenerateRsaKeyPairTestCases.Assert_GeneratesRsa2048KeyPair(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#921: key pairs can only be token objects")]
    public void SigningKeyPair_HasNoEncryptCapability() => GenerateRsaKeyPairTestCases.Assert_SigningKeyPair_HasNoEncryptCapability(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#921: key pairs can only be token objects")]
    public void GeneratesTransportKeyPair_EncryptDecryptOnly() => GenerateRsaKeyPairTestCases.Assert_GeneratesTransportKeyPair_EncryptDecryptOnly(_backend);
}
