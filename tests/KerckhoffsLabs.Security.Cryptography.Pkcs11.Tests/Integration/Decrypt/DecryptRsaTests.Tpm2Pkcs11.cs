using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>RSA PKCS#1 v1.5 gate against tpm2-pkcs11.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class DecryptRsaTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture f)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = f;


    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#921: key pairs can only be token objects")]
    public void RsaPkcs1V15_ThrowsCryptoPolicyViolationException_ByDefault()
        => DecryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
