using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>tpm2-pkcs11 counterpart of Pkcs11KeyMechanismTests_SoftHsm (shared Pkcs11KeyMechanismCases).</summary>
[Collection("Tpm2Pkcs11")]
public sealed class Pkcs11KeyMechanismTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    private Pkcs11Session OpenSession() =>
        _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 maps CKA_VERIFY onto the TPM decrypt attribute, so a sign-only key pair is refused")]
    public void RsaPkcs_SignVerify_RoundTrip()
    {
        using var session = OpenSession();
        Pkcs11KeyMechanismCases.Assert_RsaSignVerify_RoundTrips(session);
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void AesCbc_EncryptDecrypt_RoundTrip()
    {
        using var session = OpenSession();
        Pkcs11KeyMechanismCases.Assert_AesCbcEncryptDecrypt_RoundTrips(session);
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void AesKeyWrap_WrapUnwrap_RoundTrip()
    {
        using var session = OpenSession();
        Pkcs11KeyMechanismCases.Assert_AesKeyWrapUnwrap_RoundTrips(session);
    }
}
