using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationStateMixing over tpm2-pkcs11 — thin wrapper over <see cref="OperationStateMixingTestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class OperationStateMixingTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DigestMixingRefusalAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 accepts C_Digest after C_DigestUpdate")]
    public void Digest_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Digest_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void DigestUpdate_AfterCompletedDigest_Throws() => OperationStateMixingTestCases.Assert_DigestUpdate_AfterCompletedDigest_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void Sign_SinglePartAfterUpdate_Throws() => OperationStateMixingTestCases.Assert_Sign_SinglePartAfterUpdate_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void Encrypt_SinglePartAfterUpdate_Throws()
    {
        Assert.SkipUnless(_backend.Supports(CKM.CKM_AES_CBC_PAD), "Backend does not advertise CKM_AES_CBC_PAD (wolfTPM's fwTPM has no TPM2_ALG_CBC).");
        OperationStateMixingTestCases.Assert_Encrypt_SinglePartAfterUpdate_Throws(_backend);
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 cannot use a secret key from C_CreateObject (no CKA_ALLOWED_MECHANISMS)")]
    public void Decrypt_SinglePartAfterUpdate_Throws()
    {
        Assert.SkipUnless(_backend.Supports(CKM.CKM_AES_CBC_PAD), "Backend does not advertise CKM_AES_CBC_PAD (wolfTPM's fwTPM has no TPM2_ALG_CBC).");
        OperationStateMixingTestCases.Assert_Decrypt_SinglePartAfterUpdate_Throws(_backend);
    }
}
