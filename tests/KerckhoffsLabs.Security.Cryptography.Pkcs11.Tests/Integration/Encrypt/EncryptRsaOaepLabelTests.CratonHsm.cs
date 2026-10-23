using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>RSA-OAEP with a label over Craton HSM — thin wrapper over <see cref="EncryptRsaOaepLabelTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class EncryptRsaOaepLabelTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void OaepWithLabel_RoundTrips() =>
        EncryptRsaOaepLabelTestCases.Assert_OaepWithLabel_RoundTrips(_backend);

    // No OaepWithWrongLabel_FailsToDecrypt: Craton HSM reads only hashAlg from CK_RSA_PKCS_OAEP_PARAMS
    // (parse_oaep_hash, src/pkcs11_abi/functions.rs) and ignores the label, so a ciphertext decrypts under
    // any label. The round trip above passes for the same reason, not because the label is honoured.
}
