using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// C_EncapsulateKey/C_DecapsulateKey tests over tpm2-pkcs11 with classical (RSA-OAEP, ECDH1)
/// mechanisms -- thin wrapper over <see cref="EncapsulateKeyTestCases"/>.
/// </summary>
[Collection("Tpm2Pkcs11")]
public sealed class EncapsulateKeyTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    // tpm2-pkcs11 implements the PKCS#11 2.40 interface only, so it has no C_EncapsulateKey or
    // C_DecapsulateKey (3.2). CKM_RSA_PKCS_OAEP and CKM_ECDH1_DERIVE are both in its mechanism list for
    // ordinary encrypt/derive use, so a live mechanism-list check would not catch this gap.
    public static bool SupportsAsymmetricEncapsulate => false;

    [Fact(SkipUnless = nameof(SupportsAsymmetricEncapsulate), Skip = "Requires " + nameof(SupportsAsymmetricEncapsulate))]
    public void RsaOaep_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_RsaOaep_EncapsulateDecapsulate_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(SupportsAsymmetricEncapsulate), Skip = "Requires " + nameof(SupportsAsymmetricEncapsulate))]
    public void Ecdh1_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_Ecdh1_EncapsulateDecapsulate_RoundTrips(_backend);
}
