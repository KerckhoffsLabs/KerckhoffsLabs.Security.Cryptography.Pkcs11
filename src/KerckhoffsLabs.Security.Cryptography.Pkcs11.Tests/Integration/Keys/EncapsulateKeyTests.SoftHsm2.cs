using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// C_EncapsulateKey/C_DecapsulateKey tests over SoftHSM with classical (RSA-OAEP, ECDH1)
/// mechanisms -- thin wrapper over <see cref="EncapsulateKeyTestCases"/>.
/// </summary>
[Collection("SoftHsm")]
public sealed class EncapsulateKeyTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    // SoftHSM2's C_EncapsulateKey/C_DecapsulateKey dispatch (SoftHSM.cpp) only recognizes
    // CKM_ML_KEM_KEY_PAIR_GEN/CKM_ML_KEM -- no RSA or ECDH mechanism is wired to it.
    public static bool SupportsAsymmetricEncapsulate => false;

    [ConditionalFact(nameof(SupportsAsymmetricEncapsulate))]
    public void RsaOaep_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_RsaOaep_EncapsulateDecapsulate_RoundTrips(_backend);

    [ConditionalFact(nameof(SupportsAsymmetricEncapsulate))]
    public void Ecdh1_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_Ecdh1_EncapsulateDecapsulate_RoundTrips(_backend);
}
