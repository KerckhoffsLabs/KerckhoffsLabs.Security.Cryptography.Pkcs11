using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// C_EncapsulateKey/C_DecapsulateKey tests over NSS with classical (RSA-OAEP, ECDH1) mechanisms --
/// thin wrapper over <see cref="EncapsulateKeyTestCases"/>.
/// </summary>
[Collection("Nss")]
public sealed class EncapsulateKeyTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // NSS's softoken KEM support (lib/softoken/kem.c) dispatches only on CKM_ML_KEM/CKM_NSS_ML_KEM/
    // CKM_NSS_KYBER -- no RSA or ECDH mechanism reaches its C_EncapsulateKey/C_DecapsulateKey path.
    public static bool SupportsAsymmetricEncapsulate => false;

    [ConditionalFact(nameof(SupportsAsymmetricEncapsulate))]
    public void RsaOaep_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_RsaOaep_EncapsulateDecapsulate_RoundTrips(_backend);

    [ConditionalFact(nameof(SupportsAsymmetricEncapsulate))]
    public void Ecdh1_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_Ecdh1_EncapsulateDecapsulate_RoundTrips(_backend);
}
