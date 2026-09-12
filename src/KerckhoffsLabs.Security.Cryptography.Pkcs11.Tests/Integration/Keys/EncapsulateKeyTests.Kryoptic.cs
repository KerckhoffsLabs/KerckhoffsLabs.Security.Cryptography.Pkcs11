using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// C_EncapsulateKey/C_DecapsulateKey tests over Kryoptic with classical (RSA-OAEP, ECDH1)
/// mechanisms -- thin wrapper over <see cref="EncapsulateKeyTestCases"/>.
/// </summary>
[Collection("Kryoptic")]
public sealed class EncapsulateKeyTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    // Kryoptic's encapsulate/decapsulate trait methods are implemented only by its ML-KEM mechanism
    // (mlkem.rs); no RSA or EC mechanism implements them (see
    // https://github.com/latchset/kryoptic/issues/432, which asks for exactly this: RSA and ECC
    // support for C_[En|De]capsulateKey). CKM_RSA_PKCS_OAEP and CKM_ECDH1_DERIVE both exist on
    // Kryoptic for ordinary encrypt/derive use, so a live mechanism-list check would not catch this
    // gap -- it is the CKF_ENCAPSULATE/CKF_DECAPSULATE flag on those mechanisms that is missing.
    public static bool SupportsAsymmetricEncapsulate => false;

    [ConditionalFact(nameof(SupportsAsymmetricEncapsulate))]
    public void RsaOaep_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_RsaOaep_EncapsulateDecapsulate_RoundTrips(_backend);

    [ConditionalFact(nameof(SupportsAsymmetricEncapsulate))]
    public void Ecdh1_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_Ecdh1_EncapsulateDecapsulate_RoundTrips(_backend);
}
