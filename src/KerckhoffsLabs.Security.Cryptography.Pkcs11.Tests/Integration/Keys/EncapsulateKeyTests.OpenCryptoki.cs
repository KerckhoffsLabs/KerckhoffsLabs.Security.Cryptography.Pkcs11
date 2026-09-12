using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// C_EncapsulateKey/C_DecapsulateKey tests over opencryptoki with classical (RSA-OAEP, ECDH1)
/// mechanisms -- thin wrapper over <see cref="EncapsulateKeyTestCases"/>. opencryptoki's soft token
/// (soft_specific.c) advertises CKF_ENCAPSULATE/CKF_DECAPSULATE for CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS,
/// CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, and CKM_DH_PKCS_DERIVE, dispatched generically
/// (key_mgr.c -> mech_rsa.c/mech_ec.c) through existing generate-key + wrap/unwrap or derive
/// primitives -- no token-specific hook is required, so this is expected to work on the plain
/// soft_stdll build too, not just hardware-backed token types.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class EncapsulateKeyTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void RsaOaep_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_RsaOaep_EncapsulateDecapsulate_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ecdh1_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_Ecdh1_EncapsulateDecapsulate_RoundTrips(_backend);
}
