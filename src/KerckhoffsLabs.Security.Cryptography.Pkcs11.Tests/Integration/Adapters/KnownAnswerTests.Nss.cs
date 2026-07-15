using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// The same fixed-vector known-answer tests, re-run against the second real backend (NSS).
/// A second independent implementation reproducing the identical published RFC/NIST vectors is the
/// strongest cross-backend check: a parameter/key mis-encoding the wrapper and one token happen to
/// share would still have to be reproduced bit-for-bit by an unrelated token. The shared
/// <see cref="KnownAnswerTestCases"/> assertions take an <c>IPkcs11Backend</c>, which this fixture is.
/// Each KAT capability-gates on the live mechanism list, so anything NSS lacks skips cleanly.
/// </summary>
[Collection("Nss")]
public sealed class KnownAnswerTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    // NSS drives AES-GCM through the message API, not the classic CK_GCM_PARAMS path this KAT uses.
    public static bool ClassicGcm => NssBackendFixture.ClassicAesGcmAvailable;

    private void Require(CKM mechanism)
    {
        if (!_backend.Supports(mechanism))
            throw new SkipTestException($"NSS: {mechanism} not available");
    }

    [ConditionalFact(nameof(ClassicGcm))]
    public void AesGcm_Kat() { Require(CKM.CKM_AES_GCM); KnownAnswerTestCases.Assert_AesGcm_Kat(_backend); }

    [ConditionalFact(nameof(Available))]
    public void HmacSha256_Kat() { Require(CKM.CKM_SHA256_HMAC); KnownAnswerTestCases.Assert_HmacSha256_Kat(_backend); }

    [ConditionalFact(nameof(Available))]
    public void HmacSha384_Kat() { Require(CKM.CKM_SHA384_HMAC); KnownAnswerTestCases.Assert_HmacSha384_Kat(_backend); }

    [ConditionalFact(nameof(Available))]
    public void HmacSha512_Kat() { Require(CKM.CKM_SHA512_HMAC); KnownAnswerTestCases.Assert_HmacSha512_Kat(_backend); }

    [ConditionalFact(nameof(Available))]
    public void AesKeyWrap_Kat() { Require(CKM.CKM_AES_KEY_WRAP); KnownAnswerTestCases.Assert_AesKeyWrap_Kat(_backend); }

    [ConditionalFact(nameof(Available))]
    public void RsaOaep_Kat() { Require(CKM.CKM_RSA_PKCS_OAEP); KnownAnswerTestCases.Assert_RsaOaep_Kat(_backend); }

    [ConditionalFact(nameof(Available))]
    public void RsaPss_Kat() { Require(CKM.CKM_SHA256_RSA_PKCS_PSS); KnownAnswerTestCases.Assert_RsaPss_Kat(_backend); }

    [ConditionalFact(nameof(Available))]
    public void EcdsaP256_Kat() { Require(CKM.CKM_ECDSA); KnownAnswerTestCases.Assert_EcdsaP256_Kat(_backend); }

    [ConditionalFact(nameof(Available))]
    public void EcdhP256_Kat() { Require(CKM.CKM_ECDH1_DERIVE); KnownAnswerTestCases.Assert_EcdhP256_Kat(_backend); }

    // No Ed25519 KAT here. A fixed-vector KAT requires importing a known key, but NSS's
    // software token rejects importing EdDSA keys via C_CreateObject entirely — both private (raw seed)
    // and public (point) imports return CKR_FUNCTION_FAILED; it only generates EdDSA keys on-token.
    // A generated-key round-trip would be self-consistent (the weakness KATs exist to avoid) and .NET
    // has no built-in Ed25519 to cross-check against, so it adds nothing. Ed25519 stays KAT-covered on
    // SoftHSM (KnownAnswerTests_SoftHsm.Ed25519_Kat).
}
