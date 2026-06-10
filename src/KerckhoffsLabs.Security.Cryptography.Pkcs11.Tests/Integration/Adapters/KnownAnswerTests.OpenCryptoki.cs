using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// The same fixed-vector known-answer tests, re-run against the second real backend (opencryptoki).
/// A second independent implementation reproducing the identical published RFC/NIST vectors is the
/// strongest cross-backend check: a parameter/key mis-encoding the wrapper and one token happen to
/// share would still have to be reproduced bit-for-bit by an unrelated token. The shared
/// <see cref="KnownAnswerTestCases"/> assertions take an <c>IPkcs11Backend</c>, which this fixture is.
/// Each KAT capability-gates on the live mechanism list, so anything opencryptoki lacks skips cleanly.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class KnownAnswerTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private void Require(CKM mechanism)
    {
        if (!_backend.Supports(mechanism))
            throw new SkipTestException($"opencryptoki: {mechanism} not available");
    }

    [ConditionalFact(nameof(Available))]
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

    // Verify-only Ed25519 KAT: opencryptoki advertises CKM_EDDSA but its software token rejects
    // *importing* a raw private seed via C_CreateObject (CKR_FUNCTION_FAILED), so the full sign+verify
    // KAT can't run here. Verification needs only the public key, which it does accept — so this still
    // pins the EdDSA verify path and signature/point marshalling on the second backend.
    [ConditionalFact(nameof(Available))]
    public void Ed25519_Verify_Kat() { Require(CKM.CKM_EDDSA); KnownAnswerTestCases.Assert_Ed25519_Verify_Kat(_backend); }
}
