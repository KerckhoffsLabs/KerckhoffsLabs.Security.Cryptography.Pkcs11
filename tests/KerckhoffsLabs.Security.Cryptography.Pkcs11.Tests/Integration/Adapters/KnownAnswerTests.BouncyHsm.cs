using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// The same fixed-vector known-answer tests, re-run against BouncyHsm.
/// A second independent implementation reproducing the identical published RFC/NIST vectors is the
/// strongest cross-backend check: a parameter/key mis-encoding the wrapper and one token happen to
/// share would still have to be reproduced bit-for-bit by an unrelated token. The shared
/// <see cref="KnownAnswerTestCases"/> assertions take an <c>IPkcs11Backend</c>, which this fixture is.
/// Each KAT capability-gates on the live mechanism list, so anything BouncyHsm lacks skips cleanly.
/// </summary>
[Collection("BouncyHsm")]
public sealed class KnownAnswerTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    private void Require(CKM mechanism)
    {
        if (!_backend.Supports(mechanism))
            Assert.Skip($"BouncyHsm: {mechanism} not available");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesGcm_Kat() { Require(CKM.CKM_AES_GCM); KnownAnswerTestCases.Assert_AesGcm_Kat(_backend); }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesGcm_Multipart_Kat() { Require(CKM.CKM_AES_GCM); KnownAnswerTestCases.Assert_AesGcm_Multipart_Kat(_backend); }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HmacSha256_Kat() { Require(CKM.CKM_SHA256_HMAC); KnownAnswerTestCases.Assert_HmacSha256_Kat(_backend); }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HmacSha384_Kat() { Require(CKM.CKM_SHA384_HMAC); KnownAnswerTestCases.Assert_HmacSha384_Kat(_backend); }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HmacSha512_Kat() { Require(CKM.CKM_SHA512_HMAC); KnownAnswerTestCases.Assert_HmacSha512_Kat(_backend); }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesKeyWrap_Kat() { Require(CKM.CKM_AES_KEY_WRAP); KnownAnswerTestCases.Assert_AesKeyWrap_Kat(_backend); }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaOaep_Kat() { Require(CKM.CKM_RSA_PKCS_OAEP); KnownAnswerTestCases.Assert_RsaOaep_Kat(_backend); }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaPss_Kat() { Require(CKM.CKM_SHA256_RSA_PKCS_PSS); KnownAnswerTestCases.Assert_RsaPss_Kat(_backend); }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EcdsaP256_Kat() { Require(CKM.CKM_ECDSA); KnownAnswerTestCases.Assert_EcdsaP256_Kat(_backend); }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EcdhP256_Kat() { Require(CKM.CKM_ECDH1_DERIVE); KnownAnswerTestCases.Assert_EcdhP256_Kat(_backend); }

    // No Ed25519 KAT here. Its public key import (TestKeys.CreateEd25519PublicKey) writes CKA_EC_POINT
    // as a DER OCTET STRING, as SoftHSM expects; BouncyHsm takes only the raw 32-byte point and refuses
    // it with CKR_ATTRIBUTE_VALUE_INVALID. Ed25519 stays KAT-covered on SoftHSM
    // (KnownAnswerTests_SoftHsm.Ed25519_Kat).
}
