using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 key wrap/unwrap integration tests, run against NSS.
/// Each case runs across every <see cref="CKM"/> AES key-wrap variant and skips the ones NSS doesn't
/// advertise (NSS never implements <see cref="CKM.CKM_AES_KEY_WRAP_PKCS7"/>).</summary>
[Collection("Nss")]
public sealed class WrapUnwrapKeyTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // Verifies the unwrapped key via the classic CK_GCM_PARAMS path NSS rejects; skip (see NssBackendFixture).

    [Theory(SkipUnless = nameof(NssBackendFixture.ClassicAesGcmAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ClassicAesGcmAvailable))]
    [InlineData(CKM.CKM_AES_KEY_WRAP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PKCS7)]
    public void AesKeyWrap_RoundTrip(CKM wrapMechanism)
    {
        _backend.RequireMechanism(wrapMechanism);
        WrapUnwrapKeyTestCases.Assert_AesKeyWrap_RoundTrip(_backend, wrapMechanism);
    }

    // The secure-defaults unwrap cases (Unwrap_AppliesSecureDefaults /
    // Unwrap_ExplicitExtractable_RequiresAllowInsecure) are not ported here: NSS's C_UnwrapKey
    // rejects the minimal-usage unwrap template they use (CLASS/KEY_TYPE/TOKEN + injected
    // SENSITIVE/EXTRACTABLE) with CKR_ATTRIBUTE_READ_ONLY, where SoftHSM accepts it. Those cases verify
    // the library's secure-default *injection* (backend-independent logic), which stays covered on
    // SoftHSM and the managed mock (UnwrapSecureDefaultsTests.Pkcs11Mock). The real wrap/unwrap data
    // path on NSS is exercised by AesKeyWrap_RoundTrip above.

    // Dedicated KWP coverage, independent of AesKeyWrap_RoundTrip above: NSS's sftk_CryptInit never
    // sets context->blockSize for CKM_AES_KEY_WRAP_KWP (unlike its CKM_AES_KEY_WRAP/_PAD sibling,
    // which sets it to 8), so NSC_Encrypt's NULL-probe formula (ulDataLen + 2*blockSize) silently
    // omits RFC 5649's ~8-byte overhead and every real KWP wrap fails with CKR_BUFFER_TOO_SMALL --
    // unrecoverably, since NSS only updates the reported length on success, never on failure.
    // Pkcs11Session.TryWrapKeyKwp works around this by computing the wrapped length itself instead of
    // trusting the token's probe, so this needs its own real-backend proof rather than reusing
    // AesKeyWrap_RoundTrip's shared case (which also isn't reachable here anyway --
    // ClassicAesGcmAvailable gates it off NSS-wide for an unrelated GCM-verification reason).
    // Sizes: 1 (sub-block), 8 (exactly one AES block), 15 (non-block-aligned, exercises the
    // round-up-to-8 math), 40 (several blocks).
    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(40)]
    public void AesKeyWrapKwp_RoundTrip_GenericSecret(int secretLength)
    {
        _backend.RequireMechanism(CKM.CKM_AES_KEY_WRAP_KWP);
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            ObjectHandle kek = TestKeys.GenerateAes256WrappingKey(session);

            byte[] secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(secretLength);
            using var c1 = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var c2 = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var c3 = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var c4 = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
            using var c5 = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            using var c6 = new ObjectAttribute(CKA.CKA_VALUE, secret);
            ObjectHandle dataKey;
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                dataKey = session.CreateObject([c1, c2, c3, c4, c5, c6]);

            try
            {
                var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP_KWP);
                byte[] wrapped = session.WrapKey(wrapMech, kek, dataKey);

                using var u1 = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var u2 = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
                using var u3 = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var u4 = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
                using var u5 = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
                var template = new List<ObjectAttribute> { u1, u2, u3, u4, u5 };

                ObjectHandle unwrapped;
                using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                    unwrapped = session.UnwrapKey(wrapMech, kek, wrapped, template);
                try
                {
                    using var read = session.GetAttributeValue(unwrapped, [CKA.CKA_VALUE]);
                    byte[] recovered = read[0].GetValueAsByteArray();
                    Assert.Equal(secret, recovered);
                }
                finally { session.DestroyObject(unwrapped); }
            }
            finally
            {
                session.DestroyObject(dataKey);
                session.DestroyObject(kek);
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }

    // NSS softoken hard-codes a 256-byte ceiling on unwrapped secret keys (MAX_KEY_LEN,
    // softoken/pkcs11i.h) -- a fixed internal C buffer size, not a PKCS#11 spec limit. Unwrapping
    // anything longer fails with CKR_TEMPLATE_INCONSISTENT (softoken/pkcs11c.c's NSC_UnwrapKey:
    // "if (key_length > MAX_KEY_LEN) { crv = CKR_TEMPLATE_INCONSISTENT; }"). Nothing in this library
    // currently produces or unwraps a secret key anywhere near that size, so there is no client-side
    // workaround to apply here (unlike the KWP wrap-length bug above, this one isn't something we can
    // compute around: NSS's buffer really is only 256 bytes). This pins the exact behavior so a future
    // NSS version silently changing it doesn't go unnoticed. The wrap step uses KWP specifically
    // because it's already proven to succeed at this size by AesKeyWrapKwp_RoundTrip_GenericSecret
    // above (Pkcs11Session.TryWrapKeyKwp computes the wrapped length itself) -- the failure under test is
    // in C_UnwrapKey, not in wrapping.
    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Unwrap_SecretOver256Bytes_ThrowsTemplateInconsistent()
    {
        _backend.RequireMechanism(CKM.CKM_AES_KEY_WRAP_KWP);
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            ObjectHandle kek = TestKeys.GenerateAes256WrappingKey(session);

            byte[] secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(264);
            using var c1 = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var c2 = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var c3 = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var c4 = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
            using var c5 = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
            using var c6 = new ObjectAttribute(CKA.CKA_VALUE, secret);
            ObjectHandle dataKey;
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                dataKey = session.CreateObject([c1, c2, c3, c4, c5, c6]);

            try
            {
                var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP_KWP);
                byte[] wrapped = session.WrapKey(wrapMech, kek, dataKey);

                using var u1 = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var u2 = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
                using var u3 = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var u4 = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
                using var u5 = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
                var template = new List<ObjectAttribute> { u1, u2, u3, u4, u5 };

                using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                {
                    var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.UnwrapKey(wrapMech, kek, wrapped, template));
                    Assert.Equal(CKR.CKR_TEMPLATE_INCONSISTENT, ex.ReturnValue);
                }
            }
            finally
            {
                session.DestroyObject(dataKey);
                session.DestroyObject(kek);
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }
}
