using System.Buffers.Binary;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Drives <c>CKM_HSS_KEY_PAIR_GEN</c> and <c>CKM_HSS</c> (PKCS#11 v3.2 §6.65, RFC 8554 / NIST SP 800-208) against a
/// real token. HSS is stateful: every signature uses the next one-time key, so the cases check the signature
/// layout, the leaf index (q) and <c>CKA_HSS_KEYS_REMAINING</c> as well as the round trip.
/// </summary>
internal static class HssTestCases
{
    // RFC 8554 §8 (IANA "Leighton-Micali Signatures (LMS)" registry) type codes; PKCS#11 v3.2 takes them as
    // CK_LMS_TYPE and CK_LMOTS_TYPE without defining names for them.
    private const ulong LmsSha256M32H5 = 0x00000005;
    private const ulong LmotsSha256N32W8 = 0x00000004;

    // LMS_SHA256_M32_H5 with LMOTS_SHA256_N32_W8: 2^5 one-time keys per tree.
    private const int LeavesPerTree = 32;

    // RFC 8554 §4.5 and §5.4: an LM-OTS signature is u32 type || C (n) || y (p * n), with n = 32 and p = 34 for
    // W8; an LMS signature is u32 q || LM-OTS signature || u32 LMS type || path (h * m), with h = 5 and m = 32.
    private const int LmOtsSignatureLength = 4 + 32 + (34 * 32);
    private const int LmsSignatureLength = 4 + LmOtsSignatureLength + 4 + (5 * 32);

    // RFC 8554 §6.2: u32 Nspk (levels - 1) || (Nspk signed public keys) || the bottom LMS signature. A signed
    // public key is an LMS signature followed by an LMS public key (u32 type || u32 OTS type || I (16) || T[1] (32)).
    private const int LmsPublicKeyLength = 4 + 4 + 16 + 32;

    private static readonly byte[] Message = Encoding.UTF8.GetBytes("HSS over CKM_HSS, RFC 8554");

    // The Recommended policy does not list the HSS mechanisms (not reviewed). These cases test the token's
    // conformance, not our policy, so they run under Recommended with exactly those two admitted.
    private static readonly ComposedCryptoPolicy RecommendedPlusHss = CryptoPolicy.Recommended
        .ToBuilder("Recommended + HSS (conformance tests)")
        .AllowMechanism(CKM.CKM_HSS_KEY_PAIR_GEN, [CryptoOperation.GenerateKeyPair], "Token conformance test.")
        .AllowMechanism(CKM.CKM_HSS, [CryptoOperation.Sign, CryptoOperation.Verify], "Token conformance test.")
        .Build();

    internal static int ExpectedSignatureLength(int levels) =>
        4 + ((levels - 1) * (LmsSignatureLength + LmsPublicKeyLength)) + LmsSignatureLength;

    internal static void Assert_Hss_SignVerify_RoundTrips(IPkcs11Backend backend, int levels)
    {
        WithHssKey(backend, levels, key =>
        {
            byte[] signature = key.Sign(new Mechanism(CKM.CKM_HSS), Message);

            Assert.Equal(ExpectedSignatureLength(levels), signature.Length);
            Assert.Equal((uint)(levels - 1), BinaryPrimitives.ReadUInt32BigEndian(signature));
            Assert.True(key.Verify(new Mechanism(CKM.CKM_HSS), Message, signature));

            byte[] tamperedMessage = [.. Message];
            tamperedMessage[0] ^= 0xFF;
            Assert.False(key.Verify(new Mechanism(CKM.CKM_HSS), tamperedMessage, signature));

            byte[] tamperedSignature = [.. signature];
            tamperedSignature[^1] ^= 0xFF;
            Assert.False(key.Verify(new Mechanism(CKM.CKM_HSS), Message, tamperedSignature));
        });
    }

    internal static void Assert_Hss_EachSignatureUsesTheNextOneTimeKey(IPkcs11Backend backend)
    {
        WithHssKey(backend, 1, key =>
        {
            Assert.Equal((ulong)LeavesPerTree, KeysRemaining(key));

            for (uint expectedQ = 0; expectedQ < 3; expectedQ++)
            {
                byte[] signature = key.Sign(new Mechanism(CKM.CKM_HSS), Message);

                // With one level, the LMS signature starts after Nspk, with q first.
                Assert.Equal(expectedQ, BinaryPrimitives.ReadUInt32BigEndian(signature.AsSpan(4)));
                Assert.Equal((ulong)(LeavesPerTree - expectedQ - 1), KeysRemaining(key));
            }
        });
    }

    internal static void Assert_Hss_ExhaustedKey_IsRefused(IPkcs11Backend backend)
    {
        WithHssKey(backend, 1, key =>
        {
            for (int i = 0; i < LeavesPerTree; i++)
                _ = key.Sign(new Mechanism(CKM.CKM_HSS), Message);

            Assert.Equal(0UL, KeysRemaining(key));

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(new Mechanism(CKM.CKM_HSS), Message));
            Assert.Equal(CKR.CKR_KEY_EXHAUSTED, ex.ReturnValue);
        });
    }

    internal static void Assert_Hss_PrivateKey_IsSensitiveAndUnextractable(IPkcs11Backend backend)
    {
        WithHssKey(backend, 1, key =>
        {
            using var attrs = key.GetAttributeValue(KeyHandlePart.Private, CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_VALUE);
            Assert.True(attrs[0].GetValueAsBool(), "An HSS private key is not CKA_SENSITIVE.");
            Assert.False(attrs[1].GetValueAsBool(), "An HSS private key is CKA_EXTRACTABLE.");
            Assert.True(attrs[2].CannotBeRead, "The CKA_VALUE of an HSS private key was readable.");
        });
    }

    private static ulong KeysRemaining(Pkcs11Key key)
    {
        using var attrs = key.GetAttributeValue(KeyHandlePart.Private, CKA.CKA_HSS_KEYS_REMAINING);
        return attrs[0].GetValueAsUlong();
    }

    private static void WithHssKey(IPkcs11Backend backend, int levels, Action<Pkcs11Key> body)
    {
        if (!backend.Supports(CKM.CKM_HSS_KEY_PAIR_GEN))
            Assert.Skip("Backend does not advertise CKM_HSS_KEY_PAIR_GEN.");
        if (!backend.Supports(CKM.CKM_HSS))
            Assert.Skip("Backend does not advertise CKM_HSS.");

        using var session = backend.OpenSession();
        using var policy = session.UsePolicy(RecommendedPlusHss);
        string label = $"hss-{Guid.NewGuid():N}";
        byte[] id = Guid.NewGuid().ToByteArray();

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_HSS).Label(label).Id(id).Verify().Build();

        // The template builder takes no CK_ULONG array, so CKA_HSS_LMS_TYPES and CKA_HSS_LMOTS_TYPES are built
        // as ObjectAttributes, which marshal each entry at the platform's CK_ULONG width.
        ulong[] lmsTypes = [.. Enumerable.Repeat(LmsSha256M32H5, levels)];
        ulong[] lmotsTypes = [.. Enumerable.Repeat(LmotsSha256N32W8, levels)];
        using var privTpl = new ObjectTemplate(
        [
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_HSS),
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            new ObjectAttribute(CKA.CKA_SENSITIVE, true),
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, false),
            new ObjectAttribute(CKA.CKA_SIGN, true),
            new ObjectAttribute(CKA.CKA_LABEL, label),
            new ObjectAttribute(CKA.CKA_ID, id),
            new ObjectAttribute(CKA.CKA_HSS_LEVELS, (ulong)levels),
            new ObjectAttribute(CKA.CKA_HSS_LMS_TYPES, lmsTypes),
            new ObjectAttribute(CKA.CKA_HSS_LMOTS_TYPES, lmotsTypes),
        ]);

        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_HSS_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            body(key);
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }
}
