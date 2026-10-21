using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// TripleDESPkcs11 is [Obsolete] (64-bit block / Sweet32, NIST-deprecated); the secure-defaults gate is
// the point of the type, so KLPKCS11004 is suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11004

/// <summary>
/// Backend-agnostic TripleDESPkcs11 tests: token 3DES-CBC/ECB matches the BCL for the same key, the
/// managed-key / streaming surface is NotSupported, and CBC/ECB are gated by the secure-defaults policy.
/// Cases skip where the backend does not advertise <c>CKM_DES3_CBC</c> (and a known-answer op that the
/// token advertises but does not implement is turned into a skip on <c>CKR_MECHANISM_INVALID</c>).
/// </summary>
internal static class TripleDESPkcs11TestCases
{
    // 24-byte three-key 3DES key with three distinct, non-weak DES subkeys (the BCL TripleDES setter
    // rejects keys that degenerate to single/double DES).
    private static readonly byte[] Key192 =
        Convert.FromHexString("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123");

    // 16-byte two-key (2TDEA) 3DES key: K1 || K2, distinct non-weak subkeys. PKCS#11 models this as
    // CKK_DES2 (not CKK_DES3 with a short value) — TripleDESPkcs11 accepts either key type.
    private static readonly byte[] Key128 =
        Convert.FromHexString("0123456789ABCDEF23456789ABCDEF01");

    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");

    private static Pkcs11Session OpenSession(IPkcs11Backend backend) =>
        backend.OpenSession();

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    private static void WithImportedDes3(IPkcs11Backend backend, Action<Pkcs11Session, TripleDESPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_DES3_CBC))
            Assert.Skip("Backend does not advertise CKM_DES3_CBC.");

        using var session = OpenSession(backend);
        string label = $"des3-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_DES3)
            .Label(label).Value(Key192).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            using var des3 = new TripleDESPkcs11(key);
            body(session, des3);
        }
        finally { DestroyByLabel(session, label); }
    }

    // Imports Key128 as a CKK_DES2 (two-key) token key. Some backends advertise CKM_DES3_CBC but
    // reject the CKK_DES2 key type/length itself — turned into a skip, not a failure, matching
    // OrSkipIfTokenLacksDes3's tolerance for that class of backend quirk.
    private static void WithImportedDes2(IPkcs11Backend backend, Action<Pkcs11Session, TripleDESPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_DES3_CBC))
            Assert.Skip("Backend does not advertise CKM_DES3_CBC.");

        using var session = OpenSession(backend);
        string label = $"des2-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_DES2)
            .Label(label).Value(Key128).Encrypt().Decrypt()
            .OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            Pkcs11Key key;
            try
            {
                key = session.ImportKey(tpl);
            }
            catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_ATTRIBUTE_VALUE_INVALID
                or CKR.CKR_TEMPLATE_INCONSISTENT or CKR.CKR_KEY_SIZE_RANGE)
            {
                Assert.Skip(
                    "Backend advertises CKM_DES3_CBC but rejects the CKK_DES2 (two-key) key type.");
                throw; // Assert.Skip always throws; xunit.v3.assert 4.0.1 lacks [DoesNotReturn].
            }
            using (key)
            {
                using var des3 = new TripleDESPkcs11(key);
                body(session, des3);
            }
        }
        finally { DestroyByLabel(session, label); }
    }

    // Translate a token that advertises but does not implement 3DES (FIPS build) into a skip.
    private static byte[] OrSkipIfTokenLacksDes3(Func<byte[]> tokenOp)
    {
        try
        {
            return tokenOp();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_MECHANISM_INVALID)
        {
            Assert.Skip(
                "Token advertises 3DES but its operation path rejects CKM_DES3_* (FIPS build).");
            throw; // Assert.Skip always throws; xunit.v3.assert 4.0.1 lacks [DoesNotReturn].
        }
    }

    private static TripleDES BclDes3()
    {
        var bcl = TripleDES.Create();
        bcl.Key = Key192;
        return bcl;
    }

    internal static void Assert_Ctor_NonDes3Key_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN);
        using var session = OpenSession(backend);
        string label = $"nondes3-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            using var key = session.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new TripleDESPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(session, label); }
    }

    internal static void Assert_EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (session, des3) =>
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("3DES-CBC PKCS7 over a token key — variable length.");
            Assert.Throws<CryptoPolicyViolationException>(() => des3.EncryptCbc(plaintext, Iv8));

            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            using var bcl = BclDes3();
            byte[] ct = OrSkipIfTokenLacksDes3(() => des3.EncryptCbc(plaintext, Iv8)); // default PaddingMode.PKCS7
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv8), ct);
            Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8));
        });

    internal static void Assert_EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (session, des3) =>
        {
            byte[] plaintext = new byte[16]; // exactly two 8-byte blocks
            RandomNumberGenerator.Fill(plaintext);
            Assert.Throws<CryptoPolicyViolationException>(() => des3.EncryptCbc(plaintext, Iv8, PaddingMode.None));

            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            using var bcl = BclDes3();
            byte[] ct = OrSkipIfTokenLacksDes3(() => des3.EncryptCbc(plaintext, Iv8, PaddingMode.None));
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None), ct);
            Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8, PaddingMode.None));
        });

    internal static void Assert_EncryptEcb_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) =>
            Assert.Throws<CryptoPolicyViolationException>(() => des3.EncryptEcb(new byte[8], PaddingMode.None)));

    internal static void Assert_EncryptEcb_WithAllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (session, des3) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            byte[] plaintext = new byte[8];
            RandomNumberGenerator.Fill(plaintext);
            using var bcl = BclDes3();

            byte[] ct = OrSkipIfTokenLacksDes3(() => des3.EncryptEcb(plaintext, PaddingMode.None));
            Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
            Assert.Equal(plaintext, des3.DecryptEcb(ct, PaddingMode.None));
        });

    internal static void Assert_KeySize_ReflectsTokenKeyLength(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) => Assert.Equal(192, des3.KeySize));

    internal static void Assert_EncryptCbc_UnsupportedPadding_Throws(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) =>
            Assert.Throws<NotSupportedException>(() => des3.EncryptCbc(new byte[8], Iv8, PaddingMode.Zeros)));

    internal static void Assert_Cfb_NotSupported(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (session, des3) =>
        {
            // TripleDESPkcs11 does not override the CFB cores: PKCS#11 defines no CKM_DES3_CFB mechanism,
            // so the base SymmetricAlgorithm surfaces NotSupportedException — even under the AllowInsecure policy.
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            Assert.Throws<NotSupportedException>(
                () => des3.EncryptCfb(new byte[8], Iv8, PaddingMode.None, feedbackSizeInBits: 8));
        });

    internal static void Assert_GenerateIV_ProducesBlockSizedIv(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) =>
        {
            des3.GenerateIV();
            Assert.Equal(8, des3.IV.Length);
        });

    // Empty CBC input follows the BCL: unpadded it is a no-op, and padded decryption is refused, since a padded
    // ciphertext holds at least one block. Neither touches the token, so no DES support is needed.
    internal static void Assert_Cbc_EmptyInput_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (session, des3) =>
        {
            // The empty-input fast path honors the gate: without the AllowInsecure policy the gated mechanism throws
            // before the (empty) buffer reaches the token.
            Assert.Throws<CryptoPolicyViolationException>(() => des3.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));

            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            Assert.ThrowsAny<CryptographicException>(() => des3.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));
            Assert.Empty(des3.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8, PaddingMode.None));
        });

    // A ciphertext whose padding is wrong, or that is not a whole number of blocks, is refused with a
    // CryptographicException as in the BCL, and the session still decrypts afterwards (see
    // CbcPaddingTestSupport.BadlyPaddedBlocks for the paddings tried).
    internal static void Assert_DecryptCbc_InvalidPaddingOrPartialBlock_Throws_SessionReusable(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_DES3_CBC, CKM.CKM_DES3_CBC_PAD);
        WithImportedDes3(backend, (session, des3) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            OrSkipIfTokenLacksDes3(() => des3.EncryptCbc(new byte[8], Iv8));
            using var bcl = BclDes3();
            CbcPaddingTestSupport.AssertRefusesBadPadding_SessionReusable(des3, bcl, Iv8);
        });
    }

    internal static void Assert_ManagedKeyAndStreamingSurface_NotSupported(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) =>
        {
            Assert.Throws<NotSupportedException>(() => des3.CreateEncryptor(new byte[24], new byte[8]));
            Assert.Throws<NotSupportedException>(() => des3.CreateDecryptor(new byte[24], new byte[8]));
            Assert.Throws<NotSupportedException>(() => des3.GenerateKey());
            Assert.Throws<NotSupportedException>(() => des3.Key);
        });

    // === Two-key (CKK_DES2, 128-bit) 3DES ==============================================
    // No KeySize test here: TripleDESPkcs11.KeySize reads CKA_VALUE_LEN, which a spec-correct token
    // rejects on C_CreateObject (import) and never derives afterward from CKA_VALUE alone — confirmed
    // against real SoftHSM2 (CKR_ATTRIBUTE_TYPE_INVALID when supplied, unreadable when omitted). The
    // 24-byte case's KeySize test only ever passed by coincidence: 192 is also TripleDES's base-class
    // default.

    // Fixed known-answer vector: two-key (2TDEA) 3DES-CBC, key Key128, plaintext "Now is t" + 8 zero
    // bytes (two 8-byte blocks, no padding). The BCL's own TripleDES cannot be used as the oracle here —
    // on OpenSSL-backed .NET, encrypting with a 16-byte (2-key) TripleDES key throws at operation time
    // ("invalid key length"), even though setting .Key succeeds — so the expected ciphertext is pinned,
    // computed independently (Python's `cryptography` library, which expands K1||K2 to K1||K2||K1 the
    // same way PKCS#11 tokens do).
    internal static void Assert_TwoKeyDes3_EncryptCbc_KnownAnswer_MatchesReferenceVector(IPkcs11Backend backend) =>
        WithImportedDes2(backend, (session, des3) =>
        {
            byte[] plaintext = Convert.FromHexString("4E6F7720697320740000000000000000");
            byte[] expectedCt = Convert.FromHexString("8DC1D44886D99D3004C55BEE813BEC9F");
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);

            byte[] ct = OrSkipIfTokenLacksDes3(() => des3.EncryptCbc(plaintext, Iv8, PaddingMode.None));
            Assert.Equal(expectedCt, ct);
            Assert.Equal(plaintext, des3.DecryptCbc(expectedCt, Iv8, PaddingMode.None));
        });
}
