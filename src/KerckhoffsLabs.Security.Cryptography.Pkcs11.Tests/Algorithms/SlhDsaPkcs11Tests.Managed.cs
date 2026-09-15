using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

#pragma warning disable SYSLIB5006 // SLH-DSA is an evaluation-only BCL API.

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SlhDsaPkcs11 over the in-process <c>ManagedSoftToken</c> (no SoftHSM). SoftHSM has no SLH-DSA
/// (FIPS 205) support, so its KAT skips — the managed token generates the key pair, signs, and
/// verifies entirely via the BCL <see cref="SlhDsa"/> primitive. This mirrors the SoftHSM test's
/// behaviour set against the in-process token and adds BCL cross-checks: a token-produced signature
/// is verified by an independent BCL <c>SlhDsa</c> imported from the token's exported public key.
/// Crypto cases are gated on <see cref="SlhDsa.IsSupported"/> (OS PQC support — OpenSSL 3.5+ / a
/// recent Windows). SLH-DSA's fast (f) variants are preferred to keep signing time reasonable.
/// </summary>
[NoBackendCollection("Drives a per-test ManagedSoftToken in process — no native module is loaded and " +
                     "the token holds no static state, so this is safe alongside every backend collection.")]
public sealed class SlhDsaPkcs11Tests_Managed
{

    // Generates an SLH-DSA key pair for the given parameter set over the managed token, wraps it as
    // SlhDsaPkcs11, runs the body, then deletes both handles. CKA_PARAMETER_SET goes on the public
    // template (matching the SoftHSM test's WithSlhDsa helper).
    private static void WithSlhDsa(CkpSlhDsa parameterSet, Action<SlhDsaPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        string label = $"slhdsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_SLH_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_SLH_DSA)
            .Label(label).Id(id).Sign().Build();

        using var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_SLH_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var slhdsa = new SlhDsaPkcs11(key);
            body(slhdsa);
        }
        finally
        {
            try { key.Destroy(); }
            catch { /* best-effort cleanup */ }
        }
    }

    // Maps a PKCS#11 parameter-set marker to the BCL SlhDsaAlgorithm, for cross-checking.
    private static SlhDsaAlgorithm BclAlgorithm(CkpSlhDsa p) => p switch
    {
        CkpSlhDsa.CKP_SLH_DSA_SHA2_128S => SlhDsaAlgorithm.SlhDsaSha2_128s,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S => SlhDsaAlgorithm.SlhDsaShake128s,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_128F => SlhDsaAlgorithm.SlhDsaSha2_128f,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F => SlhDsaAlgorithm.SlhDsaShake128f,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_192S => SlhDsaAlgorithm.SlhDsaSha2_192s,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S => SlhDsaAlgorithm.SlhDsaShake192s,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_192F => SlhDsaAlgorithm.SlhDsaSha2_192f,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F => SlhDsaAlgorithm.SlhDsaShake192f,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_256S => SlhDsaAlgorithm.SlhDsaSha2_256s,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S => SlhDsaAlgorithm.SlhDsaShake256s,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_256F => SlhDsaAlgorithm.SlhDsaSha2_256f,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F => SlhDsaAlgorithm.SlhDsaShake256f,
        _ => throw new InvalidOperationException($"unmapped parameter set {p}"),
    };

    // === Sign / verify — pure SLH-DSA, round trip + tamper ================

    [Theory(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_192F)]
    public void SignVerifyData_RoundTrips_OverManagedToken(CkpSlhDsa parameterSet) =>
        WithSlhDsa(parameterSet, slhdsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("SLH-DSA on a managed token");
            byte[] sig = slhdsa.SignData(data);
            Assert.Equal(slhdsa.Algorithm.SignatureSizeInBytes, sig.Length);
            Assert.True(slhdsa.VerifyData(data, sig));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(slhdsa.VerifyData(tampered, sig));
        });

    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void SignVerifyData_WithContext_RoundTrips() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("context-bound message");
            byte[] context = Encoding.UTF8.GetBytes("app-context");

            byte[] sig = slhdsa.SignData(data, context);
            Assert.True(slhdsa.VerifyData(data, sig, context));
            // A signature made with a context must not verify without it.
            Assert.False(slhdsa.VerifyData(data, sig));
        });

    // A tampered signature must be rejected by the token.
    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void VerifyData_TamperedSignature_ReturnsFalse() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("integrity of the signature itself");
            byte[] sig = slhdsa.SignData(data);

            byte[] tampered = [.. sig];
            tampered[0] ^= 0xFF;
            Assert.False(slhdsa.VerifyData(data, tampered));
        });

    // === BCL cross-checks =================================================

    // The token's exported public key is the FIPS 205 standard encoding; an independent BCL SlhDsa
    // built from it must verify a signature the token produced.
    [Theory(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F)]
    public void TokenSignature_VerifiesWithBcl(CkpSlhDsa parameterSet) =>
        WithSlhDsa(parameterSet, slhdsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("token signs, BCL verifies");
            byte[] sig = slhdsa.SignData(data);

            byte[] pub = slhdsa.ExportSlhDsaPublicKey();
            using var bcl = SlhDsa.ImportSlhDsaPublicKey(BclAlgorithm(parameterSet), pub);

            Assert.True(bcl.VerifyData(data, sig));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(bcl.VerifyData(tampered, sig));
        });

    // The token's exported public key round-trips byte-for-byte through a BCL import/re-export, and
    // the BCL agrees on context binding for a token-produced, context-bound signature.
    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void ExportedPublicKey_RoundTripsThroughBcl_AndBclAgreesOnContext() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("context-bound, BCL-checked");
            byte[] context = Encoding.UTF8.GetBytes("ctx");

            byte[] pub = slhdsa.ExportSlhDsaPublicKey();
            using var bcl = SlhDsa.ImportSlhDsaPublicKey(
                BclAlgorithm(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F), pub);

            // The exported public key is the standard FIPS 205 encoding the BCL accepts and re-emits.
            Assert.Equal(pub, bcl.ExportSlhDsaPublicKey());

            // A token-produced, context-bound signature verifies on the BCL only WITH the context.
            byte[] sig = slhdsa.SignData(data, context);
            Assert.True(bcl.VerifyData(data, sig, context));
            Assert.False(bcl.VerifyData(data, sig));
        });

    // The exported public key is exactly PublicKeySizeInBytes for the parameter set.
    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void ExportSlhDsaPublicKey_ReturnsStandardEncoding() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        {
            byte[] pub = slhdsa.ExportSlhDsaPublicKey();
            Assert.Equal(slhdsa.Algorithm.PublicKeySizeInBytes, pub.Length);
        });

    // === Context-length validation =======================================

    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void SignData_ContextTooLong_Throws() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
            // The BCL validates the >255-byte context first (ArgumentOutOfRangeException) before our
            // own ArgumentException would fire; both derive from ArgumentException.
            Assert.ThrowsAny<ArgumentException>(() => slhdsa.SignData(new byte[4], new byte[256])));

    // === Private-key export is refused ===================================

    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void ExportSlhDsaPrivateKey_ThrowsInsecure() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
            Assert.Throws<InsecureOperationException>(() => slhdsa.ExportSlhDsaPrivateKey()));

    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
            Assert.Throws<InsecureOperationException>(() => slhdsa.ExportPkcs8PrivateKey()));

    // === Construction / argument validation (throws before any native call) ===

    [Fact]
    public void Ctor_NonSlhDsaKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new SlhDsaPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new SlhDsaPkcs11(null!));

    // === ResolveAlgorithm / attribute-read edge cases ======================
    //
    // A real token can't be coaxed into reporting CKA_PARAMETER_SET as sensitive, or into
    // returning a value it never advertises, on a well-formed SLH-DSA key object — these are
    // fallback paths a fake library must drive.

    private static byte[] UlongAttr(ulong value) =>
        BitConverter.GetBytes(value).AsSpan(0, UnmanagedMemory.NativeULongSize).ToArray();

    [Fact]
    public void Ctor_ParameterSetAttributeSensitive_ThrowsArgumentException()
    {
        using var key = FakeKeys.Create(CKK.CKK_SLH_DSA, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null));

        var ex = Assert.Throws<ArgumentException>(() => new SlhDsaPkcs11(key));
        Assert.Equal("key", ex.ParamName);
        Assert.Contains("not readable", ex.Message);
    }

    [Fact]
    public void Ctor_UnrecognizedParameterSet_ThrowsArgumentException()
    {
        using var key = FakeKeys.Create(CKK.CKK_SLH_DSA, _ => (CKR.CKR_OK, UlongAttr(0xFFFF)));

        var ex = Assert.Throws<ArgumentException>(() => new SlhDsaPkcs11(key));
        Assert.Equal("key", ex.ParamName);
        Assert.Contains("Unrecognized SLH-DSA parameter set", ex.Message);
    }

    // Drives all twelve CKP_SLH_DSA_* arms of ResolveAlgorithm's switch via a fake key instead of a
    // real token: real key-gen + sign/verify round trips are reserved above for a handful of fast
    // variants (SLH-DSA "s"-variant signing is slow), so most of the twelve arms are otherwise never
    // exercised. This only needs the base SlhDsa constructor to succeed, not an actual signature.
    [Theory(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_128S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_192S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_192F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_256S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_256F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F)]
    public void Ctor_ResolvesAlgorithm_ForEveryParameterSet(CkpSlhDsa parameterSet)
    {
        using var key = FakeKeys.Create(CKK.CKK_SLH_DSA, _ => (CKR.CKR_OK, UlongAttr((ulong)parameterSet)));
        using var slhdsa = new SlhDsaPkcs11(key);

        Assert.Equal(BclAlgorithm(parameterSet), slhdsa.Algorithm);
    }

    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void ExportSlhDsaPublicKey_ValueAttributeSensitive_ThrowsPkcs11Exception()
    {
        using var key = FakeKeys.Create(CKK.CKK_SLH_DSA, ca => ca == CKA.CKA_PARAMETER_SET
            ? (CKR.CKR_OK, UlongAttr((ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128S))
            : (CKR.CKR_ATTRIBUTE_SENSITIVE, null));
        using var slhdsa = new SlhDsaPkcs11(key);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => slhdsa.ExportSlhDsaPublicKey());
        Assert.Equal(CKR.CKR_ATTRIBUTE_SENSITIVE, ex.ReturnValue);
    }

    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void ExportSlhDsaPublicKey_TokenReturnsWrongLength_ThrowsPkcs11Exception()
    {
        // A well-formed token could never return a length other than the one it advertised via
        // its own CKA_PARAMETER_SET, so this drives CopyExact's mismatch guard.
        using var key = FakeKeys.Create(CKK.CKK_SLH_DSA, ca => ca == CKA.CKA_PARAMETER_SET
            ? (CKR.CKR_OK, UlongAttr((ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128S))
            : (CKR.CKR_OK, new byte[1]));
        using var slhdsa = new SlhDsaPkcs11(key);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => slhdsa.ExportSlhDsaPublicKey());
        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
    }
}
