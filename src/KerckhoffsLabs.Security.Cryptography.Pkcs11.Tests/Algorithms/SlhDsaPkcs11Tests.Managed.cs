using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
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
public sealed class SlhDsaPkcs11Tests_Managed
{
    public static bool SlhDsaSupported => SlhDsa.IsSupported;

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
        CkpSlhDsa.CKP_SLH_DSA_SHA2_128F => SlhDsaAlgorithm.SlhDsaSha2_128f,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_192F => SlhDsaAlgorithm.SlhDsaSha2_192f,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F => SlhDsaAlgorithm.SlhDsaShake128f,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F => SlhDsaAlgorithm.SlhDsaShake256f,
        _ => throw new InvalidOperationException($"unmapped parameter set {p}"),
    };

    // === Sign / verify — pure SLH-DSA, round trip + tamper ================

    [ConditionalTheory(nameof(SlhDsaSupported))]
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

    [ConditionalFact(nameof(SlhDsaSupported))]
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
    [ConditionalFact(nameof(SlhDsaSupported))]
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
    [ConditionalTheory(nameof(SlhDsaSupported))]
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
    [ConditionalFact(nameof(SlhDsaSupported))]
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
    [ConditionalFact(nameof(SlhDsaSupported))]
    public void ExportSlhDsaPublicKey_ReturnsStandardEncoding() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        {
            byte[] pub = slhdsa.ExportSlhDsaPublicKey();
            Assert.Equal(slhdsa.Algorithm.PublicKeySizeInBytes, pub.Length);
        });

    // === Context-length validation =======================================

    [ConditionalFact(nameof(SlhDsaSupported))]
    public void SignData_ContextTooLong_Throws() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
            // The BCL validates the >255-byte context first (ArgumentOutOfRangeException) before our
            // own ArgumentException would fire; both derive from ArgumentException.
            Assert.ThrowsAny<ArgumentException>(() => slhdsa.SignData(new byte[4], new byte[256])));

    // === Private-key export is refused ===================================

    [ConditionalFact(nameof(SlhDsaSupported))]
    public void ExportSlhDsaPrivateKey_ThrowsInsecure() =>
        WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
            Assert.Throws<InsecureOperationException>(() => slhdsa.ExportSlhDsaPrivateKey()));

    [ConditionalFact(nameof(SlhDsaSupported))]
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
}
