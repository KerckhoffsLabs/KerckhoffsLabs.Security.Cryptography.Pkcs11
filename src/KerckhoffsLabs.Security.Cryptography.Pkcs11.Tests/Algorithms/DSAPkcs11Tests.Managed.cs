using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// DSAPkcs11 is intentionally [Obsolete] (DSA is disallowed by FIPS 186-5); exercising it here is deliberate.
#pragma warning disable KLPKCS11006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// DSAPkcs11 over the in-process <c>ManagedSoftToken</c>. The BCL can't generate a DSA key inside a
/// caller-provided (P,Q,G) domain, so a complete BCL key is imported (C_CreateObject) as a public +
/// private object pair linked by CKA_ID; the token reconstructs a live DSA from the attributes. The
/// suite mirrors <c>DSAPkcs11Tests.SoftHsm2</c>: sign/verify data and hash run on-token (combined
/// CKM_DSA_SHA*, raw CKM_DSA r‖s), tampering is rejected, exported public material is cross-checked
/// against the BCL, and parameter export/import follow the adapter's non-extractable contract.
/// </summary>
public sealed class DSAPkcs11Tests_Managed
{
    // macOS's BCL (DSASecurityTransforms) can't generate a 2048-bit DSA key — DSA.Create(2048)
    // throws — so the managed token can't reconstruct one there. Gate on a one-time probe.
    public static bool DsaSupported { get; } = ProbeDsa();

    private static bool ProbeDsa()
    {
        try
        {
            using var d = DSA.Create(2048);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    // Imports a fresh BCL 2048-bit DSA key as a public+private object pair (linked by CKA_ID), wraps
    // it as DSAPkcs11, and hands both the adapter and the originating BCL key to the body so tests can
    // cross-check in either direction.
    private static void WithDsa(Action<DSAPkcs11, DSA> body)
        => WithDsa((dsa, bcl, _) => body(dsa, bcl));

    private static void WithDsa(Action<DSAPkcs11, DSA, Pkcs11Workspace> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        using var bcl = DSA.Create(2048);
        DSAParameters full = bcl.ExportParameters(includePrivateParameters: true);

        string label = $"dsa-{Guid.NewGuid():N}";
        byte[] id = Guid.NewGuid().ToByteArray();

        // Import the public half first, then the private half (which discovers its companion by CKA_ID).
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_DSA)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_PRIME, full.P!).Attribute(CKA.CKA_SUBPRIME, full.Q!)
            .Attribute(CKA.CKA_BASE, full.G!).Attribute(CKA.CKA_VALUE, full.Y!)
            .Verify().Build();
        _ = workspace.ImportKey(pubTpl);

        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_DSA)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_PRIME, full.P!).Attribute(CKA.CKA_SUBPRIME, full.Q!)
            .Attribute(CKA.CKA_BASE, full.G!).Attribute(CKA.CKA_VALUE, full.X!)
            .Sign().Build();
        using var key = workspace.ImportKey(privTpl);
        using var dsa = new DSAPkcs11(key);
        body(dsa, bcl, workspace);
    }

    // === Sign / verify data: on-token round-trip + tamper rejection =======================

    [ConditionalTheory(nameof(DsaSupported))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void SignVerifyData_RoundTrips_AndRejectsTampering(string hashName) => WithDsa((dsa, _, workspace) =>
    {
        var hash = new HashAlgorithmName(hashName);
        byte[] data = Encoding.UTF8.GetBytes($"dsa round trip over {hashName}");
        // DSA is FIPS-186-5-disallowed and gated at the mechanism layer; opt in to exercise it.
        using (workspace.AllowInsecureScope())
        {
            byte[] sig = dsa.SignData(data, hash);
            Assert.True(dsa.VerifyData(data, sig, hash));

            // Tamper the message: verify must fail.
            byte[] tampered = (byte[])data.Clone();
            tampered[0] ^= 0xFF;
            Assert.False(dsa.VerifyData(tampered, sig, hash));

            // Tamper the signature: verify must fail.
            byte[] badSig = (byte[])sig.Clone();
            badSig[0] ^= 0xFF;
            Assert.False(dsa.VerifyData(data, badSig, hash));
        }
    });

    // === Secure-defaults gate: DSA is insecure as an algorithm, so every sign/verify is refused =====
    // unless AllowInsecure (GuardMechanism gates all CKM_DSA* — raw and combined, every hash).

    [ConditionalFact(nameof(DsaSupported))]
    public void SignData_GatedByDefault_Throws() => WithDsa((dsa, _) =>
        Assert.Throws<InsecureOperationException>(
            () => dsa.SignData(Encoding.UTF8.GetBytes("x"), HashAlgorithmName.SHA256)));

    [ConditionalFact(nameof(DsaSupported))]
    public void CreateSignature_GatedByDefault_Throws() => WithDsa((dsa, _) =>
        Assert.Throws<InsecureOperationException>(
            () => dsa.CreateSignature(SHA256.HashData("x"u8.ToArray()))));

    // === BCL cross-check: token signature verifies under the exported public key ==========

    [ConditionalTheory(nameof(DsaSupported))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void SignData_VerifiesUnderBclWithExportedPublicKey(string hashName) => WithDsa((dsa, _, workspace) =>
    {
        var hash = new HashAlgorithmName(hashName);
        byte[] data = Encoding.UTF8.GetBytes("interop with the BCL");
        byte[] sig;
        using (workspace.AllowInsecureScope())
            sig = dsa.SignData(data, hash);

        // Export the token's public parameters and verify the token signature with the BCL.
        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
        using var bcl = DSA.Create();
        bcl.ImportParameters(pub);
        Assert.True(bcl.VerifyData(data, sig, hash));
    });

    // Reverse direction: a signature produced by the originating BCL key must verify on-token.
    [ConditionalFact(nameof(DsaSupported))]
    public void VerifyData_BclSignature_OnToken() => WithDsa((dsa, bcl, workspace) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("signed by the BCL, verified on the token");
        byte[] sig = bcl.SignData(data, HashAlgorithmName.SHA256);
        using (workspace.AllowInsecureScope())
            Assert.True(dsa.VerifyData(data, sig, HashAlgorithmName.SHA256));
    });

    // === Sign / verify a hash: raw CKM_DSA, IEEE P1363 (r‖s) ==============================

    [ConditionalFact(nameof(DsaSupported))]
    public void CreateSignature_VerifySignature_OverHash_RoundTrips() => WithDsa((dsa, _, workspace) =>
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("hash to sign"));
        using (workspace.AllowInsecureScope())
        {
            byte[] sig = dsa.CreateSignature(hash);
            Assert.True(dsa.VerifySignature(hash, sig));

            // P1363 r‖s: each component is q-sized (the subprime length of the exported domain).
            DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
            Assert.Equal(2 * pub.Q!.Length, sig.Length);

            byte[] badSig = (byte[])sig.Clone();
            badSig[0] ^= 0xFF;
            Assert.False(dsa.VerifySignature(hash, badSig));
        }
    });

    // The raw-hash signature must also verify under the BCL public key.
    [ConditionalFact(nameof(DsaSupported))]
    public void CreateSignature_VerifiesUnderBcl() => WithDsa((dsa, _, workspace) =>
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("raw hash interop"));
        byte[] sig;
        using (workspace.AllowInsecureScope())
            sig = dsa.CreateSignature(hash);

        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
        using var bcl = DSA.Create();
        bcl.ImportParameters(pub);
        // BCL VerifySignature consumes IEEE P1363 (r‖s), matching the adapter's CreateSignature output.
        Assert.True(bcl.VerifySignature(hash, sig));
    });

    // === Parameter export / import ========================================================

    [ConditionalFact(nameof(DsaSupported))]
    public void ExportParameters_ReturnsPublicDomainAndValue_ButNeverPrivate() => WithDsa((dsa, bcl) =>
    {
        DSAParameters expected = bcl.ExportParameters(includePrivateParameters: false);
        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);

        Assert.Equal(expected.P, pub.P);
        Assert.Equal(expected.Q, pub.Q);
        Assert.NotNull(pub.G);
        Assert.NotNull(pub.Y);
        Assert.Equal(pub.P!.Length, pub.G!.Length); // G/Y left-padded to the prime length
        Assert.Equal(pub.P!.Length, pub.Y!.Length);
        Assert.Null(pub.X); // never exports the private value
    });

    [ConditionalFact(nameof(DsaSupported))]
    public void ExportParameters_Private_ThrowsInsecure() => WithDsa((dsa, _) =>
        Assert.Throws<InsecureOperationException>(() => dsa.ExportParameters(includePrivateParameters: true)));

    [ConditionalFact(nameof(DsaSupported))]
    public void ImportParameters_NotSupported() => WithDsa((dsa, bcl) =>
    {
        DSAParameters pub = bcl.ExportParameters(includePrivateParameters: false);
        Assert.Throws<NotSupportedException>(() => dsa.ImportParameters(pub));
    });

    // === Construction / argument validation (runs before any native call) =================

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new DSAPkcs11(null!));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_NonDsaKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new DSAPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    [ConditionalFact(nameof(DsaSupported))]
    public void CreateSignature_NullHash_Throws() => WithDsa((dsa, _) =>
        Assert.Throws<ArgumentNullException>(() => dsa.CreateSignature(null!)));

    [ConditionalFact(nameof(DsaSupported))]
    public void VerifySignature_NullArguments_Throw() => WithDsa((dsa, _) =>
    {
        byte[] hash = SHA256.HashData("x"u8.ToArray());
        Assert.Throws<ArgumentNullException>(() => dsa.VerifySignature(null!, new byte[64]));
        Assert.Throws<ArgumentNullException>(() => dsa.VerifySignature(hash, null!));
    });
}
