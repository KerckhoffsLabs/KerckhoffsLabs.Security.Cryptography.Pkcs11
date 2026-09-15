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
[NoBackendCollection("Drives a per-test ManagedSoftToken in process — no native module is loaded and " +
                     "the token holds no static state, so this is safe alongside every backend collection.")]
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

    [Theory(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
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
            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(dsa.VerifyData(tampered, sig, hash));

            // Tamper the signature: verify must fail.
            byte[] badSig = [.. sig];
            badSig[0] ^= 0xFF;
            Assert.False(dsa.VerifyData(data, badSig, hash));
        }
    });

    // === Sign / verify via the Span-based combined path (TrySignData / VerifyData override) ==========
    //
    // DSA.SignData(byte[], HashAlgorithmName) is a NON-virtual convenience overload with no Span-input
    // counterpart returning byte[] (verified by reflection) — it never calls TrySignData. Calling it
    // with byte[] arguments, as every test above does, exercises the base class's generic hash +
    // CreateSignature(hash) path, not DSAPkcs11's own TrySignData/VerifyData override/SignDataInternal/
    // HashData. The only way to reach those is TrySignData(...) directly and VerifyData with arguments
    // typed as ReadOnlySpan<byte> (forcing the compiler to pick the virtual span overload instead of the
    // non-virtual byte[] one). ManagedSoftToken doesn't advertise the combined CKM_DSA_SHA* mechanisms
    // (see C_GetMechanismList), so SupportsMechanism is always false here and these always take the
    // "hash managed-side, sign/verify raw CKM_DSA" fallback branch — the SupportsMechanism==true branch
    // needs a real backend that advertises CKM_DSA_SHA*.

    [Theory(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    [InlineData("SHA1")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(string hashName) => WithDsa((dsa, _, workspace) =>
    {
        var hash = new HashAlgorithmName(hashName);
        byte[] data = Encoding.UTF8.GetBytes($"span-based dsa round trip over {hashName}");
        Span<byte> destination = new byte[256];

        using (workspace.AllowInsecureScope())
        {
            Assert.True(dsa.TrySignData(data, destination, hash, out int bytesWritten));
            byte[] sig = destination[..bytesWritten].ToArray();

            Assert.True(dsa.VerifyData((ReadOnlySpan<byte>)data, (ReadOnlySpan<byte>)sig, hash));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(dsa.VerifyData((ReadOnlySpan<byte>)tampered, (ReadOnlySpan<byte>)sig, hash));

            byte[] badSig = [.. sig];
            badSig[0] ^= 0xFF;
            Assert.False(dsa.VerifyData((ReadOnlySpan<byte>)data, (ReadOnlySpan<byte>)badSig, hash));
        }
    });

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => WithDsa((dsa, _, workspace) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("destination too small");
        using (workspace.AllowInsecureScope())
        {
            bool ok = dsa.TrySignData(data, [], HashAlgorithmName.SHA256, out int bytesWritten);
            Assert.False(ok);
            Assert.Equal(0, bytesWritten);
        }
    });

    // Pkcs11MechanismMap.DsaSign accepts SHA224 (CKM_DSA_SHA224 exists in the spec), but this
    // adapter's own managed-fallback HashData helper has no SHA224 case — a real gap, surfaced only
    // via the fallback branch a backend without CKM_DSA_SHA224 support takes.
    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void TrySignData_Sha224_ThrowsNotSupported_ViaManagedFallbackHasher() => WithDsa((dsa, _, workspace) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("sha224 is not in HashData's switch");
        using (workspace.AllowInsecureScope())
        {
            var ex = Assert.Throws<NotSupportedException>(
                () => dsa.TrySignData(data, new byte[256], new HashAlgorithmName("SHA224"), out int unused));
            Assert.Contains("SHA224", ex.Message);
        }
    });

    // === Secure-defaults gate: DSA is insecure as an algorithm, so every sign/verify is refused =====
    // unless AllowInsecure (GuardMechanism gates all CKM_DSA* — raw and combined, every hash).

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void SignData_GatedByDefault_Throws() => WithDsa((dsa, _) =>
        Assert.Throws<InsecureOperationException>(
            () => dsa.SignData(Encoding.UTF8.GetBytes("x"), HashAlgorithmName.SHA256)));

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void CreateSignature_GatedByDefault_Throws() => WithDsa((dsa, _) =>
        Assert.Throws<InsecureOperationException>(
            () => dsa.CreateSignature(SHA256.HashData("x"u8.ToArray()))));

    // === BCL cross-check: token signature verifies under the exported public key ==========

    [Theory(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
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
    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void VerifyData_BclSignature_OnToken() => WithDsa((dsa, bcl, workspace) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("signed by the BCL, verified on the token");
        byte[] sig = bcl.SignData(data, HashAlgorithmName.SHA256);
        using (workspace.AllowInsecureScope())
            Assert.True(dsa.VerifyData(data, sig, HashAlgorithmName.SHA256));
    });

    // === Sign / verify a hash: raw CKM_DSA, IEEE P1363 (r‖s) ==============================

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
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

            byte[] badSig = [.. sig];
            badSig[0] ^= 0xFF;
            Assert.False(dsa.VerifySignature(hash, badSig));
        }
    });

    // The raw-hash signature must also verify under the BCL public key.
    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
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

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
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

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void ExportParameters_Private_ThrowsInsecure() => WithDsa((dsa, _) =>
        Assert.Throws<InsecureOperationException>(() => dsa.ExportParameters(includePrivateParameters: true)));

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
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

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void CreateSignature_NullHash_Throws() => WithDsa((dsa, _) =>
        Assert.Throws<ArgumentNullException>(() => dsa.CreateSignature(null!)));

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void VerifySignature_NullArguments_Throw() => WithDsa((dsa, _) =>
    {
        byte[] hash = SHA256.HashData("x"u8.ToArray());
        Assert.Throws<ArgumentNullException>(() => dsa.VerifySignature(null!, new byte[64]));
        Assert.Throws<ArgumentNullException>(() => dsa.VerifySignature(hash, null!));
    });

    // === KeySize / LegalKeySizes =============================================
    // Regression coverage for the adapter never assigning KeySizeValue: KeySize was 0 and
    // LegalKeySizes threw NullReferenceException.

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void KeySize_ReflectsTokenPrime() => WithDsa((dsa, _) =>
        Assert.Equal(2048, dsa.KeySize));

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void LegalKeySizes_ReflectsTokenPrime() => WithDsa((dsa, _) =>
    {
        KeySizes[] sizes = dsa.LegalKeySizes;
        KeySizes only = Assert.Single(sizes);
        Assert.Equal(2048, only.MinSize);
        Assert.Equal(2048, only.MaxSize);
    });

    // A real token can't be coaxed into failing to read CKA_PRIME — it's a required domain-parameter
    // attribute of every DSA key object — so this drives the fallback's error path via a fake library.
    [Fact]
    public void KeySize_PrimeAttributeFails_StaysAtBclDefault()
    {
        using var key = FakeKeys.Create(CKK.CKK_DSA, _ => (CKR.CKR_DEVICE_ERROR, null));
        using var dsa = new DSAPkcs11(key);
        Assert.Equal(0, dsa.KeySize);
    }

    // The non-fatal sibling of the test above: CKA_PRIME reads back with the CannotBeRead sentinel
    // (CKR_ATTRIBUTE_SENSITIVE) instead of throwing. Same fallback-to-default outcome, different branch
    // (the `attrs[0].CannotBeRead` check in TryReadKeySizeBits, not its surrounding try/catch).
    [Fact]
    public void KeySize_PrimeAttributeSensitive_StaysAtBclDefault()
    {
        using var key = FakeKeys.Create(CKK.CKK_DSA, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null));
        using var dsa = new DSAPkcs11(key);
        Assert.Equal(0, dsa.KeySize);
    }

    // A real token can't be coaxed into reporting its domain parameters / public value as sensitive on
    // a well-formed DSA key object, so this drives ExportParameters' fallback error path via a fake.
    [Fact]
    public void ExportParameters_AttributesSensitive_ThrowsPkcs11Exception()
    {
        using var key = FakeKeys.Create(CKK.CKK_DSA, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null));
        using var dsa = new DSAPkcs11(key);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => dsa.ExportParameters(includePrivateParameters: false));
        Assert.Equal(CKR.CKR_ATTRIBUTE_SENSITIVE, ex.ReturnValue);
    }

    // === LeftPad edge cases (G / Y shorter or longer than P after trimming leading zeros) ============
    //
    // A randomly-generated real key's G/Y only occasionally need padding (roughly 1-in-256 chance of a
    // leading zero byte for a 2048-bit prime), so these drive both branches deterministically with
    // fabricated attribute values a real backend would never actually return.

    [Fact]
    public void ExportParameters_BaseAndValueShorterThanPrime_AreLeftPadded()
    {
        using var key = FakeKeys.Create(CKK.CKK_DSA, ca => ca switch
        {
            CKA.CKA_PRIME => (CKR.CKR_OK, (byte[])[0x01, 0x02, 0x03, 0x04]),
            CKA.CKA_SUBPRIME => (CKR.CKR_OK, (byte[])[0x05, 0x06]),
            CKA.CKA_BASE => (CKR.CKR_OK, (byte[])[0x07]),
            CKA.CKA_VALUE => (CKR.CKR_OK, (byte[])[0x08]),
            _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        });
        using var dsa = new DSAPkcs11(key);

        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
        Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x07 }, pub.G);
        Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x08 }, pub.Y);
    }

    [Fact]
    public void ExportParameters_BaseAndValueLongerThanPrime_AreTruncatedFromTheLeft()
    {
        using var key = FakeKeys.Create(CKK.CKK_DSA, ca => ca switch
        {
            CKA.CKA_PRIME => (CKR.CKR_OK, (byte[])[0x01, 0x02]),
            CKA.CKA_SUBPRIME => (CKR.CKR_OK, (byte[])[0x05]),
            CKA.CKA_BASE => (CKR.CKR_OK, (byte[])[0x01, 0x02, 0x03]),
            CKA.CKA_VALUE => (CKR.CKR_OK, (byte[])[0x04, 0x05, 0x06]),
            _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        });
        using var dsa = new DSAPkcs11(key);

        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
        Assert.Equal(new byte[] { 0x02, 0x03 }, pub.G);
        Assert.Equal(new byte[] { 0x05, 0x06 }, pub.Y);
    }
}
