using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// DSAPkcs11 is intentionally [Obsolete] (DSA is disallowed by FIPS 186-5); exercising it here is deliberate.
#pragma warning disable KLPKCS11006
// SHA-1 is passed on purpose: its refusal is the behaviour under test.
#pragma warning disable KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// DSAPkcs11 over the in-process <c>ManagedSoftToken</c>. The BCL can't generate a DSA key inside a
/// caller-provided (P,Q,G) domain, so a complete BCL key is imported (C_CreateObject) as a public +
/// private object pair linked by CKA_ID; the token reconstructs a live DSA from the attributes. The
/// suite mirrors <c>DSAPkcs11Tests.SoftHsm2</c>: sign/verify data and hash run on-token (combined
/// CKM_DSA_SHA*, raw CKM_DSA r‖s), tampering is rejected, exported public material is cross-checked
/// against the BCL, and parameter export/import follow the adapter's non-extractable contract.
/// </summary>
[Collection(FakeModuleCollection.Name)]
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

    // With publicObject false only the private half is imported: a key that can sign but has no public value.
    private static void WithDsa(Action<DSAPkcs11, DSA, Pkcs11Session> body, bool publicObject = true)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);

        using var bcl = DSA.Create(2048);
        DSAParameters full = bcl.ExportParameters(includePrivateParameters: true);

        string label = $"dsa-{Guid.NewGuid():N}";
        byte[] id = Guid.NewGuid().ToByteArray();

        // Import the public half first, then the private half (which discovers its companion by CKA_ID).
        if (publicObject)
        {
            using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_DSA)
                .Label(label).Id(id)
                .Attribute(CKA.CKA_PRIME, full.P!).Attribute(CKA.CKA_SUBPRIME, full.Q!)
                .Attribute(CKA.CKA_BASE, full.G!).Attribute(CKA.CKA_VALUE, full.Y!)
                .Verify().Build();
            _ = session.ImportKey(pubTpl);
        }

        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_DSA)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_PRIME, full.P!).Attribute(CKA.CKA_SUBPRIME, full.Q!)
            .Attribute(CKA.CKA_BASE, full.G!).Attribute(CKA.CKA_VALUE, full.X!)
            .Sign().Build();
        using var key = session.ImportKey(privTpl);
        using var dsa = new DSAPkcs11(key);
        body(dsa, bcl, session);
    }

    // === Sign / verify data: on-token round-trip + tamper rejection =======================

    [Theory(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void SignVerifyData_RoundTrips_AndRejectsTampering(string hashName) => WithDsa((dsa, _, session) =>
    {
        var hash = new HashAlgorithmName(hashName);
        byte[] data = Encoding.UTF8.GetBytes($"dsa round trip over {hashName}");
        // DSA is FIPS-186-5-disallowed and gated at the mechanism layer; opt in to exercise it.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
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
    public void TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(string hashName) => WithDsa((dsa, _, session) =>
    {
        var hash = new HashAlgorithmName(hashName);
        byte[] data = Encoding.UTF8.GetBytes($"span-based dsa round trip over {hashName}");
        Span<byte> destination = new byte[256];

        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
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
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => WithDsa((dsa, _, session) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("destination too small");
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            bool ok = dsa.TrySignData(data, [], HashAlgorithmName.SHA256, out int bytesWritten);
            Assert.False(ok);
            Assert.Equal(0, bytesWritten);
        }
    });

    // The IEEE P1363 signature has a fixed size (twice the length of q), and a destination of exactly that
    // size is enough.
    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void TrySignData_DestinationOfExactlyTheSignatureSize_Succeeds() => WithDsa((dsa, _, session) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("exact destination");
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            Assert.True(dsa.TrySignData(data, new byte[256], HashAlgorithmName.SHA256, out int size));
            byte[] destination = new byte[size];

            Assert.True(dsa.TrySignData(data, destination, HashAlgorithmName.SHA256, out int written));

            Assert.Equal(size, written);
            Assert.True(dsa.VerifyData((ReadOnlySpan<byte>)data, (ReadOnlySpan<byte>)destination, HashAlgorithmName.SHA256));
        }
    });

    // Pkcs11MechanismMap.DsaSign accepts SHA224 (CKM_DSA_SHA224 exists in the spec), but this
    // adapter's own managed-fallback HashData helper has no SHA224 case — a real gap, surfaced only
    // via the fallback branch a backend without CKM_DSA_SHA224 support takes.
    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void TrySignData_Sha224_ThrowsNotSupported_ViaManagedFallbackHasher() => WithDsa((dsa, _, session) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("sha224 is not in HashData's switch");
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            var ex = Assert.Throws<NotSupportedException>(
                () => dsa.TrySignData(data, new byte[256], new HashAlgorithmName("SHA224"), out int unused));
            Assert.Contains("SHA224", ex.Message);
        }
    });

    // === Secure-defaults gate: DSA is insecure as an algorithm, so every sign/verify is refused =====
    // unless the session's crypto policy permits it (the check gates all CKM_DSA* — raw and combined, every hash).

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void SignData_GatedByDefault_Throws() => WithDsa((dsa, _) =>
        Assert.Throws<CryptoPolicyViolationException>(
            () => dsa.SignData(Encoding.UTF8.GetBytes("x"), HashAlgorithmName.SHA256)));

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void CreateSignature_GatedByDefault_Throws() => WithDsa((dsa, _) =>
        Assert.Throws<CryptoPolicyViolationException>(
            () => dsa.CreateSignature(SHA256.HashData("x"u8.ToArray()))));

    // === BCL cross-check: token signature verifies under the exported public key ==========

    [Theory(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void SignData_VerifiesUnderBclWithExportedPublicKey(string hashName) => WithDsa((dsa, _, session) =>
    {
        var hash = new HashAlgorithmName(hashName);
        byte[] data = Encoding.UTF8.GetBytes("interop with the BCL");
        byte[] sig;
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            sig = dsa.SignData(data, hash);

        // Export the token's public parameters and verify the token signature with the BCL.
        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
        using var bcl = DSA.Create();
        bcl.ImportParameters(pub);
        Assert.True(bcl.VerifyData(data, sig, hash));
    });

    // Reverse direction: a signature produced by the originating BCL key must verify on-token.
    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void VerifyData_BclSignature_OnToken() => WithDsa((dsa, bcl, session) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("signed by the BCL, verified on the token");
        byte[] sig = bcl.SignData(data, HashAlgorithmName.SHA256);
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            Assert.True(dsa.VerifyData(data, sig, HashAlgorithmName.SHA256));
    });

    // === Sign / verify a hash: raw CKM_DSA, IEEE P1363 (r‖s) ==============================

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void CreateSignature_VerifySignature_OverHash_RoundTrips() => WithDsa((dsa, _, session) =>
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("hash to sign"));
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
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
    public void CreateSignature_VerifiesUnderBcl() => WithDsa((dsa, _, session) =>
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("raw hash interop"));
        byte[] sig;
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
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
        Assert.Throws<CryptoPolicyViolationException>(() => dsa.ExportParameters(includePrivateParameters: true)));

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
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

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
        }, publicOnly: true);
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
        }, publicOnly: true);
        using var dsa = new DSAPkcs11(key);

        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
        Assert.Equal(new byte[] { 0x02, 0x03 }, pub.G);
        Assert.Equal(new byte[] { 0x05, 0x06 }, pub.Y);
    }

    // On the private-key object CKA_VALUE is X, not Y. A private-only key whose X the token leaves
    // readable must not have it exported as the public value.
    [Fact]
    public void ExportParameters_PrivateOnlyKey_NeverReadsThePrivateValue()
    {
        byte[] privateValue = [0x0A, 0x0B];
        using var key = FakeKeys.Create(CKK.CKK_DSA, ca => ca switch
        {
            CKA.CKA_PRIME => (CKR.CKR_OK, (byte[])[0x01, 0x02]),
            CKA.CKA_SUBPRIME => (CKR.CKR_OK, (byte[])[0x05]),
            CKA.CKA_BASE => (CKR.CKR_OK, (byte[])[0x01, 0x03]),
            CKA.CKA_VALUE => (CKR.CKR_OK, privateValue),
            _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        });
        using var dsa = new DSAPkcs11(key);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => dsa.ExportParameters(includePrivateParameters: false));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    // === Verification with a DSASignatureFormat: token errors propagate ======================
    //
    // The base VerifySignatureCore read q through ExportParameters(false) inside a catch of
    // CryptographicException, so any Pkcs11Exception from that read became false and C_Verify was never
    // called. The adapter's override reads only CKA_SUBPRIME: to size a DER signature's conversion, and to
    // check an r‖s signature's length, on every verification path, with a format or without.

    private const DSASignatureFormat P1363 = DSASignatureFormat.IeeeP1363FixedFieldConcatenation;

    // Each formatted verification entry point, over the data or its SHA-256 hash.
    private static readonly Dictionary<string, Func<DSAPkcs11, byte[], byte[], DSASignatureFormat, bool>> FormattedVerifies = new()
    {
        ["VerifyData(byte[])"] = (d, data, sig, f) => d.VerifyData(data, sig, HashAlgorithmName.SHA256, f),
        ["VerifyData(byte[], offset, count)"] = (d, data, sig, f) => d.VerifyData(data, 0, data.Length, sig, HashAlgorithmName.SHA256, f),
        ["VerifyData(span)"] = (d, data, sig, f) => d.VerifyData(data.AsSpan(), sig.AsSpan(), HashAlgorithmName.SHA256, f),
        ["VerifyData(Stream)"] = (d, data, sig, f) =>
        {
            using var stream = new MemoryStream(data);
            return d.VerifyData(stream, sig, HashAlgorithmName.SHA256, f);
        },
        ["VerifySignature(byte[])"] = (d, data, sig, f) => d.VerifySignature(SHA256.HashData(data), sig, f),
        ["VerifySignature(span)"] = (d, data, sig, f) => d.VerifySignature(SHA256.HashData(data).AsSpan(), sig.AsSpan(), f),
    };

    public static TheoryData<string, DSASignatureFormat> FormattedVerifyCases()
    {
        var cases = new TheoryData<string, DSASignatureFormat>();
        foreach (string name in FormattedVerifies.Keys)
        {
            cases.Add(name, P1363);
            cases.Add(name, Der);
        }
        return cases;
    }

    // A key with no public-key object cannot verify: the token's error must reach the caller rather than
    // read as an invalid signature.
    [Theory(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    [MemberData(nameof(FormattedVerifyCases))]
    public void FormattedVerify_NoPublicKeyObject_ThrowsTheTokensError(string call, DSASignatureFormat format) => WithDsa((dsa, bcl, session) =>
    {
        byte[] sig = bcl.SignData(Data, HashAlgorithmName.SHA256, format);
        using var policy = session.UsePolicy(CryptoPolicy.AllowInsecure);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => FormattedVerifies[call](dsa, Data, sig, format));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }, publicObject: false);

    [Theory(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    [MemberData(nameof(FormattedVerifyCases))]
    public void FormattedVerify_BclSignature_VerifiesOnToken_AndTamperedDoesNot(string call, DSASignatureFormat format) => WithDsa((dsa, bcl, session) =>
    {
        byte[] sig = bcl.SignData(Data, HashAlgorithmName.SHA256, format);
        byte[] badSig = [.. sig];
        badSig[^1] ^= 0xFF;
        using var policy = session.UsePolicy(CryptoPolicy.AllowInsecure);

        Assert.True(FormattedVerifies[call](dsa, Data, sig, format));
        Assert.False(FormattedVerifies[call](dsa, Data, badSig, format));
    });

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void FormattedVerify_GatedByDefault_Throws() => WithDsa((dsa, bcl) =>
    {
        foreach (DSASignatureFormat format in (DSASignatureFormat[])[P1363, Der])
        {
            byte[] sig = bcl.SignData(Data, HashAlgorithmName.SHA256, format);
            Assert.Throws<CryptoPolicyViolationException>(
                () => dsa.VerifySignature(SHA256.HashData(Data), sig, format));
        }
    });

    // Both formats need q: DER to size the conversion, P1363 to check the signature's length. A failed read
    // is the token's error.
    [Theory]
    [InlineData(DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]
    [InlineData(DSASignatureFormat.Rfc3279DerSequence)]
    public void FormattedVerify_SubprimeReadFails_ThrowsTheTokensError(DSASignatureFormat format)
    {
        using var key = FakeKeys.Create(CKK.CKK_DSA, _ => (CKR.CKR_DEVICE_ERROR, null), CryptoPolicy.AllowInsecure, publicOnly: true);
        using var dsa = new DSAPkcs11(key);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => dsa.VerifySignature(new byte[32], SignatureIn(format), format));
        Assert.Equal(CKR.CKR_DEVICE_ERROR, ex.ReturnValue);
    }

    // An attribute that cannot be read may be sensitive or missing, which the token does not tell apart for
    // one attribute among several, so no return code is claimed for it.
    [Theory]
    [InlineData(CKR.CKR_ATTRIBUTE_SENSITIVE, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]
    [InlineData(CKR.CKR_ATTRIBUTE_SENSITIVE, DSASignatureFormat.Rfc3279DerSequence)]
    [InlineData(CKR.CKR_ATTRIBUTE_TYPE_INVALID, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]
    [InlineData(CKR.CKR_ATTRIBUTE_TYPE_INVALID, DSASignatureFormat.Rfc3279DerSequence)]
    public void FormattedVerify_SubprimeUnreadable_ThrowsPkcs11AttributeException(CKR rv, DSASignatureFormat format)
    {
        using var key = FakeKeys.Create(CKK.CKK_DSA, _ => (rv, null), CryptoPolicy.AllowInsecure, publicOnly: true);
        using var dsa = new DSAPkcs11(key);

        var ex = Assert.Throws<Pkcs11AttributeException>(() => dsa.VerifySignature(new byte[32], SignatureIn(format), format));
        Assert.Equal(CKA.CKA_SUBPRIME, ex.Attribute);
    }

    // A q of zero is no key's: the token's malformed key is an error, not every signature failing to verify.
    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0x00, 0x00 })]
    public void Verify_SubprimeIsZero_ThrowsAttributeValueInvalid(byte[] subprime)
    {
        using var key = FakeKeys.Create(CKK.CKK_DSA, _ => (CKR.CKR_OK, subprime), CryptoPolicy.AllowInsecure, publicOnly: true);
        using var dsa = new DSAPkcs11(key);

        Func<bool>[] verifies =
        [
            () => dsa.VerifySignature(new byte[32], new byte[2]),
            () => dsa.VerifySignature(new byte[32], new byte[2], P1363),
            () => dsa.VerifySignature(new byte[32], SignatureIn(Der), Der),
        ];
        Assert.All(verifies, verify =>
            Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID, Assert.ThrowsAny<Pkcs11Exception>(() => verify()).ReturnValue));
    }

    private static byte[] SignatureIn(DSASignatureFormat format) =>
        format == Der ? DSAPkcs11TestCases.DerSignature([0x01], [0x02]) : new byte[64];

    // === An r‖s signature of the wrong length does not verify, and never reaches the token =========
    //
    // NSS answers one with CKR_ARGUMENTS_BAD rather than a verdict. The fake key's q is one byte long, so an
    // r‖s signature is two; its module refuses C_VerifyInit, so reaching the token throws.

    private static FakeKey OneByteSubprimeKey(Action onSubprimeRead, ICryptoPolicy? policy = null) =>
        FakeKeys.Create(CKK.CKK_DSA, ca =>
        {
            if (ca != CKA.CKA_SUBPRIME)
                return (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null);
            onSubprimeRead();
            return (CKR.CKR_OK, [0x05]);
        }, policy ?? CryptoPolicy.AllowInsecure, publicOnly: true);

    private static readonly Dictionary<string, Func<DSAPkcs11, byte[], bool>> HashVerifies = new()
    {
        ["VerifySignature(byte[])"] = (d, sig) => d.VerifySignature(new byte[32], sig),
        ["VerifySignature(byte[], P1363)"] = (d, sig) => d.VerifySignature(new byte[32], sig, P1363),
        ["VerifySignature(span, P1363)"] = (d, sig) => d.VerifySignature(new byte[32].AsSpan(), sig.AsSpan(), P1363),
        ["VerifyData(byte[], P1363)"] = (d, sig) => d.VerifyData(new byte[3], sig, HashAlgorithmName.SHA256, P1363),
    };

    public static TheoryData<string> HashVerifyNames() => [.. HashVerifies.Keys];

    [Theory]
    [MemberData(nameof(HashVerifyNames))]
    public void P1363Verify_SignatureOfTheWrongLength_ReturnsFalse_WithoutTheToken(string call)
    {
        using var key = OneByteSubprimeKey(() => { });
        using var dsa = new DSAPkcs11(key);

        Assert.False(HashVerifies[call](dsa, new byte[1]));
        Assert.False(HashVerifies[call](dsa, new byte[3]));
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => HashVerifies[call](dsa, new byte[2]));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    // The policy still refuses DSA before the length decides anything.
    [Fact]
    public void P1363Verify_SignatureOfTheWrongLength_GatedByDefault_Throws()
    {
        using var key = OneByteSubprimeKey(() => { }, CryptoPolicy.SecureOnly);
        using var dsa = new DSAPkcs11(key);

        Assert.Throws<CryptoPolicyViolationException>(() => dsa.VerifySignature(new byte[32], new byte[3]));
    }

    // The policy is asked before the token is read, so a refused mechanism is refused as such, even when the
    // read would fail.
    [Theory]
    [MemberData(nameof(HashVerifyNames))]
    public void Verify_GatedByDefault_ThrowsBeforeReadingTheToken(string call)
    {
        int reads = 0;
        using var key = FakeKeys.Create(CKK.CKK_DSA, _ =>
        {
            reads++;
            return (CKR.CKR_DEVICE_ERROR, null);
        }, CryptoPolicy.SecureOnly, publicOnly: true);
        using var dsa = new DSAPkcs11(key);
        reads = 0; // The constructor reads the key's size.

        Assert.Throws<CryptoPolicyViolationException>(() => HashVerifies[call](dsa, new byte[2]));
        Assert.Throws<CryptoPolicyViolationException>(() => dsa.VerifySignature(new byte[32], SignatureIn(Der), Der));
        Assert.Equal(0, reads);
    }

    // A key with no public-key object cannot verify, and says so whatever the signature: its length or
    // encoding does not turn that error into false.
    [Theory]
    [MemberData(nameof(HashVerifyNames))]
    public void Verify_NoPublicKeyObject_ThrowsWhateverTheSignature(string call)
    {
        using var key = FakeKeys.Create(CKK.CKK_DSA, _ => (CKR.CKR_OK, [0x05]), CryptoPolicy.AllowInsecure);
        using var dsa = new DSAPkcs11(key);

        foreach (byte[] signature in (byte[][])[[], new byte[1], new byte[2], new byte[3]])
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => HashVerifies[call](dsa, signature));
            Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
        }
        foreach (byte[] signature in (byte[][])[[0x30, 0x00], [0x04], DSAPkcs11TestCases.DerSignature([0x01], [0x02])])
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => dsa.VerifySignature(new byte[32], signature, Der));
            Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
        }
    }

    [Fact]
    public void SubprimeLength_IsReadOnce()
    {
        int reads = 0;
        using var key = OneByteSubprimeKey(() => reads++);
        using var dsa = new DSAPkcs11(key);

        Assert.False(dsa.VerifySignature(new byte[32], new byte[3]));
        int afterFirst = reads;
        Assert.False(dsa.VerifySignature(new byte[32], new byte[3], P1363));
        Assert.False(dsa.VerifySignature(new byte[32], (byte[])[0x30, 0x00], Der));

        // C_GetAttributeValue may be called twice for one read (its length, then its value).
        Assert.NotEqual(0, afterFirst);
        Assert.Equal(afterFirst, reads);
    }

    // Once q's length is read, a signature of the wrong length is decided without the token, but a disposed
    // key or a closed session still throws rather than answering false.
    [Theory]
    [MemberData(nameof(HashVerifyNames))]
    public void P1363Verify_SignatureOfTheWrongLength_KeyDisposed_Throws(string call)
    {
        using var key = OneByteSubprimeKey(() => { });
        using var dsa = new DSAPkcs11(key);
        Assert.False(HashVerifies[call](dsa, new byte[3]));

        key.Key.Dispose();

        Assert.Throws<ObjectDisposedException>(() => HashVerifies[call](dsa, new byte[3]));
    }

    [Theory]
    [MemberData(nameof(HashVerifyNames))]
    public void P1363Verify_SignatureOfTheWrongLength_SessionClosed_Throws(string call)
    {
        using var key = OneByteSubprimeKey(() => { });
        using var dsa = new DSAPkcs11(key);
        Assert.False(HashVerifies[call](dsa, new byte[3]));

        key.Key.Session.Dispose();

        Assert.Throws<ObjectDisposedException>(() => HashVerifies[call](dsa, new byte[3]));
    }

    // The shared cases build DER from a token's r‖s halves, which start with a zero byte about once in 256.
    [Fact]
    public void DerSignature_HalvesWithLeadingZeros_AreEncodedMinimally()
    {
        Assert.Equal(Convert.FromHexString("300702010502020085"), DSAPkcs11TestCases.DerSignature([0x00, 0x05], [0x00, 0x00, 0x85]));
        Assert.Equal(Convert.FromHexString("3006020100020100"), DSAPkcs11TestCases.DerSignature([0x00, 0x00], [0x00]));
    }

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void FormattedVerify_UnknownFormat_ThrowsAsTheBclDoes() => WithDsa((dsa, bcl) =>
    {
        const DSASignatureFormat unknown = (DSASignatureFormat)99;
        byte[] hash = SHA256.HashData(Data);

        var expected = Assert.Throws<ArgumentOutOfRangeException>(() => bcl.VerifySignature(hash, new byte[64], unknown));
        var actual = Assert.Throws<ArgumentOutOfRangeException>(() => dsa.VerifySignature(hash, new byte[64], unknown));
        Assert.Equal(expected.ParamName, actual.ParamName);
        actual = Assert.Throws<ArgumentOutOfRangeException>(() => dsa.VerifyData(Data, new byte[64], HashAlgorithmName.SHA256, unknown));
        Assert.Equal(expected.ParamName, actual.ParamName);

        // Unreachable through the public overloads, which check first; the Core refuses it as DSAOpenSsl's does.
        Assert.Throws<CryptographicException>(() => CallVerifySignatureCore(dsa, hash, new byte[64], unknown));
    });

    private delegate bool VerifySignatureCoreCall(
        DSAPkcs11 dsa, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, DSASignatureFormat signatureFormat);

    // An open-instance delegate over the protected override: MethodInfo.Invoke cannot pass a span.
    private static readonly VerifySignatureCoreCall CallVerifySignatureCore = typeof(DSAPkcs11)
        .GetMethod("VerifySignatureCore", BindingFlags.Instance | BindingFlags.NonPublic)!
        .CreateDelegate<VerifySignatureCoreCall>();

    // GetMaxSignatureSize is not virtual and reads q through ExportParameters(false), as the class remarks
    // say: it works with the public-key object and throws without it, although that key can sign.
    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void GetMaxSignatureSize_WithPublicKeyObject_IsSizedFromQ() => WithDsa((dsa, bcl) =>
    {
        Assert.Equal(bcl.GetMaxSignatureSize(P1363), dsa.GetMaxSignatureSize(P1363));
        Assert.Equal(bcl.GetMaxSignatureSize(Der), dsa.GetMaxSignatureSize(Der));
    });

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void GetMaxSignatureSize_NoPublicKeyObject_ThrowsPkcs11Exception() => WithDsa((dsa, _, session) =>
    {
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            Assert.NotEmpty(dsa.CreateSignature(SHA256.HashData(Data)));

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => dsa.GetMaxSignatureSize(P1363));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }, publicObject: false);

    // === The hash is put to the policy on every path that hashes on the managed side ==========

    // Permits DSA but refuses SHA-1, whether asked about the hash or about the combined CKM_DSA_SHA1. The
    // built-in policies refuse or allow the two together; a custom one may not, and must still be obeyed.
    private sealed class NoSha1Policy : ICryptoPolicy
    {
        public string Name => "NoSha1";
        public bool AllowsOverride => true;
        public PolicyDecision Evaluate(PolicyRequest request) => request switch
        {
            HashUseRequest { Hash.Name: "SHA1" } => PolicyDecision.Deny("no SHA-1"),
            MechanismUseRequest { Mechanism.Type: CKM.CKM_DSA_SHA1 } => PolicyDecision.Deny("no SHA-1"),
            _ => PolicyDecision.Allow,
        };
    }

    private static readonly HashAlgorithmName Sha1 = HashAlgorithmName.SHA1;
    private const DSASignatureFormat Der = DSASignatureFormat.Rfc3279DerSequence;

    // A byte[], not a collection expression: the BCL has span overloads too, which C# would prefer.
    private static readonly byte[] Data = [1, 2, 3];

    // Each entry point, and the operation the refusal must name; the Stream ones read the stream the theory
    // owns. The managed token does not advertise CKM_DSA_SHA1, so TrySignData takes the fallback that
    // hashes on the managed side.
    private static readonly Dictionary<string, (Action<DSAPkcs11, Stream> Call, CryptoOperation Operation)> Sha1Calls = new()
    {
        ["SignData(byte[])"] = ((d, _) => d.SignData(Data, Sha1), CryptoOperation.Sign),
        ["SignData(byte[], format)"] = ((d, _) => d.SignData(Data, Sha1, Der), CryptoOperation.Sign),
        ["SignData(Stream)"] = ((d, stream) => d.SignData(stream, Sha1), CryptoOperation.Sign),
        ["SignData(Stream, format)"] = ((d, stream) => d.SignData(stream, Sha1, Der), CryptoOperation.Sign),
        ["TrySignData(span)"] = ((d, _) => d.TrySignData(Data, new byte[256], Sha1, out int _), CryptoOperation.Sign),
        ["VerifyData(byte[])"] = ((d, _) => d.VerifyData(Data, new byte[64], Sha1), CryptoOperation.Verify),
        ["VerifyData(byte[], format)"] = ((d, _) => d.VerifyData(Data, new byte[64], Sha1, Der), CryptoOperation.Verify),
        ["VerifyData(Stream)"] = ((d, stream) => d.VerifyData(stream, new byte[64], Sha1), CryptoOperation.Verify),
        ["VerifyData(Stream, format)"] = ((d, stream) => d.VerifyData(stream, new byte[64], Sha1, Der), CryptoOperation.Verify),
        ["VerifyData(span, format)"] = ((d, _) => d.VerifyData(Data.AsSpan(), new byte[64].AsSpan(), Sha1, Der), CryptoOperation.Verify),
    };

    public static TheoryData<string> Sha1CallNames() => [.. Sha1Calls.Keys];

    [Theory(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    [MemberData(nameof(Sha1CallNames))]
    public void Sha1_IsRefused_ByAPolicyThatPermitsDsa(string call) => WithDsa((dsa, _, session) =>
    {
        using var policy = session.UsePolicy(new NoSha1Policy());

        using var stream = new MemoryStream(Data);

        var e = Assert.Throws<CryptoPolicyViolationException>(() => Sha1Calls[call].Call(dsa, stream));

        Assert.Equal(Sha1Calls[call].Operation, Assert.IsType<HashUseRequest>(e.Request).Operation);
    });

    // The verification overrides check the hash name as the BCL does, naming hashAlgorithm.
    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void VerifyData_HashName_IsCheckedAsTheBclChecksIt() => WithDsa((dsa, _) =>
    {
        using var stream = new MemoryStream(Data);
        byte[] sig = new byte[64];
        var empty = new HashAlgorithmName("");

        Assert.Equal("hashAlgorithm", Assert.Throws<ArgumentNullException>(() => dsa.VerifyData(Data, sig, default)).ParamName);
        Assert.Equal("hashAlgorithm", Assert.Throws<ArgumentException>(() => dsa.VerifyData(Data, sig, empty)).ParamName);
        Assert.Equal("hashAlgorithm", Assert.Throws<ArgumentNullException>(() => dsa.VerifyData(stream, sig, default)).ParamName);
        Assert.Equal("hashAlgorithm", Assert.Throws<ArgumentException>(() => dsa.VerifyData(stream, sig, empty)).ParamName);
    });

    // The same policy lets a strong hash through on the paths that now ask about it.
    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void Sha256_IsAllowed_ByThatPolicy() => WithDsa((dsa, _, session) =>
    {
        using var policy = session.UsePolicy(new NoSha1Policy());
        byte[] data = Encoding.UTF8.GetBytes("strong hash");

        byte[] sig = dsa.SignData(data, HashAlgorithmName.SHA256);
        using var stream = new MemoryStream(data);

        Assert.True(dsa.VerifyData(data, sig, HashAlgorithmName.SHA256));
        Assert.True(dsa.VerifyData(stream, sig, HashAlgorithmName.SHA256));
    });
}
