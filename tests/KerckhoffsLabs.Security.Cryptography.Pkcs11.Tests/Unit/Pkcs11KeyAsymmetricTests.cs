using System.Formats.Asn1;
using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// SLH-DSA and the ML-DSA / ML-KEM SubjectPublicKeyInfo exports are evaluation-only BCL APIs.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The key-type-neutral members of <see cref="Pkcs11Key"/> over the in-process <c>ManagedSoftToken</c>:
/// <see cref="Pkcs11Key.KeySize"/>, <see cref="Pkcs11Key.Export"/>, <see cref="Pkcs11Key.DeriveRawSecret"/>
/// and <see cref="Pkcs11Key.DeriveSecretAgreement"/>, cross-checked against the BCL. The adapters are built on
/// them, and their own tests cover the same behaviour through the BCL surface.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11KeyAsymmetricTests
{
    public static bool Supported { get; } = Probe();

    private static bool Probe()
    {
        try
        {
            using (ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256)) { }
            using (ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384)) { }
            return true;
        }
        catch (PlatformNotSupportedException) { return false; }
        catch (CryptographicException) { return false; }
    }

    private const string P256 = "1.2.840.10045.3.1.7";
    private const string P384 = "1.3.132.0.34";

    private static void WithKey(Func<Pkcs11Session, Pkcs11Key> generate, Action<Pkcs11Key> body, bool allowExtraction = false)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using IDisposable? insecure = allowExtraction ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;
        using var key = generate(session);
        body(key);
    }

    private static void WithEcKey(string oid, Action<Pkcs11Key> body, bool allowExtraction = false)
        => WithKey(s => s.GenerateEcKeyPair(Pkcs11ECCurve.CreateFromValue(oid)), body, allowExtraction);

    private static void WithAesKey(Action<Pkcs11Key> body) => WithKey(s => s.GenerateAesKey(256), body);

    // === KeySize ==============================================================

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData(P256, 256)]
    [InlineData(P384, 384)]
    public void KeySize_EcKey_IsTheCurveFieldSize(string oid, int bits)
        => WithEcKey(oid, key => Assert.Equal(bits, key.KeySize));

    [Fact]
    public void KeySize_RsaKey_IsTheModulusSize()
        => WithKey(s => s.GenerateRsaSigningKeyPair(3072), key => Assert.Equal(3072, key.KeySize));

    [Fact]
    public void KeySize_SecretKey_IsTheValueLength() => WithAesKey(key => Assert.Equal(256, key.KeySize));

    [Fact]
    public void KeySize_DisposedKey_Throws() => WithAesKey(key =>
    {
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => key.KeySize);
    });

    // === Export ===============================================================

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void Export_SubjectPublicKeyInfo_IsImportedByTheBcl() => WithEcKey(P256, key =>
    {
        byte[] spki = key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo);

        using var bcl = ECDiffieHellman.Create();
        bcl.ImportSubjectPublicKeyInfo(spki, out int read);
        Assert.Equal(spki.Length, read);
        ECParameters p = bcl.ExportParameters(includePrivateParameters: false);
        Assert.Equal(P256, p.Curve.Oid.Value);
        Assert.Equal(spki, bcl.ExportSubjectPublicKeyInfo());
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void Export_RawPublicKey_IsTheUncompressedPointOfTheSpki() => WithEcKey(P256, key =>
    {
        byte[] raw = key.Export(Pkcs11KeyBlobFormat.RawPublicKey);
        using var bcl = ECDiffieHellman.Create();
        bcl.ImportSubjectPublicKeyInfo(key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo), out _);
        ECParameters p = bcl.ExportParameters(includePrivateParameters: false);

        Assert.Equal([0x04, .. p.Q.X!, .. p.Q.Y!], raw);
    });

    [Fact]
    public void Export_Rsa_SubjectPublicKeyInfo_IsWhatTheBclWrites() => WithKey(s => s.GenerateRsaSigningKeyPair(3072), key =>
    {
        byte[] spki = key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo);

        using var bcl = RSA.Create();
        bcl.ImportSubjectPublicKeyInfo(spki, out int read);
        Assert.Equal(spki.Length, read);
        Assert.Equal(3072, bcl.KeySize);
        Assert.Equal(spki, bcl.ExportSubjectPublicKeyInfo());
    });

    [Fact]
    public void Export_Rsa_RawPublicKey_IsPkcs1RsaPublicKey() => WithKey(s => s.GenerateRsaSigningKeyPair(3072), key =>
    {
        using var bcl = RSA.Create();
        bcl.ImportSubjectPublicKeyInfo(key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo), out _);

        Assert.Equal(bcl.ExportRSAPublicKey(), key.Export(Pkcs11KeyBlobFormat.RawPublicKey));
    });

    // macOS's BCL can't generate a 2048-bit DSA key, so the key can't be made there.
    public static bool DsaSupported { get; } = ProbeDsa();

    private static bool ProbeDsa()
    {
        try
        {
            using (DSA.Create(2048)) { }
            return true;
        }
        catch (PlatformNotSupportedException) { return false; }
        catch (CryptographicException) { return false; }
    }

    [Fact(SkipUnless = nameof(DsaSupported), Skip = "Requires " + nameof(DsaSupported))]
    public void Export_Dsa_SubjectPublicKeyInfo_IsWhatTheBclWrites()
    {
        using var bcl = DSA.Create(2048);
        DSAParameters p = bcl.ExportParameters(includePrivateParameters: false);

        WithKey(s =>
        {
            using var template = ObjectTemplate.ForPublicKey(CKK.CKK_DSA)
                .Attribute(CKA.CKA_PRIME, p.P!).Attribute(CKA.CKA_SUBPRIME, p.Q!)
                .Attribute(CKA.CKA_BASE, p.G!).Attribute(CKA.CKA_VALUE, p.Y!)
                .Verify().Build();
            return s.ImportKey(template);
        }, key =>
        {
            Assert.Equal(2048, key.KeySize);
            Assert.Equal(bcl.ExportSubjectPublicKeyInfo(), key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo));
        });
    }

    // === Export: ML-DSA, SLH-DSA, ML-KEM (over a fake token: no platform PQC support needed) =====

    private static byte[] UlongAttr(ulong value) =>
        BitConverter.GetBytes(value).AsSpan(0, KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.UnmanagedMemory.NativeULongSize).ToArray();

    private static FakeKey PostQuantumKey(CKK keyType, ulong parameterSet, byte[] value, bool publicOnly = true)
        => FakeKeys.Create(keyType, ca => ca switch
        {
            CKA.CKA_PARAMETER_SET => (CKR.CKR_OK, UlongAttr(parameterSet)),
            CKA.CKA_VALUE => (CKR.CKR_OK, value),
            _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        }, publicOnly: publicOnly);

    // The OIDs and lengths written out here rather than read from the library's table, so a mistyped
    // entry fails: NIST CSOR / RFC 9881 / RFC 9909, FIPS 203/204/205.
    [Theory]
    [InlineData(CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_44, "2.16.840.1.101.3.4.3.17", 1312)]
    [InlineData(CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_65, "2.16.840.1.101.3.4.3.18", 1952)]
    [InlineData(CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_87, "2.16.840.1.101.3.4.3.19", 2592)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128S, "2.16.840.1.101.3.4.3.20", 32)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, "2.16.840.1.101.3.4.3.21", 32)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_192S, "2.16.840.1.101.3.4.3.22", 48)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_192F, "2.16.840.1.101.3.4.3.23", 48)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_256S, "2.16.840.1.101.3.4.3.24", 64)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_256F, "2.16.840.1.101.3.4.3.25", 64)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S, "2.16.840.1.101.3.4.3.26", 32)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F, "2.16.840.1.101.3.4.3.27", 32)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S, "2.16.840.1.101.3.4.3.28", 48)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F, "2.16.840.1.101.3.4.3.29", 48)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S, "2.16.840.1.101.3.4.3.30", 64)]
    [InlineData(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F, "2.16.840.1.101.3.4.3.31", 64)]
    [InlineData(CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_512, "2.16.840.1.101.3.4.4.1", 800)]
    [InlineData(CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_768, "2.16.840.1.101.3.4.4.2", 1184)]
    [InlineData(CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_1024, "2.16.840.1.101.3.4.4.3", 1568)]
    public void Export_PostQuantum_NamesTheParameterSet(CKK keyType, ulong parameterSet, string oid, int length)
    {
        byte[] value = RandomNumberGenerator.GetBytes(length);
        using var key = PostQuantumKey(keyType, parameterSet, value);

        Assert.Equal(value, key.Key.Export(Pkcs11KeyBlobFormat.RawPublicKey));

        var outer = new AsnReader(key.Key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo), AsnEncodingRules.DER);
        AsnReader info = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        AsnReader algorithm = info.ReadSequence();
        Assert.Equal(oid, algorithm.ReadObjectIdentifier());
        Assert.False(algorithm.HasData); // parameters absent
        Assert.Equal(value, info.ReadBitString(out int unusedBits));
        Assert.Equal(0, unusedBits);
        info.ThrowIfNotEmpty();
    }

    // On the private-key object CKA_VALUE is the private key. A private-only key must not have it
    // exported as the public key, however readable the token leaves it.
    [Fact]
    public void Export_PostQuantum_PrivateOnlyKey_NeverReadsThePrivateValue()
    {
        using var key = PostQuantumKey(CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_44, new byte[1312], publicOnly: false);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Key.Export(Pkcs11KeyBlobFormat.RawPublicKey));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    [Fact]
    public void Export_PostQuantum_UnrecognizedParameterSet_Throws()
    {
        using var key = PostQuantumKey(CKK.CKK_ML_KEM, 0xFFFF, new byte[800]);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo));
        Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID, ex.ReturnValue);
    }

    // Where the platform implements the algorithm, the SPKI is byte for byte what the BCL writes.
    [Fact(SkipUnless = nameof(MLDsa.IsSupported), SkipType = typeof(MLDsa), Skip = "Requires " + nameof(MLDsa.IsSupported))]
    public void Export_MlDsa_SubjectPublicKeyInfo_IsWhatTheBclWrites()
    {
        using var bcl = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var key = PostQuantumKey(CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_65, bcl.ExportMLDsaPublicKey());
        Assert.Equal(bcl.ExportSubjectPublicKeyInfo(), key.Key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo));
    }

    [Fact(SkipUnless = nameof(SlhDsa.IsSupported), SkipType = typeof(SlhDsa), Skip = "Requires " + nameof(SlhDsa.IsSupported))]
    public void Export_SlhDsa_SubjectPublicKeyInfo_IsWhatTheBclWrites()
    {
        using var bcl = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake128f);
        using var key = PostQuantumKey(CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F, bcl.ExportSlhDsaPublicKey());
        Assert.Equal(bcl.ExportSubjectPublicKeyInfo(), key.Key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo));
    }

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Export_MlKem_SubjectPublicKeyInfo_IsWhatTheBclWrites()
    {
        using var bcl = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        using var key = PostQuantumKey(CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_768, bcl.ExportEncapsulationKey());
        Assert.Equal(bcl.ExportSubjectPublicKeyInfo(), key.Key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo));
    }

    [Fact]
    public void Export_SecretKey_IsNotSupported() => WithAesKey(key =>
        Assert.Throws<NotSupportedException>(() => key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo)));

    [Fact]
    public void Export_UndefinedFormat_Throws() => WithAesKey(key =>
        Assert.Throws<ArgumentOutOfRangeException>(() => key.Export((Pkcs11KeyBlobFormat)42)));

    // === DeriveRawSecret ======================================================

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData(P256, 32)]
    [InlineData(P384, 48)]
    public void DeriveRawSecret_MatchesBcl(string oid, int fieldSizeBytes) => WithEcKey(oid, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.CreateFromValue(oid));
        using var alicePublic = ECDiffieHellman.Create();
        alicePublic.ImportSubjectPublicKeyInfo(alice.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo), out _);

        byte[] aliceZ = alice.DeriveRawSecret(bob.ExportSubjectPublicKeyInfo());
        byte[] bobZ = bob.DeriveRawSecretAgreement(alicePublic.PublicKey);

        Assert.Equal(fieldSizeBytes, aliceZ.Length);
        Assert.Equal(bobZ, aliceZ);
    }, allowExtraction: true);

    // A token that returns Z shorter than the field (leading zeros dropped) is refused, not passed on as a
    // different secret, and the ephemeral derived key is still destroyed.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecret_TokenDropsLeadingBytes_Throws()
    {
        var token = new ManagedSoftToken { EcdhDropsLeadingBytes = 1 };
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.CreateFromValue(P256));
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        var ex = Assert.Throws<CryptographicException>(() => alice.DeriveRawSecret(bob.ExportSubjectPublicKeyInfo()));

        Assert.Contains("31-byte", ex.Message, StringComparison.Ordinal);
    }

    // The export check runs before the peer is looked at: even garbage gets the policy refusal.
    [Fact]
    public void DeriveRawSecret_DefaultPolicy_IsRefusedBeforeThePeerIsRead() => WithEcKey(P256, alice =>
        Assert.Throws<CryptoPolicyViolationException>(() => alice.DeriveRawSecret([0x30, 0x00])));

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecret_PeerOnAnotherCurve_Throws() => WithEcKey(P256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384);
        Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecret(bob.ExportSubjectPublicKeyInfo()));
    }, allowExtraction: true);

    // A point off the curve is the invalid-curve attack's input; it must never reach C_DeriveKey.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecret_PointOffTheCurve_Throws() => WithEcKey(P256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters peer = bob.ExportParameters(includePrivateParameters: false);
        peer.Q.Y![^1] ^= 1;

        Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecret(SubjectPublicKeyInfoEncoding.EncodeEc(peer)));
    }, allowExtraction: true);

    [Fact]
    public void DeriveRawSecret_PeerOfAnotherAlgorithm_Throws() => WithEcKey(P256, alice =>
    {
        using var rsa = RSA.Create(2048);
        Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecret(rsa.ExportSubjectPublicKeyInfo()));
    }, allowExtraction: true);

    [Fact]
    public void DeriveRawSecret_NotASubjectPublicKeyInfo_Throws() => WithEcKey(P256, alice =>
    {
        var ex = Assert.Throws<ArgumentException>(() => alice.DeriveRawSecret([0x04, 0x01, 0x02]));
        Assert.Equal("peerSubjectPublicKeyInfo", ex.ParamName);
    }, allowExtraction: true);

    // RFC 5480 permits compressed points, but the token needs the uncompressed form and decompressing
    // is not this library's job.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecret_CompressedPoint_Throws() => WithEcKey(P256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters p = bob.ExportParameters(includePrivateParameters: false);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.10045.2.1"); // id-ecPublicKey
                writer.WriteObjectIdentifier(P256);
            }
            writer.WriteBitString([(byte)(0x02 | (p.Q.Y![^1] & 1)), .. p.Q.X!]);
        }

        var ex = Assert.Throws<ArgumentException>(() => alice.DeriveRawSecret(writer.Encode()));
        Assert.Equal("peerSubjectPublicKeyInfo", ex.ParamName);
    }, allowExtraction: true);

    [Fact]
    public void DeriveRawSecret_SecretKey_IsNotSupported() => WithAesKey(key =>
        Assert.Throws<NotSupportedException>(() => key.DeriveRawSecret([])));

    // === DeriveSecretAgreement ================================================

    private static readonly byte[] HkdfSalt = "agreement salt"u8.ToArray();
    private static readonly byte[] HkdfInfo = "mac key"u8.ToArray();
    private static readonly byte[] ProbeMessage = "probe"u8.ToArray();

    public static TheoryData<string> Policies => ["Recommended", "NistApproved"];

    // The whole key schedule on the token under a default policy: agree into Z, HKDF Z into an HMAC key,
    // MAC a probe. No secret byte is read; the BCL peer computes the same MAC from its own Z.
    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [MemberData(nameof(Policies))]
    public void DeriveSecretAgreement_ThenHkdfOnTheToken_MatchesBcl(string policy)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, policy == "NistApproved" ? CryptoPolicy.NistApproved : CryptoPolicy.Recommended);
        using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        using Pkcs11Key z = alice.DeriveSecretAgreement(bob.ExportSubjectPublicKeyInfo());

        using var macTemplate = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Sign().Build();
        using Pkcs11Key macKey = z.Derive(
            new Mechanism(CKM.CKM_HKDF_DERIVE,
                CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, HkdfSalt, HkdfInfo)),
            macTemplate);
        byte[] tag = macKey.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), ProbeMessage);

        using var alicePublic = ECDiffieHellman.Create();
        alicePublic.ImportSubjectPublicKeyInfo(alice.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo), out _);
        byte[] bobZ = bob.DeriveRawSecretAgreement(alicePublic.PublicKey);
        byte[] expected = HMACSHA256.HashData(HKDF.DeriveKey(HashAlgorithmName.SHA256, bobZ, 32, HkdfSalt, HkdfInfo), ProbeMessage);

        Assert.Equal(expected, tag);
    }

    // Z can only feed a derivation: the token refuses it as a MAC key.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveSecretAgreement_ResultIsNotAWorkingKey() => WithEcKey(P256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        using Pkcs11Key z = alice.DeriveSecretAgreement(bob.ExportSubjectPublicKeyInfo());

        using var attrs = z.GetAttributeValue(CKA.CKA_DERIVE, CKA.CKA_SIGN, CKA.CKA_ENCRYPT, CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE);
        Assert.True(attrs[0].GetValueAsBool());
        Assert.False(attrs[1].GetValueAsBool());
        Assert.False(attrs[2].GetValueAsBool());
        Assert.True(attrs[3].GetValueAsBool());
        Assert.False(attrs[4].GetValueAsBool());
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveSecretAgreement_PointOffTheCurve_Throws() => WithEcKey(P256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters peer = bob.ExportParameters(includePrivateParameters: false);
        peer.Q.Y![^1] ^= 1;

        Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveSecretAgreement(SubjectPublicKeyInfoEncoding.EncodeEc(peer)));
    });

    // The policy widening is for derivation-only results: CKD_NULL straight into a working key stays refused.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void CkdNull_IntoAWorkingKey_IsStillRefused() => WithEcKey(P256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters peer = bob.ExportParameters(includePrivateParameters: false);
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE,
            new CkmEcdh1DeriveParams(CKD.CKD_NULL, EcPointEncoding.Encode(peer.Q.X!, peer.Q.Y!)));
        using var aes = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Encrypt().Decrypt().Build();

        Assert.Throws<CryptoPolicyViolationException>(() => alice.Derive(mechanism, aes));
    });

    [Fact]
    public void DeriveSecretAgreement_SecretKey_IsNotSupported() => WithAesKey(key =>
        Assert.Throws<NotSupportedException>(() => key.DeriveSecretAgreement([])));
}
