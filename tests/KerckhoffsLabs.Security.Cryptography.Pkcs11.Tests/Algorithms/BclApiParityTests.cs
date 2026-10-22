using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

// The evaluation-only BCL types are named here only to inspect their members.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// The adapters that follow a BCL API without deriving from it, because the BCL type is sealed or static
/// (<see cref="AesGcm"/>, <see cref="HKDF"/>, ...), checked member for member against it. Every public member of
/// the BCL type is either mirrored by a named adapter member, a deviation with its reason, or a known gap; every
/// public member of the adapter is either such a counterpart or an addition with its reason.
/// </summary>
/// <remarks>
/// The adapters that derive from a BCL type are checked by <see cref="BclOverrideCoverageTests"/>; together the two
/// cover every public type in the Algorithms namespace, which <see cref="EveryPublicAlgorithmsType_IsCovered"/> pins.
/// The test fails when a .NET release adds a member to a mirrored BCL type, when an adapter gains or loses one,
/// and on an entry that matches nothing, so fixing a gap means changing its entry.
/// </remarks>
public sealed class BclApiParityTests
{
    /// <summary>A BCL type the adapter follows, and which of its members it follows.</summary>
    public sealed record Mirror(Type Adapter, Type[] Bcl, Func<MethodBase, bool>? BclMember = null);

    private static readonly Mirror[] Mirrors =
    [
        new(typeof(AesGcmPkcs11), [typeof(AesGcm)]),
        new(typeof(AesCcmPkcs11), [typeof(AesCcm)]),
        new(typeof(ChaCha20Poly1305Pkcs11), [typeof(ChaCha20Poly1305)]),
        new(typeof(HkdfPkcs11), [typeof(HKDF)]),
        new(typeof(SP800108HmacCounterKdfPkcs11), [typeof(SP800108HmacCounterKdf)]),
        new(typeof(Rfc2898DeriveBytesPkcs11), [typeof(Rfc2898DeriveBytes), typeof(DeriveBytes)]),
        // X509Certificate2's private-key members, and the extension classes that add the rest.
        new(typeof(Pkcs11CertificateExtensions),
            [typeof(X509Certificate2), typeof(RSACertificateExtensions), typeof(ECDsaCertificateExtensions), typeof(DSACertificateExtensions)],
            m => m.Name.EndsWith("PrivateKey", StringComparison.Ordinal)),
    ];

    // Public types of the namespace that follow no BCL type.
    private static readonly Dictionary<Type, string> NotBclShaped = new()
    {
        [typeof(Pkcs11MechanismMap)] = "The library's own mapping from BCL hash and padding names to PKCS#11 mechanisms.",
    };

    // === How each BCL member is followed ==========================================================

    private abstract record Parity;

    /// <summary>Mirrored by <paramref name="Counterpart"/>; <paramref name="Why"/> says why the signature differs, when it does.</summary>
    private sealed record Mirrored(string Counterpart, string? Why = null) : Parity;

    /// <summary>Deliberately not followed.</summary>
    private sealed record Deviation(string Reason) : Parity;

    /// <summary>Should be followed and is not.</summary>
    private sealed record Gap(string Description) : Parity;

    private static Mirrored Same(string signature) => new(signature);

    private static Mirrored As(string counterpart, string why) => new(counterpart, why);

    private const string TokenKey = "Takes the token key (Pkcs11Key) instead of key bytes, which never leave the token.";
    private const string IsSupportedPerToken =
        "Support depends on the token, not the platform: Pkcs11Key.SupportsMechanism answers it for the mechanism.";
    private const string ByteArrayAead =
        "The byte[] overload is missing. Arrays bind to the span overload instead, so a null array is taken as empty: a null " +
        "plaintext and ciphertext encrypt nothing without error, where the BCL throws ArgumentNullException.";
    private const string CcmTagSizePerCall =
        "AesCcm takes the tag size from each call's tag; AesCcmPkcs11's only constructor fixes it, and refuses a tag of " +
        "another legal size.";
    private const string KdfCharOverloads =
        "The string and ReadOnlySpan<char> label and context overloads, which the BCL encodes as UTF-8, are missing.";
    private const string KdfStaticKeyBytes = "Takes the key as bytes; derive through an instance over the token key.";
    private const string Pbkdf2Session = "Takes the session that runs PBKDF2 (CKM_PKCS5_PBKD2) as its first argument.";
    private const string ObsoleteDefaults =
        "Obsolete (SYSLIB0060), and defaults to SHA-1 and 1000 iterations; the adapter takes the hash and the iteration count explicitly.";
    private const string ObsoleteRandomSalt =
        "Obsolete (SYSLIB0060), and generates the salt; the adapter takes the salt, the hash and the iteration count explicitly.";
    private const string TokenCertificate =
        "Extends the token certificate (Pkcs11Certificate), whose private key is found on the token by CKA_ID.";
    private const string CopyWithPrivateKey =
        "Attaches a managed key to a certificate; a token certificate and its key are already paired on the token by CKA_ID.";

    private static readonly Dictionary<string, Dictionary<string, Parity>> Followed = new(StringComparer.Ordinal)
    {
        [nameof(AesGcmPkcs11)] = new(StringComparer.Ordinal)
        {
            ["ctor(Byte[])"] = new Deviation("Obsolete (SYSLIB0053): AesGcm is to be given its tag size."),
            ["ctor(ReadOnlySpan<Byte>)"] = new Deviation("Obsolete (SYSLIB0053): AesGcm is to be given its tag size."),
            ["ctor(Byte[], Int32)"] = As("ctor(Pkcs11Key, Int32)", TokenKey),
            ["ctor(ReadOnlySpan<Byte>, Int32)"] = As("ctor(Pkcs11Key, Int32)", TokenKey),
            ["Int32? TagSizeInBytes { get; }"] = As("Int32 TagSizeInBytes { get; }", "Never null: the only constructor takes the tag size."),
            ["Void Encrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"] =
                Same("Void Encrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"),
            ["Void Decrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"] =
                Same("Void Decrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"),
            ["Void Encrypt(Byte[], Byte[], Byte[], Byte[], Byte[])"] = new Gap(ByteArrayAead),
            ["Void Decrypt(Byte[], Byte[], Byte[], Byte[], Byte[])"] = new Gap(ByteArrayAead),
            ["Void Dispose()"] = Same("Void Dispose()"),
            ["static Boolean IsSupported { get; }"] = new Deviation(IsSupportedPerToken),
            ["static KeySizes NonceByteSizes { get; }"] = Same("static KeySizes NonceByteSizes { get; }"),
            ["static KeySizes TagByteSizes { get; }"] = Same("static KeySizes TagByteSizes { get; }"),
        },
        [nameof(AesCcmPkcs11)] = new(StringComparer.Ordinal)
        {
            ["ctor(Byte[])"] = new Gap(CcmTagSizePerCall),
            ["ctor(ReadOnlySpan<Byte>)"] = new Gap(CcmTagSizePerCall),
            ["Void Encrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"] =
                Same("Void Encrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"),
            ["Void Decrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"] =
                Same("Void Decrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"),
            ["Void Encrypt(Byte[], Byte[], Byte[], Byte[], Byte[])"] = new Gap(ByteArrayAead),
            ["Void Decrypt(Byte[], Byte[], Byte[], Byte[], Byte[])"] = new Gap(ByteArrayAead),
            ["Void Dispose()"] = Same("Void Dispose()"),
            ["static Boolean IsSupported { get; }"] = new Deviation(IsSupportedPerToken),
            ["static KeySizes NonceByteSizes { get; }"] = Same("static KeySizes NonceByteSizes { get; }"),
            ["static KeySizes TagByteSizes { get; }"] = Same("static KeySizes TagByteSizes { get; }"),
        },
        [nameof(ChaCha20Poly1305Pkcs11)] = new(StringComparer.Ordinal)
        {
            ["ctor(Byte[])"] = As("ctor(Pkcs11Key)", TokenKey),
            ["ctor(ReadOnlySpan<Byte>)"] = As("ctor(Pkcs11Key)", TokenKey),
            ["Void Encrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"] =
                Same("Void Encrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"),
            ["Void Decrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"] =
                Same("Void Decrypt(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"),
            ["Void Encrypt(Byte[], Byte[], Byte[], Byte[], Byte[])"] = new Gap(ByteArrayAead),
            ["Void Decrypt(Byte[], Byte[], Byte[], Byte[], Byte[])"] = new Gap(ByteArrayAead),
            ["Void Dispose()"] = Same("Void Dispose()"),
            ["static Boolean IsSupported { get; }"] = new Deviation(IsSupportedPerToken),
        },
        [nameof(HkdfPkcs11)] = new(StringComparer.Ordinal)
        {
            ["static Byte[] DeriveKey(HashAlgorithmName, Byte[], Int32, Byte[], Byte[])"] =
                As("static Byte[] DeriveKey(HashAlgorithmName, Pkcs11Key, Int32, Byte[], Byte[])", TokenKey),
            ["static Void DeriveKey(HashAlgorithmName, ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] =
                As("static Void DeriveKey(HashAlgorithmName, Pkcs11Key, Span<Byte>, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)", TokenKey),
            ["static Byte[] Extract(HashAlgorithmName, Byte[], Byte[])"] =
                As("static Byte[] Extract(HashAlgorithmName, Pkcs11Key, Byte[])", TokenKey),
            ["static Int32 Extract(HashAlgorithmName, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>)"] =
                As("static Int32 Extract(HashAlgorithmName, Pkcs11Key, ReadOnlySpan<Byte>, Span<Byte>)", TokenKey),
            ["static Byte[] Expand(HashAlgorithmName, Byte[], Int32, Byte[])"] =
                As("static Byte[] Expand(HashAlgorithmName, Pkcs11Key, Int32, Byte[])", TokenKey),
            ["static Void Expand(HashAlgorithmName, ReadOnlySpan<Byte>, Span<Byte>, ReadOnlySpan<Byte>)"] =
                As("static Void Expand(HashAlgorithmName, Pkcs11Key, Span<Byte>, ReadOnlySpan<Byte>)", TokenKey),
        },
        [nameof(SP800108HmacCounterKdfPkcs11)] = new(StringComparer.Ordinal)
        {
            ["ctor(Byte[], HashAlgorithmName)"] = As("ctor(Pkcs11Key, HashAlgorithmName)", TokenKey),
            ["ctor(ReadOnlySpan<Byte>, HashAlgorithmName)"] = As("ctor(Pkcs11Key, HashAlgorithmName)", TokenKey),
            ["Byte[] DeriveKey(Byte[], Byte[], Int32)"] = Same("Byte[] DeriveKey(Byte[], Byte[], Int32)"),
            ["Byte[] DeriveKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Int32)"] = Same("Byte[] DeriveKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Int32)"),
            ["Void DeriveKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>)"] = Same("Void DeriveKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>)"),
            ["Byte[] DeriveKey(String, String, Int32)"] = new Gap(KdfCharOverloads),
            ["Byte[] DeriveKey(ReadOnlySpan<Char>, ReadOnlySpan<Char>, Int32)"] = new Gap(KdfCharOverloads),
            ["Void DeriveKey(ReadOnlySpan<Char>, ReadOnlySpan<Char>, Span<Byte>)"] = new Gap(KdfCharOverloads),
            ["Void Dispose()"] = Same("Void Dispose()"),
            ["static Byte[] DeriveBytes(Byte[], HashAlgorithmName, Byte[], Byte[], Int32)"] = new Deviation(KdfStaticKeyBytes),
            ["static Byte[] DeriveBytes(Byte[], HashAlgorithmName, String, String, Int32)"] = new Deviation(KdfStaticKeyBytes),
            ["static Byte[] DeriveBytes(ReadOnlySpan<Byte>, HashAlgorithmName, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Int32)"] = new Deviation(KdfStaticKeyBytes),
            ["static Byte[] DeriveBytes(ReadOnlySpan<Byte>, HashAlgorithmName, ReadOnlySpan<Char>, ReadOnlySpan<Char>, Int32)"] = new Deviation(KdfStaticKeyBytes),
            ["static Void DeriveBytes(ReadOnlySpan<Byte>, HashAlgorithmName, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>)"] = new Deviation(KdfStaticKeyBytes),
            ["static Void DeriveBytes(ReadOnlySpan<Byte>, HashAlgorithmName, ReadOnlySpan<Char>, ReadOnlySpan<Char>, Span<Byte>)"] = new Deviation(KdfStaticKeyBytes),
        },
        [nameof(Rfc2898DeriveBytesPkcs11)] = new(StringComparer.Ordinal)
        {
            ["ctor(Byte[], Byte[], Int32, HashAlgorithmName)"] = As("ctor(Pkcs11Session, Byte[], Byte[], Int32, HashAlgorithmName)", Pbkdf2Session),
            ["ctor(String, Byte[], Int32, HashAlgorithmName)"] = As("ctor(Pkcs11Session, String, Byte[], Int32, HashAlgorithmName)", Pbkdf2Session),
            ["ctor(Byte[], Byte[], Int32)"] = new Deviation(ObsoleteDefaults),
            ["ctor(String, Byte[])"] = new Deviation(ObsoleteDefaults),
            ["ctor(String, Byte[], Int32)"] = new Deviation(ObsoleteDefaults),
            ["ctor(String, Int32)"] = new Deviation(ObsoleteRandomSalt),
            ["ctor(String, Int32, Int32)"] = new Deviation(ObsoleteRandomSalt),
            ["ctor(String, Int32, Int32, HashAlgorithmName)"] = new Deviation(ObsoleteRandomSalt),
            ["Byte[] CryptDeriveKey(String, String, Int32, Byte[])"] = new Deviation("Obsolete (SYSLIB0033), and not supported by the BCL itself."),
            ["Byte[] GetBytes(Int32)"] = Same("Byte[] GetBytes(Int32)"),
            ["Void Reset()"] = Same("Void Reset()"),
            ["Void Dispose()"] = Same("Void Dispose()"),
            ["Byte[] Salt { get; set; }"] = Same("Byte[] Salt { get; set; }"),
            ["Int32 IterationCount { get; set; }"] = Same("Int32 IterationCount { get; set; }"),
            ["HashAlgorithmName HashAlgorithm { get; }"] = Same("HashAlgorithmName HashAlgorithm { get; }"),
            ["static Byte[] Pbkdf2(Byte[], Byte[], Int32, HashAlgorithmName, Int32)"] =
                As("static Byte[] Pbkdf2(Pkcs11Session, Byte[], Byte[], Int32, HashAlgorithmName, Int32)", Pbkdf2Session),
            ["static Byte[] Pbkdf2(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Int32, HashAlgorithmName, Int32)"] =
                As("static Byte[] Pbkdf2(Pkcs11Session, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Int32, HashAlgorithmName, Int32)", Pbkdf2Session),
            ["static Byte[] Pbkdf2(String, Byte[], Int32, HashAlgorithmName, Int32)"] =
                As("static Byte[] Pbkdf2(Pkcs11Session, String, Byte[], Int32, HashAlgorithmName, Int32)", Pbkdf2Session),
            ["static Void Pbkdf2(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, Int32, HashAlgorithmName)"] =
                As("static Void Pbkdf2(Pkcs11Session, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Span<Byte>, Int32, HashAlgorithmName)", Pbkdf2Session),
            ["static Byte[] Pbkdf2(ReadOnlySpan<Char>, ReadOnlySpan<Byte>, Int32, HashAlgorithmName, Int32)"] =
                As("static Byte[] Pbkdf2(Pkcs11Session, ReadOnlySpan<Char>, ReadOnlySpan<Byte>, Int32, HashAlgorithmName, Int32)", Pbkdf2Session),
            ["static Void Pbkdf2(ReadOnlySpan<Char>, ReadOnlySpan<Byte>, Span<Byte>, Int32, HashAlgorithmName)"] =
                As("static Void Pbkdf2(Pkcs11Session, ReadOnlySpan<Char>, ReadOnlySpan<Byte>, Span<Byte>, Int32, HashAlgorithmName)", Pbkdf2Session),
        },
        [nameof(Pkcs11CertificateExtensions)] = new(StringComparer.Ordinal)
        {
            ["RSACertificateExtensions.static RSA GetRSAPrivateKey(X509Certificate2)"] =
                As("static RSA GetRSAPrivateKey(Pkcs11Certificate)", TokenCertificate),
            ["ECDsaCertificateExtensions.static ECDsa GetECDsaPrivateKey(X509Certificate2)"] =
                As("static ECDsa GetECDsaPrivateKey(Pkcs11Certificate)", TokenCertificate),
            ["DSACertificateExtensions.static DSA GetDSAPrivateKey(X509Certificate2)"] =
                As("static DSA GetDSAPrivateKey(Pkcs11Certificate)", TokenCertificate),
            ["X509Certificate2.ECDiffieHellman GetECDiffieHellmanPrivateKey()"] =
                As("static ECDiffieHellman GetECDiffieHellmanPrivateKey(Pkcs11Certificate)", TokenCertificate),
            ["X509Certificate2.MLDsa GetMLDsaPrivateKey()"] =
                As("static MLDsa GetMLDsaPrivateKey(Pkcs11Certificate)", TokenCertificate),
            ["X509Certificate2.MLKem GetMLKemPrivateKey()"] =
                As("static MLKem GetMLKemPrivateKey(Pkcs11Certificate)", TokenCertificate),
            ["X509Certificate2.SlhDsa GetSlhDsaPrivateKey()"] =
                As("static SlhDsa GetSlhDsaPrivateKey(Pkcs11Certificate)", TokenCertificate),
            ["X509Certificate2.CompositeMLDsa GetCompositeMLDsaPrivateKey()"] =
                new Deviation("PKCS#11 defines no composite ML-DSA mechanism, and the library has no adapter for it."),
            ["X509Certificate2.AsymmetricAlgorithm PrivateKey { get; set; }"] = new Deviation("Obsolete (SYSLIB0028)."),
            ["X509Certificate2.Boolean HasPrivateKey { get; }"] =
                new Deviation("Pkcs11Certificate.GetPrivateKey() answers it, looking for the key on the token."),
            ["DSACertificateExtensions.static X509Certificate2 CopyWithPrivateKey(X509Certificate2, DSA)"] = new Deviation(CopyWithPrivateKey),
            ["ECDsaCertificateExtensions.static X509Certificate2 CopyWithPrivateKey(X509Certificate2, ECDsa)"] = new Deviation(CopyWithPrivateKey),
            ["RSACertificateExtensions.static X509Certificate2 CopyWithPrivateKey(X509Certificate2, RSA)"] = new Deviation(CopyWithPrivateKey),
            ["X509Certificate2.X509Certificate2 CopyWithPrivateKey(CompositeMLDsa)"] = new Deviation(CopyWithPrivateKey),
            ["X509Certificate2.X509Certificate2 CopyWithPrivateKey(ECDiffieHellman)"] = new Deviation(CopyWithPrivateKey),
            ["X509Certificate2.X509Certificate2 CopyWithPrivateKey(MLDsa)"] = new Deviation(CopyWithPrivateKey),
            ["X509Certificate2.X509Certificate2 CopyWithPrivateKey(MLKem)"] = new Deviation(CopyWithPrivateKey),
            ["X509Certificate2.X509Certificate2 CopyWithPrivateKey(SlhDsa)"] = new Deviation(CopyWithPrivateKey),
        },
    };

    // === Adapter members with no BCL counterpart =====================================================

    private const string OnTokenResult = "Keeps the derived key on the token, where the BCL can only return its bytes.";

    private static readonly Dictionary<string, Dictionary<string, string>> Additions = new(StringComparer.Ordinal)
    {
        [nameof(AesGcmPkcs11)] = new(StringComparer.Ordinal),
        [nameof(AesCcmPkcs11)] = new(StringComparer.Ordinal)
        {
            ["ctor(Pkcs11Key, Int32)"] = "Takes the token key and fixes the tag size, as AesGcm does; see the AesCcm constructor gap.",
            ["Int32 TagSizeInBytes { get; }"] = "The tag size the constructor fixed, as AesGcm reports its own.",
        },
        [nameof(ChaCha20Poly1305Pkcs11)] = new(StringComparer.Ordinal)
        {
            ["static KeySizes NonceByteSizes { get; }"] = "The fixed 12-byte nonce, exposed as the AES-GCM and AES-CCM adapters expose theirs.",
            ["static KeySizes TagByteSizes { get; }"] = "The fixed 16-byte tag, exposed as the AES-GCM and AES-CCM adapters expose theirs.",
        },
        [nameof(HkdfPkcs11)] = new(StringComparer.Ordinal)
        {
            ["static Pkcs11Key DeriveKey(HashAlgorithmName, Pkcs11Key, ObjectTemplate, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>)"] = OnTokenResult,
            ["static Pkcs11Key ExtractKey(HashAlgorithmName, Pkcs11Key, ReadOnlySpan<Byte>)"] = OnTokenResult,
            ["static Pkcs11Key ExpandKey(HashAlgorithmName, Pkcs11Key, ObjectTemplate, ReadOnlySpan<Byte>)"] = OnTokenResult,
        },
        [nameof(SP800108HmacCounterKdfPkcs11)] = new(StringComparer.Ordinal)
        {
            ["Pkcs11Key DeriveKey(ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, ObjectTemplate)"] = OnTokenResult,
        },
        [nameof(Rfc2898DeriveBytesPkcs11)] = new(StringComparer.Ordinal)
        {
            ["ctor(Pkcs11Session, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Int32, HashAlgorithmName)"] = "A span overload of the byte[] constructor.",
            ["static Pkcs11Key Pbkdf2Key(Pkcs11Session, ReadOnlySpan<Byte>, ReadOnlySpan<Byte>, Int32, HashAlgorithmName, ObjectTemplate)"] = OnTokenResult,
            ["static Pkcs11Key Pbkdf2Key(Pkcs11Session, SecurePassword, ReadOnlySpan<Byte>, Int32, HashAlgorithmName, ObjectTemplate)"] = OnTokenResult,
        },
        [nameof(Pkcs11CertificateExtensions)] = new(StringComparer.Ordinal),
    };

    // === Tests ======================================================================================

    public static TheoryData<string> MirrorNames() => [.. Mirrors.Select(m => m.Adapter.Name)];

    private static Mirror MirrorOf(string adapter) => Mirrors.Single(m => m.Adapter.Name == adapter);

    [Theory]
    [MemberData(nameof(MirrorNames))]
    public void EveryBclMember_IsMirrored_OrADeviation_OrAKnownGap(string adapter)
    {
        Dictionary<string, Parity> followed = Followed[adapter];
        string[] unreviewed = [.. BclMembers(MirrorOf(adapter)).Where(m => !followed.ContainsKey(m))];

        Assert.True(unreviewed.Length == 0,
            $"{adapter} does not say how it follows these BCL members. Mirror each, or add it as a deviation or a gap:\n"
            + string.Join("\n", unreviewed));
    }

    [Theory]
    [MemberData(nameof(MirrorNames))]
    public void EveryMirroredMember_HasItsCounterpart_AndAReasonWhereTheSignatureDiffers(string adapter)
    {
        HashSet<string> members = [.. AdapterMembers(MirrorOf(adapter).Adapter)];
        var mirrored = Followed[adapter].Where(e => e.Value is Mirrored).Select(e => (Bcl: e.Key, Entry: (Mirrored)e.Value)).ToArray();

        string[] missing = [.. mirrored.Where(m => !members.Contains(m.Entry.Counterpart)).Select(m => m.Entry.Counterpart)];
        string[] unexplained = [.. mirrored.Where(m => m.Entry.Counterpart != m.Bcl && m.Entry.Why is null).Select(m => m.Bcl)];

        Assert.Empty(missing);
        Assert.Empty(unexplained);
    }

    [Theory]
    [MemberData(nameof(MirrorNames))]
    public void EveryAdapterMember_IsACounterpart_OrAnAddition(string adapter)
    {
        HashSet<string> counterparts = [.. Followed[adapter].Values.OfType<Mirrored>().Select(m => m.Counterpart)];
        Dictionary<string, string> additions = Additions[adapter];
        string[] members = [.. AdapterMembers(MirrorOf(adapter).Adapter)];

        string[] unaccounted = [.. members.Where(m => !counterparts.Contains(m) && !additions.ContainsKey(m))];
        string[] staleAdditions = [.. additions.Keys.Where(a => !members.Contains(a))];

        Assert.True(unaccounted.Length == 0,
            $"{adapter} has members that follow no BCL member and are not listed as additions:\n" + string.Join("\n", unaccounted));
        Assert.Empty(staleAdditions);
    }

    [Theory]
    [MemberData(nameof(MirrorNames))]
    public void EveryEntry_IsStillABclMember(string adapter)
    {
        HashSet<string> members = [.. BclMembers(MirrorOf(adapter))];
        string[] stale = [.. Followed[adapter].Keys.Where(k => !members.Contains(k))];

        Assert.Empty(stale);
    }

    // Between them, this test and BclOverrideCoverageTests check every public type of the namespace: a new adapter
    // would otherwise go unchecked.
    [Fact]
    public void EveryPublicAlgorithmsType_IsCovered()
    {
        HashSet<Type> covered = [.. BclOverrideCoverageTests.AdapterTypes, .. Mirrors.Select(m => m.Adapter), .. NotBclShaped.Keys];

        Type[] uncovered = [.. typeof(AesPkcs11).Assembly.GetExportedTypes()
            .Where(t => t.Namespace == typeof(AesPkcs11).Namespace && !covered.Contains(t))];

        Assert.Empty(uncovered);
    }

    // === Signatures =================================================================================

    private const BindingFlags DeclaredPublic = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    // The public constructors, methods and properties of the mirrored BCL types. A member of several types is
    // qualified with its type's name, so the extension classes' members keep apart from X509Certificate2's.
    private static IEnumerable<string> BclMembers(Mirror mirror) =>
        mirror.Bcl.SelectMany(t => Members(t, qualify: mirror.BclMember is not null))
            .Where(m => mirror.BclMember is null || mirror.BclMember(m.Method))
            .Select(m => m.Signature)
            .Distinct(StringComparer.Ordinal);

    private static IEnumerable<string> AdapterMembers(Type adapter) => Members(adapter, qualify: false).Select(m => m.Signature);

    private static IEnumerable<(MethodBase Method, string Signature)> Members(Type type, bool qualify)
    {
        string prefix = qualify ? type.Name + "." : "";
        foreach (ConstructorInfo c in type.GetConstructors(BindingFlags.Public | BindingFlags.Instance))
            yield return (c, $"{prefix}ctor({Parameters(c)})");
        foreach (MethodInfo m in type.GetMethods(DeclaredPublic).Where(m => !m.IsSpecialName))
            yield return (m, $"{prefix}{(m.IsStatic ? "static " : "")}{TypeName(m.ReturnType)} {m.Name}({Parameters(m)})");
        foreach (PropertyInfo p in type.GetProperties(DeclaredPublic))
        {
            MethodInfo accessor = (p.GetMethod ?? p.SetMethod)!;
            string accessors = (p.GetMethod?.IsPublic == true ? " get;" : "") + (p.SetMethod?.IsPublic == true ? " set;" : "");
            yield return (accessor, $"{prefix}{(accessor.IsStatic ? "static " : "")}{TypeName(p.PropertyType)} {p.Name} {{{accessors} }}");
        }
    }

    private static string Parameters(MethodBase m) => string.Join(", ", m.GetParameters().Select(p =>
        (p.IsOut ? "out " : p.ParameterType.IsByRef ? "ref " : "") + TypeName(p.ParameterType)));

    private static string TypeName(Type t)
    {
        if (t.IsByRef) return TypeName(t.GetElementType()!);
        if (t.IsArray) return TypeName(t.GetElementType()!) + "[]";
        if (Nullable.GetUnderlyingType(t) is { } underlying) return TypeName(underlying) + "?";
        if (!t.IsGenericType) return t.Name;
        var sb = new StringBuilder(t.Name[..t.Name.IndexOf('`')]).Append('<');
        sb.AppendJoin(", ", t.GetGenericArguments().Select(TypeName));
        return sb.Append('>').ToString();
    }
}
