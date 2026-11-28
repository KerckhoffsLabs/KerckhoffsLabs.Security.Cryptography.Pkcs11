using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Policies;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Costs;

/// <summary>
/// The native calls a keyed operation through <see cref="Pkcs11Key"/> costs, under the library's default policy
/// (<see cref="CryptoPolicy.Recommended"/>) and under the same policy with key inspection off. The difference is the
/// key-strength read the default policy makes before every use of a key (#388): one <c>C_GetAttributeValue</c> for an
/// AES or HMAC key (its type and length), two for an RSA or EC key (then its modulus or curve), never cached, as a
/// handle can come to name another key. On a network HSM each call is a round trip, so these pins are the cost the
/// default configuration pays per operation.
/// </summary>
/// <remarks>
/// The core guards (<c>OperationCostGuardTests</c>) keep a non-inspecting policy, so they measure the operation alone;
/// these measure what a caller of the public API gets. Each pin is the second call on the key, after the one-time reads
/// a first use makes (<see cref="FirstUse_ReadsTheKeyOnce_ThenNotAgain"/>). A change to a path's cost fails its pin:
/// update the pin and say why in the change.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class KeyOperationCallCountTests
{
    private static readonly byte[] Data = new byte[32];

    private static Mechanism Gcm() => new(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], 128));

    private static Mechanism Pss() => new(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));

    private static Mechanism Oaep() => new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));

    // Path; calls under Recommended; calls with key inspection off.
    private static readonly (string Path, string UnderRecommended, string WithoutInspection)[] Paths =
    [
        // Classic single-part AEAD: the output length is known, so there is no length query.
        ("AES-GCM encrypt", "C_Encrypt×1, C_EncryptInit×1, C_GetAttributeValue×1", "C_Encrypt×1, C_EncryptInit×1"),
        ("AES-GCM decrypt", "C_Decrypt×1, C_DecryptInit×1, C_GetAttributeValue×1", "C_Decrypt×1, C_DecryptInit×1"),
        ("HMAC-SHA256 sign", "C_GetAttributeValue×1, C_Sign×1, C_SignInit×1", "C_Sign×1, C_SignInit×1"),
        ("HMAC-SHA256 verify", "C_GetAttributeValue×1, C_Verify×1, C_VerifyInit×1", "C_Verify×1, C_VerifyInit×1"),
        // C_Sign×2: a length query, then the signature (CP-023 would learn the length once per key).
        ("ECDSA P-256 sign", "C_GetAttributeValue×2, C_Sign×2, C_SignInit×1", "C_Sign×2, C_SignInit×1"),
        ("ECDSA P-256 verify", "C_GetAttributeValue×2, C_Verify×1, C_VerifyInit×1", "C_Verify×1, C_VerifyInit×1"),
        ("RSA-2048 PSS sign", "C_GetAttributeValue×2, C_Sign×2, C_SignInit×1", "C_Sign×2, C_SignInit×1"),
        ("RSA-2048 PSS verify", "C_GetAttributeValue×2, C_Verify×1, C_VerifyInit×1", "C_Verify×1, C_VerifyInit×1"),
        // C_Encrypt×2: a length query, then the ciphertext.
        ("RSA-2048 OAEP encrypt", "C_Encrypt×2, C_EncryptInit×1, C_GetAttributeValue×2", "C_Encrypt×2, C_EncryptInit×1"),
        ("RSA-2048 OAEP decrypt", "C_Decrypt×1, C_DecryptInit×1, C_GetAttributeValue×2", "C_Decrypt×1, C_DecryptInit×1"),
    ];

    public static TheoryData<string, bool, string> SteadyStatePaths
    {
        get
        {
            var data = new TheoryData<string, bool, string>();
            foreach ((string path, string underRecommended, string withoutInspection) in Paths)
            {
                data.Add(path, true, underRecommended);
                data.Add(path, false, withoutInspection);
            }
            return data;
        }
    }

    // The guard is only worth something if the default it measures is the library's: a library loaded with no options
    // over a token that describes its keys runs Recommended, which inspects keys.
    [Fact]
    public void TheDefaultPolicy_IsRecommended_AndInspectsKeys()
    {
        using var library = new ManagedSoftToken().Load();

        Assert.Same(CryptoPolicy.Recommended, library.Policy);
        Assert.True(library.Policy.InspectsKeys);
    }

    [Theory]
    [MemberData(nameof(SteadyStatePaths))]
    public void SteadyState(string path, bool inspectKeys, string calls)
        => Assert.Equal(calls, Measure(path, inspectKeys, warm: true));

    // Every steady-state path pays exactly the key-strength read under Recommended, and nothing else: one call for a
    // secret key, two for an RSA or EC key.
    [Fact]
    public void TheDefaultPolicy_AddsOnlyTheKeyStrengthRead()
    {
        foreach ((string path, string underRecommended, string withoutInspection) in Paths)
        {
            int reads = path.StartsWith("AES", StringComparison.Ordinal) || path.StartsWith("HMAC", StringComparison.Ordinal) ? 1 : 2;
            Assert.Equal(NativeCalls.Total(withoutInspection) + reads, NativeCalls.Total(underRecommended));
        }
    }

    // What a key's first operation adds, once, and the second does not repeat:
    // - every private key: CKA_ALWAYS_AUTHENTICATE, through the generic two-call reader (length, then value), so a key
    //   that needs a context login gets one; the answer is kept on the Pkcs11Key;
    // - an RSA decryption key: its modulus, through the same reader, to refuse a ciphertext the key cannot have made.
    [Theory]
    [InlineData("ECDSA P-256 sign", true, "C_GetAttributeValue×4, C_Sign×2, C_SignInit×1")]
    [InlineData("ECDSA P-256 sign", false, "C_GetAttributeValue×2, C_Sign×2, C_SignInit×1")]
    [InlineData("RSA-2048 PSS sign", true, "C_GetAttributeValue×4, C_Sign×2, C_SignInit×1")]
    [InlineData("RSA-2048 OAEP decrypt", true, "C_Decrypt×1, C_DecryptInit×1, C_GetAttributeValue×6")]
    [InlineData("RSA-2048 OAEP decrypt", false, "C_Decrypt×1, C_DecryptInit×1, C_GetAttributeValue×4")]
    // A secret key and a public key read nothing more on first use.
    [InlineData("AES-GCM encrypt", true, "C_Encrypt×1, C_EncryptInit×1, C_GetAttributeValue×1")]
    [InlineData("ECDSA P-256 verify", true, "C_GetAttributeValue×2, C_Verify×1, C_VerifyInit×1")]
    public void FirstUse_ReadsTheKeyOnce_ThenNotAgain(string path, bool inspectKeys, string firstUse)
        => Assert.Equal(firstUse, Measure(path, inspectKeys, warm: false));

    // Each path on a key of its own, over a token of its own: nothing a previous path read is remembered.
    private static string Measure(string path, bool inspectKeys, bool warm)
    {
        var token = new ManagedSoftToken { ReportsDefaultAttributes = true };
        using Pkcs11Library library = token.Load(inspectKeys ? null : new Pkcs11LibraryOptions { Policy = TestPolicies.RecommendedWithoutKeyInspection });
        using Pkcs11Session session = ManagedToken.OpenSession(library);
        using Pkcs11Key key = KeyFor(path, session);
        Action operation = OperationFor(path, key);
        if (warm)
            operation();
        return NativeCalls.Of(token, operation);
    }

    private static Pkcs11Key KeyFor(string path, Pkcs11Session session)
    {
        if (path.StartsWith("AES", StringComparison.Ordinal))
            return session.GenerateAesKey(256);
        if (path.StartsWith("HMAC", StringComparison.Ordinal))
        {
            using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Sign().Verify().Build();
            return session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), template);
        }
        if (path.StartsWith("ECDSA", StringComparison.Ordinal))
            return session.GenerateEcSigningKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        if (path.Contains("OAEP", StringComparison.Ordinal))
            return session.GenerateRsaKeyTransportKeyPair(2048);
        return session.GenerateRsaSigningKeyPair(2048);
    }

    private static Action OperationFor(string path, Pkcs11Key key)
    {
        byte[] gcmCiphertext = path == "AES-GCM decrypt" ? key.Encrypt(Gcm(), Data) : [];
        byte[] oaepCiphertext = path == "RSA-2048 OAEP decrypt" ? key.Encrypt(Oaep(), Data) : [];
        byte[] tag = path == "HMAC-SHA256 verify" ? key.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), Data) : [];
        byte[] ecdsa = path == "ECDSA P-256 verify" ? key.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), Data) : [];
        byte[] pss = path == "RSA-2048 PSS verify" ? key.Sign(Pss(), Data) : [];
        return path switch
        {
            "AES-GCM encrypt" => () => key.Encrypt(Gcm(), Data),
            "AES-GCM decrypt" => () => key.Decrypt(Gcm(), gcmCiphertext),
            "HMAC-SHA256 sign" => () => key.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), Data),
            "HMAC-SHA256 verify" => () => Assert.True(key.Verify(new Mechanism(CKM.CKM_SHA256_HMAC), Data, tag)),
            "ECDSA P-256 sign" => () => key.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), Data),
            "ECDSA P-256 verify" => () => Assert.True(key.Verify(new Mechanism(CKM.CKM_ECDSA_SHA256), Data, ecdsa)),
            "RSA-2048 PSS sign" => () => key.Sign(Pss(), Data),
            "RSA-2048 PSS verify" => () => Assert.True(key.Verify(Pss(), Data, pss)),
            "RSA-2048 OAEP encrypt" => () => key.Encrypt(Oaep(), Data),
            "RSA-2048 OAEP decrypt" => () => key.Decrypt(Oaep(), oaepCiphertext),
            _ => throw new ArgumentOutOfRangeException(nameof(path), path, null),
        };
    }
}
