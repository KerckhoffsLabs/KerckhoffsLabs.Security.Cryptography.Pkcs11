using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// <c>CKM_ECDH1_DERIVE</c> serves both Weierstrass (<c>CKK_EC</c>) and Montgomery (<c>CKK_EC_MONTGOMERY</c>,
/// X25519/X448) keys, so the mechanism alone cannot tell FipsOnly that an existing X25519 key is in use.
/// The session reads the key's <c>CKA_KEY_TYPE</c> and submits it as a <see cref="KeyAgreementKeyRequest"/>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class EcdhKeyTypeGateTests
{
    private static readonly byte[] PeerPoint = [0x04, 0x41, 0x04, .. new byte[64]];

    /// <summary>Answers CKA_KEY_TYPE with <paramref name="keyType"/> (or fails it), and counts calls that reach the token.</summary>
    private sealed class KeyTypeFake(CKK? keyType) : SessionTestModule
    {
        public new int Calls { get; private set; }

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
            => keyType is { } type ? KeyTypeAttribute.Answer(template, type) : CKR.CKR_OBJECT_HANDLE_INVALID;

        protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
        {
            Calls++;
            key = (NativeCULong)20UL;
            return CKR.CKR_OK;
        }

        // Counted, then failed: only whether the call reached the token matters here.
        protected override CKR C_EncapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong key)
        {
            Calls++;
            ciphertextLen = (NativeCULong)0UL;
            return CKR.CKR_FUNCTION_FAILED;
        }

        protected override CKR C_DecapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, ReadOnlySpan<byte> ciphertext, ref NativeCULong key)
        {
            Calls++;
            return CKR.CKR_FUNCTION_FAILED;
        }
    }

    private static void Derive(Pkcs11Session session, CKM type = CKM.CKM_ECDH1_DERIVE)
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var mechanism = new Mechanism(type, new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, PeerPoint));
        session.DeriveKey(mechanism, new ObjectHandle(5UL), [.. template.Attributes]);
    }

    [Theory]
    [InlineData(CKM.CKM_ECDH1_DERIVE)]
    [InlineData(CKM.CKM_ECDH1_COFACTOR_DERIVE)]
    public void FipsOnly_RefusesAMontgomeryKey_BeforeReachingTheToken(CKM type)
    {
        using var fake = new KeyTypeFake(CKK.CKK_EC_MONTGOMERY);
        using var session = fake.CreateSession(sessionId: 1, policy: CryptoPolicy.FipsOnly);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => Derive(session, type));
        var request = Assert.IsType<KeyAgreementKeyRequest>(ex.Request);
        Assert.Equal(type, request.Mechanism);
        Assert.Equal(CKK.CKK_EC_MONTGOMERY, request.KeyType);
        Assert.Contains("SP 800-56A", ex.Reason, StringComparison.Ordinal);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public void FipsOnly_AllowsAWeierstrassKey()
    {
        using var fake = new KeyTypeFake(CKK.CKK_EC);
        using var session = fake.CreateSession(sessionId: 1, policy: CryptoPolicy.FipsOnly);

        Derive(session);
        Assert.Equal(1, fake.Calls);
    }

    [Theory]
    [InlineData(CKK.CKK_EC)]
    [InlineData(CKK.CKK_EC_MONTGOMERY)]
    public void SecureOnly_AllowsBothEcKeyTypes(CKK keyType)
    {
        using var fake = new KeyTypeFake(keyType);
        using var session = fake.CreateSession(sessionId: 1);

        Derive(session);
        Assert.Equal(1, fake.Calls);
    }

    // A key type no allow-list names (here a vendor value) is refused, as everything unlisted is.
    [Fact]
    public void AnUnlistedKeyType_IsRefused()
    {
        using var fake = new KeyTypeFake(CKK.CKK_VENDOR_DEFINED);
        using var session = fake.CreateSession(sessionId: 1);

        Assert.Throws<CryptoPolicyViolationException>(() => Derive(session));
        Assert.Equal(0, fake.Calls);
    }

    // CKA_KEY_TYPE is never sensitive, so an unreadable one means an unusable handle: the token's own
    // call reports that, as it would have without the check.
    [Fact]
    public void AnUnreadableKeyType_IsLeftToTheToken()
    {
        using var fake = new KeyTypeFake(keyType: null);
        using var session = fake.CreateSession(sessionId: 1, policy: CryptoPolicy.FipsOnly);

        Derive(session);
        Assert.Equal(1, fake.Calls);
    }

    /// <summary>Refuses only key agreement with a Montgomery key. FipsOnly cannot stand in here: it refuses the ECDH KEM outright, on the mechanism.</summary>
    private sealed class RefuseMontgomeryKeys : ICryptoPolicy
    {
        public string Name => "RefuseMontgomeryKeys";
        public bool AllowsOverride => true;

        public PolicyDecision Evaluate(PolicyRequest request) => request is KeyAgreementKeyRequest { KeyType: CKK.CKK_EC_MONTGOMERY }
            ? PolicyDecision.Deny("Montgomery keys are refused.")
            : PolicyDecision.Allow;
    }

    [Fact]
    public void AMontgomeryKey_IsJudgedOnEncapsulateAndDecapsulate()
    {
        using var fake = new KeyTypeFake(CKK.CKK_EC_MONTGOMERY);
        using var session = fake.CreateSession(sessionId: 1, policy: new RefuseMontgomeryKeys());
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForEncapsulation(CKD.CKD_SHA256_KDF));

        Assert.IsType<KeyAgreementKeyRequest>(Assert.Throws<CryptoPolicyViolationException>(
            () => session.EncapsulateKey(mechanism, new ObjectHandle(5UL), [.. template.Attributes])).Request);
        Assert.IsType<KeyAgreementKeyRequest>(Assert.Throws<CryptoPolicyViolationException>(
            () => session.DecapsulateKey(mechanism, new ObjectHandle(5UL), PeerPoint, [.. template.Attributes])).Request);
        Assert.Equal(0, fake.Calls);
    }

    // Only ECDH mechanisms are asked about their key: other derivations never read CKA_KEY_TYPE.
    [Fact]
    public void NonEcdhDerivation_DoesNotConsultTheKeyType()
    {
        using var fake = new KeyTypeFake(CKK.CKK_EC_MONTGOMERY);
        using var session = fake.CreateSession(sessionId: 1, policy: CryptoPolicy.FipsOnly);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var hkdf = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC));

        session.DeriveKey(hkdf, new ObjectHandle(5UL), [.. template.Attributes]);
        Assert.Equal(1, fake.Calls);
    }
}
