using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The key-agreement KDF inside <c>CK_ECDH1_DERIVE_PARAMS</c> is judged on every ECDH derivation and KEM,
/// not only through <c>Pkcs11Workspace.DeriveSharedSecretEcdh</c>: <c>Pkcs11Key.Derive</c> and
/// <c>EncapsulateKey</c> / <c>DecapsulateKey</c> reach the same session calls and meet the same allow-list.
/// </summary>
public sealed class EcdhKdfGateTests
{
    private static readonly byte[] PeerPoint = [0x04, 0x41, 0x04, .. new byte[64]];

    private sealed class RecordingFake : FakeLowLevelPkcs11Library
    {
        public int Calls { get; private set; }

        public override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
            => KeyTypeAttribute.Answer(template, CKK.CKK_EC);

        public override CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong key)
        {
            Calls++;
            key = (NativeCULong)20UL;
            return CKR.CKR_OK;
        }

        // Counted, then failed: only whether the call reached the token matters here.
        public override CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, ReadOnlySpan<CK_ATTRIBUTE> template, Span<byte> ciphertext, out NativeCULong ciphertextLen, ref NativeCULong derivedKey)
        {
            Calls++;
            ciphertextLen = (NativeCULong)0UL;
            return CKR.CKR_FUNCTION_FAILED;
        }

        public override CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, ReadOnlySpan<CK_ATTRIBUTE> template, ReadOnlySpan<byte> ciphertext, ref NativeCULong derivedKey)
        {
            Calls++;
            return CKR.CKR_FUNCTION_FAILED;
        }
    }

    private static void Derive(Pkcs11Session session, Mechanism mechanism)
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        session.DeriveKey(mechanism, new ObjectHandle(5UL), [.. template.Attributes]);
    }

    private static Mechanism Ecdh(CKD kdf, CKM type = CKM.CKM_ECDH1_DERIVE) => new(type, new CkmEcdh1DeriveParams(kdf, PeerPoint));

    [Theory]
    [InlineData(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL)]
    [InlineData(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA1_KDF)]
    [InlineData(CKM.CKM_ECDH1_COFACTOR_DERIVE, CKD.CKD_NULL)]
    [InlineData(CKM.CKM_ECDH1_COFACTOR_DERIVE, CKD.CKD_SHA224_KDF)]
    public void RefusedKdf_IsRefusedBeforeReachingTheToken(CKM type, CKD kdf)
    {
        var fake = new RecordingFake();
        using var session = new Pkcs11Session(fake, sessionId: 1);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => Derive(session, Ecdh(kdf, type)));
        var request = Assert.IsType<KeyAgreementKdfRequest>(ex.Request);
        Assert.Equal(type, request.Mechanism);
        Assert.Equal(kdf, request.Kdf);
        Assert.Equal(0, fake.Calls);
    }

    [Theory]
    [InlineData(CKD.CKD_SHA256_KDF)]
    [InlineData(CKD.CKD_SHA384_KDF_SP800)]
    [InlineData(CKD.CKD_SHA3_512_KDF)]
    public void AllowedKdf_Proceeds(CKD kdf)
    {
        var fake = new RecordingFake();
        using var session = new Pkcs11Session(fake, sessionId: 1);

        Derive(session, Ecdh(kdf));
        Assert.Equal(1, fake.Calls);
    }

    // CKD_SHA224_KDF is refused by SecureOnly but approved by FipsOnly (SP 800-56C): the verdict is the
    // policy's, not a fixed list in the session.
    [Fact]
    public void TheKdfVerdictFollowsThePolicy()
    {
        var secure = new RecordingFake();
        using (var session = new Pkcs11Session(secure, sessionId: 1))
            Assert.Throws<CryptoPolicyViolationException>(() => Derive(session, Ecdh(CKD.CKD_SHA224_KDF)));
        Assert.Equal(0, secure.Calls);

        var fips = new RecordingFake();
        using (var session = new Pkcs11Session(fips, sessionId: 1, policy: CryptoPolicy.FipsOnly))
            Derive(session, Ecdh(CKD.CKD_SHA224_KDF));
        Assert.Equal(1, fips.Calls);

        var insecure = new RecordingFake();
        using (var session = new Pkcs11Session(insecure, sessionId: 1, policy: CryptoPolicy.AllowInsecure))
            Derive(session, Ecdh(CKD.CKD_NULL));
        Assert.Equal(1, insecure.Calls);
    }

    // Raw bytes would hide the KDF from the policy, so the restrictive policies require the typed params.
    [Theory]
    [InlineData("SecureOnly")]
    [InlineData("FipsOnly")]
    public void UntypedParameters_AreRefused(string policyName)
    {
        ICryptoPolicy policy = policyName == "FipsOnly" ? CryptoPolicy.FipsOnly : CryptoPolicy.SecureOnly;
        var fake = new RecordingFake();
        using var session = new Pkcs11Session(fake, sessionId: 1, policy: policy);

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => Derive(session, new Mechanism(CKM.CKM_ECDH1_DERIVE, new byte[40])));
        Assert.IsType<MechanismUseRequest>(ex.Request);
        Assert.Contains("CkmEcdh1DeriveParams", ex.Reason, StringComparison.Ordinal);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public void Encapsulate_RefusesACkdNullKdf()
    {
        var fake = new RecordingFake();
        using var session = new Pkcs11Session(fake, sessionId: 1);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForEncapsulation(CKD.CKD_NULL));

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => session.EncapsulateKey(mechanism, new ObjectHandle(5UL), [.. template.Attributes]));
        Assert.IsType<KeyAgreementKdfRequest>(ex.Request);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public void Decapsulate_RefusesACkdNullKdf()
    {
        var fake = new RecordingFake();
        using var session = new Pkcs11Session(fake, sessionId: 1);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForEncapsulation(CKD.CKD_NULL));

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => session.DecapsulateKey(mechanism, new ObjectHandle(5UL), PeerPoint, [.. template.Attributes]));
        Assert.IsType<KeyAgreementKdfRequest>(ex.Request);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public void Encapsulate_WithAnAllowedKdf_ReachesTheToken()
    {
        var fake = new RecordingFake();
        using var session = new Pkcs11Session(fake, sessionId: 1);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForEncapsulation(CKD.CKD_SHA256_KDF));

        Assert.ThrowsAny<Pkcs11Exception>(
            () => session.EncapsulateKey(mechanism, new ObjectHandle(5UL), [.. template.Attributes]));
        Assert.Equal(1, fake.Calls);
    }

    // The public generic path: before this check it derived a key straight from the raw ECDH secret.
    [Fact]
    public void Workspace_KeyDerive_RefusesCkdNull()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using Pkcs11Key ours = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using Pkcs11Key theirs = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        byte[] peerPoint = theirs.GetAttributeValue(CKA.CKA_EC_POINT)[0].GetValueAsByteArray();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();

        Assert.Throws<CryptoPolicyViolationException>(
            () => ours.Derive(new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, peerPoint)), template));
    }
}
