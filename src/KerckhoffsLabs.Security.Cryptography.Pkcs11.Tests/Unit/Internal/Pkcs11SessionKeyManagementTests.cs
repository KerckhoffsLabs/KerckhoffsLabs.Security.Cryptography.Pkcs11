using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for key-management on <see cref="Pkcs11Session"/>: the two-handle
/// <c>GenerateKeyPair</c> out-parameters, the <c>WrapKey</c> length-probe + resize, and
/// <c>UnwrapKey</c>/<c>DeriveKey</c> handle return and CKR-&gt;exception mapping. Driven through a
/// <see cref="FakeModule"/> behind the real loader, so the buffer-probe and out-parameter wiring are
/// pinned without depending on a backend generating real keys.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionKeyManagementTests
{
    private const ulong SessionId = 11;

    private sealed class KeyFake : SessionTestModule
    {
        public CKR GenPairRv = CKR.CKR_OK, WrapRv = CKR.CKR_OK, UnwrapRv = CKR.CKR_OK, DeriveRv = CKR.CKR_OK;
        public ulong PublicId = 10, PrivateId = 20, UnwrappedId = 30, DerivedId = 40;
        public byte[] Wrapped = [0xAA, 0xBB, 0xCC];
        public int? WrapSecondLen; // when set, the real call reports fewer bytes than the probe -> resize down

        protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
        { publicKey = (NativeCULong)PublicId; privateKey = (NativeCULong)PrivateId; return GenPairRv; }

        protected override CKR C_WrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen)
        {
            if (wrappedKey.IsNull) { wrappedKeyLen = (NativeCULong)Wrapped.Length; return WrapRv; }
            int n = WrapSecondLen ?? Wrapped.Length;
            Wrapped.AsSpan(0, Math.Min(n, wrappedKey.Span.Length)).CopyTo(wrappedKey.Span);
            wrappedKeyLen = (NativeCULong)n;
            return WrapRv;
        }

        protected override CKR C_UnwrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
        { key = (NativeCULong)UnwrappedId; return UnwrapRv; }

        protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
        { key = (NativeCULong)DerivedId; return DeriveRv; }

        // The session reads the base key's type before an ECDH derivation.
        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
            => KeyTypeAttribute.Answer(template, CKK.CKK_EC);
    }

    // === GenerateKeyPair ====================================================

    [Fact]
    public void GenerateKeyPair_Ok_ReturnsBothHandles()
    {
        using var fake = new KeyFake { PublicId = 0x11, PrivateId = 0x22 };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        s.GenerateKeyPair(mech, [], [], out ObjectHandle pub, out ObjectHandle priv);

        Assert.Equal(0x11UL, pub.ObjectId);
        Assert.Equal(0x22UL, priv.ObjectId);
    }

    [Fact]
    public void GenerateKeyPair_Error_Throws()
    {
        using var fake = new KeyFake { GenPairRv = CKR.CKR_TEMPLATE_INCONSISTENT };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.GenerateKeyPair(mech, [], [], out _, out _));
    }

    // === WrapKey ============================================================

    [Fact]
    public void WrapKey_Ok_ReturnsProbedBytes()
    {
        using var fake = new KeyFake { Wrapped = [1, 2, 3, 4] };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, s.WrapKey(mech, new ObjectHandle(1), new ObjectHandle(2)));
    }

    [Fact]
    public void WrapKey_SecondCallShorter_ResizesDown()
    {
        // Probe says 4 bytes; the real call only fills 2 -> the result must be trimmed to 2.
        using var fake = new KeyFake { Wrapped = [9, 8, 7, 6], WrapSecondLen = 2 };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.Equal(new byte[] { 9, 8 }, s.WrapKey(mech, new ObjectHandle(1), new ObjectHandle(2)));
    }

    [Fact]
    public void WrapKey_Error_Throws()
    {
        using var fake = new KeyFake { WrapRv = CKR.CKR_KEY_UNEXTRACTABLE };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.WrapKey(mech, new ObjectHandle(1), new ObjectHandle(2)));
    }

    // === UnwrapKey ==========================================================

    [Fact]
    public void UnwrapKey_Ok_ReturnsHandle()
    {
        using var fake = new KeyFake { UnwrappedId = 0x77 };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.Equal(0x77UL, s.UnwrapKey(mech, new ObjectHandle(1), [1, 2, 3], []).ObjectId);
    }

    [Fact]
    public void UnwrapKey_Error_Throws()
    {
        using var fake = new KeyFake { UnwrapRv = CKR.CKR_WRAPPED_KEY_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.UnwrapKey(mech, new ObjectHandle(1), [1, 2, 3], []));
    }

    // === DeriveKey ==========================================================

    [Fact]
    public void DeriveKey_Ok_ReturnsHandle()
    {
        using var fake = new KeyFake { DerivedId = 0x55 };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, [0x04, 0x01, 0x04]));
        Assert.Equal(0x55UL, s.DeriveKey(mech, new ObjectHandle(1), []).ObjectId);
    }

    [Fact]
    public void DeriveKey_Error_Throws()
    {
        using var fake = new KeyFake { DeriveRv = CKR.CKR_MECHANISM_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, [0x04, 0x01, 0x04]));
        Assert.ThrowsAny<Pkcs11Exception>(() => s.DeriveKey(mech, new ObjectHandle(1), []));
    }
}
