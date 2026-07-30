using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for key-management on <see cref="Pkcs11Session"/>: the two-handle
/// <c>GenerateKeyPair</c> out-parameters, the <c>WrapKey</c> length-probe + resize, and
/// <c>UnwrapKey</c>/<c>DeriveKey</c> handle return and CKR-&gt;exception mapping. Driven through
/// <see cref="ILowLevelPkcs11Library"/> so the buffer-probe and out-parameter wiring are pinned
/// without depending on a backend generating real keys.
/// </summary>
public sealed class Pkcs11SessionKeyManagementTests
{
    private const ulong SessionId = 11;

    private sealed class KeyFake : FakeLowLevelPkcs11Library
    {
        public CKR GenPairRv = CKR.CKR_OK, WrapRv = CKR.CKR_OK, UnwrapRv = CKR.CKR_OK, DeriveRv = CKR.CKR_OK;
        public ulong PublicId = 10, PrivateId = 20, UnwrappedId = 30, DerivedId = 40;
        public byte[] Wrapped = [0xAA, 0xBB, 0xCC];
        public int? WrapSecondLen; // when set, the real call reports fewer bytes than the probe -> resize down

        public override CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? publicKeyTemplate, NativeCULong publicKeyAttributeCount, CK_ATTRIBUTE[]? privateKeyTemplate, NativeCULong privateKeyAttributeCount, ref NativeCULong publicKey, ref NativeCULong privateKey)
        { publicKey = (NativeCULong)PublicId; privateKey = (NativeCULong)PrivateId; return GenPairRv; }

        public override CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[]? wrappedKey, ref NativeCULong wrappedKeyLen)
        {
            if (wrappedKey is null) { wrappedKeyLen = (NativeCULong)Wrapped.Length; return WrapRv; }
            int n = WrapSecondLen ?? Wrapped.Length;
            Array.Copy(Wrapped, wrappedKey, Math.Min(n, wrappedKey.Length));
            wrappedKeyLen = (NativeCULong)n;
            return WrapRv;
        }

        public override CKR C_UnwrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[]? template, NativeCULong attributeCount, ref NativeCULong key)
        { key = (NativeCULong)UnwrappedId; return UnwrapRv; }

        public override CKR C_DeriveKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[]? template, NativeCULong attributeCount, ref NativeCULong key)
        { key = (NativeCULong)DerivedId; return DeriveRv; }
    }

    private static Pkcs11Session NewSession(KeyFake fake) => new(fake, SessionId);

    // === GenerateKeyPair ====================================================

    [Fact]
    public void GenerateKeyPair_Ok_ReturnsBothHandles()
    {
        var s = NewSession(new KeyFake { PublicId = 0x11, PrivateId = 0x22 });
        var mech = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        s.GenerateKeyPair(mech, [], [], out ObjectHandle pub, out ObjectHandle priv);

        Assert.Equal(0x11UL, pub.ObjectId);
        Assert.Equal(0x22UL, priv.ObjectId);
    }

    [Fact]
    public void GenerateKeyPair_Error_Throws()
    {
        var s = NewSession(new KeyFake { GenPairRv = CKR.CKR_TEMPLATE_INCONSISTENT });
        var mech = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.GenerateKeyPair(mech, [], [], out _, out _));
    }

    // === WrapKey ============================================================

    [Fact]
    public void WrapKey_Ok_ReturnsProbedBytes()
    {
        var s = NewSession(new KeyFake { Wrapped = [1, 2, 3, 4] });
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, s.WrapKey(mech, new ObjectHandle(1), new ObjectHandle(2)));
    }

    [Fact]
    public void WrapKey_SecondCallShorter_ResizesDown()
    {
        // Probe says 4 bytes; the real call only fills 2 -> the result must be trimmed to 2.
        var s = NewSession(new KeyFake { Wrapped = [9, 8, 7, 6], WrapSecondLen = 2 });
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.Equal(new byte[] { 9, 8 }, s.WrapKey(mech, new ObjectHandle(1), new ObjectHandle(2)));
    }

    [Fact]
    public void WrapKey_Error_Throws()
    {
        var s = NewSession(new KeyFake { WrapRv = CKR.CKR_KEY_UNEXTRACTABLE });
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.WrapKey(mech, new ObjectHandle(1), new ObjectHandle(2)));
    }

    // === UnwrapKey ==========================================================

    [Fact]
    public void UnwrapKey_Ok_ReturnsHandle()
    {
        var s = NewSession(new KeyFake { UnwrappedId = 0x77 });
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.Equal(0x77UL, s.UnwrapKey(mech, new ObjectHandle(1), [1, 2, 3], []).ObjectId);
    }

    [Fact]
    public void UnwrapKey_Error_Throws()
    {
        var s = NewSession(new KeyFake { UnwrapRv = CKR.CKR_WRAPPED_KEY_INVALID });
        var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.UnwrapKey(mech, new ObjectHandle(1), [1, 2, 3], []));
    }

    // === DeriveKey ==========================================================

    [Fact]
    public void DeriveKey_Ok_ReturnsHandle()
    {
        var s = NewSession(new KeyFake { DerivedId = 0x55 });
        var mech = new Mechanism(CKM.CKM_ECDH1_DERIVE);
        Assert.Equal(0x55UL, s.DeriveKey(mech, new ObjectHandle(1), []).ObjectId);
    }

    [Fact]
    public void DeriveKey_Error_Throws()
    {
        var s = NewSession(new KeyFake { DeriveRv = CKR.CKR_MECHANISM_INVALID });
        var mech = new Mechanism(CKM.CKM_ECDH1_DERIVE);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.DeriveKey(mech, new ObjectHandle(1), []));
    }
}
