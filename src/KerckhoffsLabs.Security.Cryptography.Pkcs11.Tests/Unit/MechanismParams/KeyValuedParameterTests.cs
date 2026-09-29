using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// The rules for mechanism parameters that reference on-token keys: which half of a key a field
/// takes, when a key is refused, and what an absent optional key marshals to. The field values
/// themselves are covered per type in <see cref="BuildMarshalableTests"/>.
/// </summary>
public sealed class KeyValuedParameterTests
{
    [Fact]
    public void KeyFromAnotherWorkspace_IsRefusedWhenMarshalled()
    {
        using var caller = new ParameterKeys();
        using var other = new ParameterKeys();
        var p = new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, other.Secret(9), [0x01]);
        using var scope = caller.NewScope();

        var e = Assert.Throws<ArgumentException>(() => p.BuildMarshalable(scope));
        Assert.Equal("seedKey", e.ParamName);
    }

    [Fact]
    public void KeyFromAnotherWorkspace_IsRefusedBeforeTheDeriveReachesTheModule()
    {
        using var caller = new ParameterKeys(CryptoPolicy.AllowInsecure);
        using var other = new ParameterKeys();
        using var baseKey = caller.Secret(1);
#pragma warning disable KLPKCS11009 // IKE PRF+ is legacy; the fixture's policy admits it so the call reaches marshalling.
        var mechanism = new Mechanism(CKM.CKM_IKE2_PRF_PLUS_DERIVE,
#pragma warning restore KLPKCS11009
            new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, other.Secret(9), [0x01]));
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Build();

        // The fake module answers C_DeriveKey with CKR_FUNCTION_NOT_SUPPORTED, so an ArgumentException
        // here proves the refusal happened while marshalling, before anything was sent.
        var e = Assert.Throws<ArgumentException>(() => baseKey.Derive(mechanism, template));
        Assert.Equal("seedKey", e.ParamName);
    }

    [Fact]
    public void DisposedKey_IsRefusedWhenMarshalled()
    {
        using var keys = new ParameterKeys();
        Pkcs11Key seed = keys.Secret(9);
        var p = new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, seed, [0x01]);
        seed.Dispose();
        using var scope = keys.NewScope();

        Assert.Throws<ObjectDisposedException>(() => p.BuildMarshalable(scope));
    }

    [Fact]
    public void PublicField_RefusesASecretKeyAtConstruction()
    {
        using var keys = new ParameterKeys();

        var e = Assert.Throws<ArgumentException>(() => new CkmX3dhRespondParams(
            CKM.CKM_SHA256_HMAC, [0x01], [0x02], [0x03], initiatorIdentity: keys.Secret(1), [0x04]));
        Assert.Equal("initiatorIdentity", e.ParamName);
    }

    [Fact]
    public void PrivateField_RefusesAPublicOnlyKeyAtConstruction()
    {
        using var keys = new ParameterKeys();

        var e = Assert.Throws<ArgumentException>(() => new CkmX3dhInitiateParams(
            CKM.CKM_SHA256_HMAC, keys.PublicOnly(1), keys.PublicOnly(2), [0x01], [0x02],
            ownIdentity: keys.PublicOnly(3), ownEphemeral: keys.Pair(4, 0x40)));
        Assert.Equal("ownIdentity", e.ParamName);
    }

    [Fact]
    public void RequiredKey_RejectsNull()
    {
        using var keys = new ParameterKeys();

        var e = Assert.Throws<ArgumentNullException>(() => new CkmIke1PrfDeriveParams(
            CKM.CKM_SHA256_HMAC, keygxy: null!, prevKey: keys.Secret(2), [0x01], [0x02], keyNumber: 0));
        Assert.Equal("keygxy", e.ParamName);
    }

    [Fact]
    public void AbsentOptionalKeys_MarshalAsNotPresentWithNoHandle()
    {
        using var keys = new ParameterKeys();
        using var scope = keys.NewScope();

        var ike1 = (CK_IKE1_PRF_DERIVE_PARAMS)new CkmIke1PrfDeriveParams(
            CKM.CKM_SHA256_HMAC, keys.Secret(11), prevKey: null, [0x01], [0x02], keyNumber: 1).BuildMarshalable(scope);
        Assert.False(ike1.HasPrevKey);
        Assert.Equal(0UL, (ulong)ike1.PrevKey);
        Assert.Equal(11UL, (ulong)ike1.Keygxy);

        var extended = (CK_IKE1_EXTENDED_DERIVE_PARAMS)new CkmIke1ExtendedDeriveParams(
            CKM.CKM_SHA256_HMAC, keygxy: null, [0x01]).BuildMarshalable(scope);
        Assert.False(extended.HasKeygxy);
        Assert.Equal(0UL, (ulong)extended.Keygxy);

        var ike = (CK_IKE_PRF_DERIVE_PARAMS)new CkmIkePrfDeriveParams(
            CKM.CKM_SHA256_HMAC, dataAsKey: false, rekey: false, [0x01], [0x02]).BuildMarshalable(scope);
        Assert.Equal(0UL, (ulong)ike.NewKey);
    }

    [Fact]
    public void ScopeWithoutASession_CannotResolveKeys()
    {
        using var keys = new ParameterKeys();
        var p = new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, keys.Secret(9), [0x01]);
        using var scope = new MechanismParameterScope();

        Assert.Throws<InvalidOperationException>(() => p.BuildMarshalable(scope));
    }

    [Fact]
    public void HkdfWithSalt_RejectsAnEmptySalt()
    {
        var e = Assert.Throws<ArgumentException>(() =>
            CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC, default));
        Assert.Equal("salt", e.ParamName);
    }

    [Fact]
    public void HkdfWithoutSalt_SendsTheNullSaltType()
    {
        using var scope = new MechanismParameterScope();

        var s = (CK_HKDF_PARAMS)CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC)
            .BuildMarshalable(scope);

        Assert.Equal((ulong)HkdfSaltType.Null, (ulong)s.SaltType);
        Assert.Equal(IntPtr.Zero, s.Salt);
        Assert.Equal(0UL, (ulong)s.SaltKey);
    }

    [Fact]
    public void HkdfWithSaltKey_RefusesAPublicOnlyKey()
    {
        using var keys = new ParameterKeys();

        var e = Assert.Throws<ArgumentException>(() =>
            CkmHkdfParams.WithSaltKey(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC, keys.PublicOnly(3)));
        Assert.Equal("saltKey", e.ParamName);
    }

    [Fact]
    public void Sp800108Key_RejectsNull() =>
        Assert.Throws<ArgumentNullException>(() => CkmSp800108KdfParams.Counter(CKM.CKM_AES_CMAC).Key(null!));

    private sealed class HandlePairParams(Pkcs11Key key) : VendorMechanismParameters
    {
        protected override void Describe(Pkcs11ParameterWriter writer) => writer
            .Key(key)
            .Key(key, KeyHandlePart.Public);
    }

    [Fact]
    public void ParameterWriterKey_WritesTheRequestedHalf()
    {
        using var keys = new ParameterKeys();
        using var scope = keys.NewScope();

        var block = (Pkcs11ParameterBlock)new HandlePairParams(keys.Pair(0x11, 0x22)).BuildMarshalable(scope);

        int word = UnmanagedMemory.NativeULongSize;
        Assert.Equal(2 * word, block.Length);
        Assert.Equal(0x11UL, ReadWord(block.Pointer, 0, word));
        Assert.Equal(0x22UL, ReadWord(block.Pointer, word, word));
    }

    [Fact]
    public void ParameterWriterKey_RefusesAKeyFromAnotherWorkspace()
    {
        using var caller = new ParameterKeys();
        using var other = new ParameterKeys();
        using var scope = caller.NewScope();

        var e = Assert.Throws<ArgumentException>(() => new HandlePairParams(other.Pair(0x11, 0x22)).BuildMarshalable(scope));
        Assert.Equal("key", e.ParamName);
    }

    private static ulong ReadWord(IntPtr block, int offset, int width)
    {
        byte[] bytes = UnmanagedMemory.Read(IntPtr.Add(block, offset), width);
        return width == 4 ? BitConverter.ToUInt32(bytes) : BitConverter.ToUInt64(bytes);
    }
}
