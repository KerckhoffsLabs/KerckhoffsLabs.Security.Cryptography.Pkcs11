using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// The rules for mechanism parameters that reference on-token keys: which half of a key a field
/// takes, when a key is refused, and what an absent optional key marshals to. The field values
/// themselves are covered per type in <see cref="BuildMarshalableTests"/>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class KeyValuedParameterTests
{
    [Fact]
    public void KeyFromAnotherSession_IsRefusedWhenMarshalled()
    {
        using var caller = new ParameterKeys();
        using var other = caller.OtherSession();
        var p = new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, other.Secret(9), [0x01]);
        using var scope = caller.NewScope();

        var e = Assert.Throws<ArgumentException>(() => p.BuildMarshalable(scope));
        Assert.Equal("seedKey", e.ParamName);
    }

    [Fact]
    public void KeyFromAnotherSession_IsRefusedBeforeTheDeriveReachesTheModule()
    {
        using var caller = new ParameterKeys(CryptoPolicy.AllowInsecure);
        using var other = caller.OtherSession();
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

    // === Every key field, not one per type ===================================

    // Which half each field takes, whether it may be absent, and how to build its type with a given
    // key in each field. Keyed by "Type.parameter" so each row is serializable.
    private sealed record KeyField(KeyHandlePart Part, bool Optional, Func<Func<string, Pkcs11Key?>, object> Make);

    private static readonly Dictionary<string, KeyField> KeyFields = new()
    {
        ["CkmX3dhInitiateParams.peerIdentity"] = new(KeyHandlePart.Public, false, X3dhInitiate),
        ["CkmX3dhInitiateParams.peerPrekey"] = new(KeyHandlePart.Public, false, X3dhInitiate),
        ["CkmX3dhInitiateParams.ownIdentity"] = new(KeyHandlePart.Private, false, X3dhInitiate),
        ["CkmX3dhInitiateParams.ownEphemeral"] = new(KeyHandlePart.Private, false, X3dhInitiate),
        ["CkmX3dhRespondParams.initiatorIdentity"] = new(KeyHandlePart.Public, false,
            k => new CkmX3dhRespondParams(CKM.CKM_SHA256_HMAC, [0x01], [0x02], [0x03], k("initiatorIdentity")!, [0x04])),
        ["CkmX2RatchetInitializeParams.peerPublicPrekey"] = new(KeyHandlePart.Public, false, X2RatchetInitialize),
        ["CkmX2RatchetInitializeParams.peerPublicIdentity"] = new(KeyHandlePart.Public, false, X2RatchetInitialize),
        ["CkmX2RatchetInitializeParams.ownPublicIdentity"] = new(KeyHandlePart.Public, false, X2RatchetInitialize),
        ["CkmX2RatchetRespondParams.ownPrekey"] = new(KeyHandlePart.Private, false, X2RatchetRespond),
        ["CkmX2RatchetRespondParams.initiatorIdentity"] = new(KeyHandlePart.Public, false, X2RatchetRespond),
        ["CkmX2RatchetRespondParams.ownPublicIdentity"] = new(KeyHandlePart.Public, false, X2RatchetRespond),
        ["CkmIke1PrfDeriveParams.keygxy"] = new(KeyHandlePart.Private, false, Ike1Prf),
        ["CkmIke1PrfDeriveParams.prevKey"] = new(KeyHandlePart.Private, true, Ike1Prf),
        ["CkmIke1ExtendedDeriveParams.keygxy"] = new(KeyHandlePart.Private, true,
            k => new CkmIke1ExtendedDeriveParams(CKM.CKM_SHA256_HMAC, k("keygxy"), [0x01])),
        ["CkmIke2PrfPlusDeriveParams.seedKey"] = new(KeyHandlePart.Private, true,
            k => new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, k("seedKey"), [0x01])),
        ["CkmIkePrfDeriveParams.newKey"] = new(KeyHandlePart.Private, true,
            k => new CkmIkePrfDeriveParams(CKM.CKM_SHA256_HMAC, dataAsKey: false, rekey: true, [0x01], [0x02], k("newKey"))),
        ["CkmHkdfParams.saltKey"] = new(KeyHandlePart.Private, false,
            k => CkmHkdfParams.WithSaltKey(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, k("saltKey")!)),
        ["Sp800108KdfBuilder.key"] = new(KeyHandlePart.Private, false,
            k => CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC).IterationCounter().Key(k("key")!)),
    };

    private static object X3dhInitiate(Func<string, Pkcs11Key?> k) => new CkmX3dhInitiateParams(
        CKM.CKM_SHA256_HMAC, k("peerIdentity")!, k("peerPrekey")!, [0x01], [0x02], k("ownIdentity")!, k("ownEphemeral")!);

    private static object X2RatchetInitialize(Func<string, Pkcs11Key?> k) => new CkmX2RatchetInitializeParams(
        [0x01], k("peerPublicPrekey")!, k("peerPublicIdentity")!, k("ownPublicIdentity")!,
        encryptedHeader: false, curve: 1, CKM.CKM_AES_GCM, CKM.CKM_SHA256_HMAC);

    private static object X2RatchetRespond(Func<string, Pkcs11Key?> k) => new CkmX2RatchetRespondParams(
        [0x01], k("ownPrekey")!, k("initiatorIdentity")!, k("ownPublicIdentity")!,
        encryptedHeader: false, curve: 1, CKM.CKM_AES_GCM, CKM.CKM_SHA256_HMAC);

    private static object Ike1Prf(Func<string, Pkcs11Key?> k) => new CkmIke1PrfDeriveParams(
        CKM.CKM_SHA256_HMAC, k("keygxy")!, k("prevKey"), [0x01], [0x02], keyNumber: 0);

    public static TheoryData<string> KeyFieldNames() => [.. KeyFields.Keys];

    // Every other field gets a full key pair, which has both halves.
    private static object MakeWith(ParameterKeys keys, string row, Pkcs11Key? inTheField)
    {
        string field = row[(row.IndexOf('.') + 1)..];
        return KeyFields[row].Make(name => name == field ? inTheField : keys.Pair(0x10, 0x11));
    }

    [Theory]
    [MemberData(nameof(KeyFieldNames))]
    public void KeyField_WithoutTheHalfItTakes_IsRefusedAtConstruction(string row)
    {
        using var keys = new ParameterKeys();
        Pkcs11Key wrongHalf = KeyFields[row].Part == KeyHandlePart.Public ? keys.Secret(9) : keys.PublicOnly(9);

        var e = Assert.Throws<ArgumentException>(() => MakeWith(keys, row, wrongHalf));

        Assert.Equal(row[(row.IndexOf('.') + 1)..], e.ParamName);
    }

    [Theory]
    [MemberData(nameof(KeyFieldNames))]
    public void KeyField_Null_IsRefusedUnlessOptional(string row)
    {
        using var keys = new ParameterKeys();

        if (KeyFields[row].Optional)
        {
            Assert.NotNull(MakeWith(keys, row, null));
            return;
        }

        var e = Assert.Throws<ArgumentNullException>(() => MakeWith(keys, row, null));
        Assert.Equal(row[(row.IndexOf('.') + 1)..], e.ParamName);
    }

    [Fact]
    public void AbsentOptionalKeys_MarshalAsNotPresentWithNoHandle()
    {
        using var keys = new ParameterKeys();
        using var scope = keys.NewScope();

        var ike1 = new CkmIke1PrfDeriveParams(
            CKM.CKM_SHA256_HMAC, keys.Secret(11), prevKey: null, [0x01], [0x02], keyNumber: 1).BuildMarshalable(scope).Read<CK_IKE1_PRF_DERIVE_PARAMS>();
        Assert.Equal(CkBbool.False, ike1.HasPrevKey);
        Assert.Equal(0UL, (ulong)ike1.PrevKey);
        Assert.Equal(11UL, (ulong)ike1.Keygxy);

        var extended = new CkmIke1ExtendedDeriveParams(
            CKM.CKM_SHA256_HMAC, keygxy: null, [0x01]).BuildMarshalable(scope).Read<CK_IKE1_EXTENDED_DERIVE_PARAMS>();
        Assert.Equal(CkBbool.False, extended.HasKeygxy);
        Assert.Equal(0UL, (ulong)extended.Keygxy);

        var ike = new CkmIkePrfDeriveParams(
            CKM.CKM_SHA256_HMAC, dataAsKey: false, rekey: false, [0x01], [0x02]).BuildMarshalable(scope).Read<CK_IKE_PRF_DERIVE_PARAMS>();
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

        var s = CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC)
            .BuildMarshalable(scope).Read<CK_HKDF_PARAMS>();

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
    public void ParameterWriterKey_RefusesAKeyFromAnotherSession()
    {
        using var caller = new ParameterKeys();
        using var other = caller.OtherSession();
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
